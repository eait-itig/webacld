/*
 * Copyright 2025, the University of Queensland
 * Author: Alex Wilson <alex@uq.edu.au>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

//! KVD protocol packet structs and client.

use std::net::UdpSocket;
use std::net::ToSocketAddrs;
use std::time::Duration;

use crate::userinfo::UserInfo;

use deku::prelude::*;

/// Local `Error` type for the KVD client.
///
/// We break out `TimedOut` and `Truncated` errors from all other errors
/// (where we just return a `String` for now), since these require special
/// action in our code.
#[derive(Debug)]
pub enum Error {
    TimedOut,
    Truncated,
    Other(String)
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Error {
        Other(value.to_string())
    }
}

use std::str::Utf8Error;
impl From<Utf8Error> for Error {
    fn from(value: Utf8Error) -> Error {
        Other(value.to_string())
    }
}

impl From<Error> for String {
    fn from(err: Error) -> String {
        err.to_string()
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// KVD "cookie" or "key" value, a 32-character unique string
#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(ctx = "_endian: deku::ctx::Endian")]
pub struct Cookie {
    #[deku(count = "32", assert = "bytes.len() == 32")]
    bytes: Vec<u8>
}

impl Cookie {
    /// Generate a new random [`Cookie`] using url-safe base64.
    pub fn random() -> Self {
        let mut buf = [0u8; 24];
        getrandom::fill(&mut buf).expect("getrandom failed");
        let mut v: Vec<u8> = URL_SAFE.encode(buf).into();
        v.resize(32, 0);
        Cookie { bytes: v }
    }
    /// Converts the [`Cookie`] to a [`str`] value (removing any NUL bytes)
    fn to_str(&self) -> &str {
        let mut i = 0;
        while i < 32 && self.bytes[i] != 0 {
            i += 1;
        }
        std::str::from_utf8(&self.bytes[..i]).unwrap()
    }
}

impl ToString for Cookie {
    fn to_string(&self) -> String {
        self.to_str().to_string()
    }
}

impl From<&str> for Cookie {
    fn from(value: &str) -> Self {
        let mut vec = Vec::from(value);
        vec.resize(32, 0);
        Cookie { bytes: vec }
    }
}

impl From<String> for Cookie {
    fn from(value: String) -> Self {
        let mut vec = Vec::from(value);
        vec.resize(32, 0);
        Cookie { bytes: vec }
    }
}

impl From<&Vec<u8>> for Cookie {
    fn from(value: &Vec<u8>) -> Self {
        let mut vec = value.clone();
        vec.resize(32, 0);
        Cookie { bytes: vec }
    }
}

/// Message exchanged in the KVD protocol
///
/// This enum represents all of the supported KVD protocol messages.
#[deku_derive(DekuRead, DekuWrite)]
#[derive(Debug, PartialEq)]
#[deku(id_type = "u8", endian = "big")]
pub enum Packet {
    /// Sent to the KVD server to create a new session
    #[deku(id = 0)]
    Create {
        #[deku(pad_bytes_before = "1", temp, temp_value = "data.len() as u16")]
        payload_size: u16,
        /// Correlation cookie (will be included in the reply verbatim)
        cookie: Cookie,
        /// JSON data to put in the new session
        #[deku(count = "payload_size")]
        data: Vec<u8>
    },
    /// Server reply to a [`Packet::Create`] message, gives the new session's key
    #[deku(id = 1)]
    Created {
        #[deku(pad_bytes_before = "1", temp, temp_value = "32")]
        payload_size: u16,
        /// Correlation cookie (matches the `Create` command)
        cookie: Cookie,
        /// The new KVD session key
        key: Cookie
    },
    /// Sent to the KVD server to request the JSON data for a given session
    #[deku(id = 2)]
    Request {
        #[deku(pad_bytes_before = "1", temp, temp_value = "bucket.len() as u16")]
        payload_size: u16,
        /// Session key
        key: Cookie,
        /// The host bucket (FQDN from the URI the user requested)
        #[deku(count = "payload_size")]
        bucket: Vec<u8>
    },
    /// Server reply to [`Packet::Request`] when the session has JSON data
    #[deku(id = 3)]
    Value {
        #[deku(pad_bytes_before = "1")]
        data_size: u16,
        /// Session key
        key: Cookie,
        /// JSON data about the user
        #[deku(read_all)]
        data: Vec<u8>
    },
    /// Server reply to [`Packet::Request`] when the session does not exist or is invalid
    #[deku(id = 4)]
    NoValue {
        #[deku(pad_bytes_before = "1", temp, temp_value = "0")]
        payload_size: u16,
        /// Session key
        key: Cookie
    },
    /// Modified version of [`Packet::Request`] which includes an offset and allows for
    /// retrieving partial data
    ///
    /// This is necessary when the size of the user info JSON exceeds the
    /// maximum that can be transferred in a single UDP datagram.
    #[deku(id = 13)]
    PartialRequest {
        #[deku(pad_bytes_before = "1", temp, temp_value = "(bucket.len() + 4) as u16")]
        payload_size: u16,
        /// Session key
        key: Cookie,
        /// Offset in the JSON blob to begin any `Value` reply at
        offset: u32,
        /// Host bucket (FQDN)
        #[deku(count = "payload_size - 4")]
        bucket: Vec<u8>
    },
}

const DEFAULT_PORT: u16 = 1080;

/// Configuration for creating a new [`Client`] instance
pub struct ClientConfig {
    pub host: String,
    pub port: u16,
    pub retries: u32,
    pub timeout: u32,
}

impl ClientConfig {
    pub fn default() -> ClientConfig {
        ClientConfig {
            host: "127.0.0.1".into(),
            port: DEFAULT_PORT,
            retries: 5,
            timeout: 250
        }
    }

    pub fn with_host(mut self, host: &str) -> ClientConfig {
        self.host = host.into();
        self
    }

    pub fn with_port(mut self, port: u16) -> ClientConfig {
        self.port = port;
        self
    }
}

/// Client for the KVD protocol
pub struct Client {
    socket: UdpSocket,
    config: ClientConfig,
}

/// Return type for [`Client::get_partial`]
#[derive(Debug)]
pub enum PartialReturn {
    /// No value for the given key
    NoValue,
    /// Value completely received, this is the last chunk
    Complete(Vec<u8>),
    /// Chunk of data, there is more to fetch
    Partial(Vec<u8>)
}

use Error::*;
use PartialReturn::*;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};

impl Client {
    /// Creates a new client, using the given Config.
    pub fn open(config: ClientConfig) -> Result<Client,> {
        match UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => Ok(Client { socket, config }),
            Err(why) => Err(Other(why.to_string()))
        }
    }

    /// Request-reply exchange of packets with the server.
    #[doc(hidden)]
    fn xpkt(&mut self, pkt: Packet, timeout: u32) -> Result<Packet> {
        let mut diter = match (self.config.host.as_str(), self.config.port).to_socket_addrs() {
            Ok(diter) => diter,
            Err(why) => return Err(Other(why.to_string()))
        };
        let daddr = match diter.next() {
            Some(daddr) => daddr,
            None =>
                return Err(Other("no results when looking up KVD server".to_string()))
        };
        let data: Vec<u8> = pkt.try_into().expect("failed to generate packet");

        let _wrote = match self.socket.send_to(data.as_slice(), daddr) {
            Ok(wrote) => wrote,
            Err(why) => return Err(Other(why.to_string()))
        };

        let mut buf = vec![0_u8; u16::MAX as usize + 36];
        let dur = Duration::from_millis(timeout as u64);

        self.socket.set_read_timeout(Some(dur)).expect("failed to set timeout");

        let (len, saddr) = match self.socket.recv_from(&mut buf) {
            Ok(tup) => tup,
            Err(why) => match why.kind() {
                std::io::ErrorKind::TimedOut => return Err(TimedOut),
                std::io::ErrorKind::WouldBlock => return Err(TimedOut),
                _ => return Err(Other(why.to_string()))
            }
        };
        assert_eq!(saddr, daddr);
        match Packet::try_from(&buf[..len]) {
            Ok(rpkt) => Ok(rpkt),
            Err(why) => Err(Other(why.to_string()))
        }
    }

    #[doc(hidden)]
    fn get_partial_once(&mut self, key: &Cookie, bucket: &str, offset: u32, timeout: u32) -> Result<PartialReturn> {
        let mut pkt = Packet::PartialRequest {
            key: key.clone(),
            bucket: bucket.into(),
            offset
        };
        pkt.update().expect("failed to update packet");
        match self.xpkt(pkt, timeout) {
            Ok(Packet::NoValue { .. }) => Ok(NoValue),
            Ok(Packet::Value { data_size, data, .. }) =>
                if data_size == u16::MAX || data_size == (i16::MAX as u16) {
                    Ok(Partial(data))
                } else if (data_size as usize) == data.len() {
                    Ok(Complete(data))
                } else {
                    Ok(Partial(data))
                },
            Ok(_) => Err(Other("invalid response packet".to_string())),
            Err(TimedOut) => Err(TimedOut),
            Err(Other(why)) => Err(Other(why.to_string())),
            Err(Truncated) => panic!("this should never happen")
        }
    }

    /// Retrieve part of the JSON value for a given key.
    ///
    /// Sends a [`Packet::PartialRequest`] message to the server and returns
    /// its response.
    pub fn get_partial(&mut self, key: &Cookie, bucket: &str, offset: u32) -> Result<PartialReturn> {
        let mut retries = self.config.retries;
        let mut timeout = self.config.timeout;
        while retries > 0 {
            let result = self.get_partial_once(key, bucket, offset, timeout);
            if let Err(TimedOut) = result {
                retries -= 1;
                timeout *= 2;
                continue;
            } else {
                return result;
            }
        }
        Err(TimedOut)
    }

    #[doc(hidden)]
    fn get_bucket_once(&mut self, key: &Cookie, bucket: &str, timeout: u32) -> Result<Option<Vec<u8>>> {
        let mut pkt = Packet::Request {
            key: key.clone(),
            bucket: bucket.into()
        };
        pkt.update().expect("failed to update packet");
        match self.xpkt(pkt, timeout) {
            Ok(Packet::NoValue { .. }) => Ok(None),
            Ok(Packet::Value { data_size, data, .. }) =>
                if (data_size as usize) == data.len() {
                    Ok(Some(data))
                } else {
                    Err(Truncated)
                }
            Ok(_) => Err(Other("invalid response packet".to_string())),
            Err(TimedOut) => Err(TimedOut),
            Err(Truncated) => Err(Truncated),
            Err(Other(why)) => Err(Other(why.to_string()))
        }
    }

    pub fn get_bucket(&mut self, key: &Cookie, bucket: &str) -> Result<Option<UserInfo>> {
        let mut retries = self.config.retries;
        let mut timeout = self.config.timeout;
        while retries > 0 {
            let result = self.get_bucket_once(key, bucket, timeout);
            match result {
                Ok(None) => return Ok(None),
                Ok(Some(data)) => {
                    let strdata = std::str::from_utf8(&data[..])?;
                    let uinfo: UserInfo = serde_json::from_str(&strdata)?;
                    return Ok(Some(uinfo))
                },
                Err(TimedOut) => (),
                Err(Truncated) => return Err(Truncated),
                Err(Other(why)) => return Err(Other(why.to_string()))
            }
            retries -= 1;
            timeout *= 2;
        }
        Err(TimedOut)
    }

    #[doc(hidden)]
    fn create_once(&mut self, uinfo: &UserInfo, bucket: Option<&str>, timeout: u32) -> Result<Cookie> {
        let cookie = Cookie::random();

        let mut uinfo2 = uinfo.clone();
        if let Some(bucket) = bucket {
            uinfo2._bucket = Some(bucket.to_string());
        }

        let data = serde_json::to_string(&uinfo2)?;

        let mut pkt = Packet::Create {
            cookie: cookie.clone().into(),
            data: data.into()
        };
        pkt.update().expect("failed to update packet");
        match self.xpkt(pkt, timeout) {
            Ok(Packet::Created { cookie: rcookie, key, .. }) =>
                if cookie == rcookie {
                    Ok(key)
                } else {
                    Err(Other("cookie mismatch".to_string()))
                },
            Ok(_) => Err(Other("invalid response packet".to_string())),
            Err(TimedOut) => Err(TimedOut),
            Err(Truncated) => Err(Truncated),
            Err(Other(why)) => Err(Other(why.to_string()))
        }
    }

    #[allow(dead_code)]
    pub fn create(&mut self, uinfo: &UserInfo, bucket: Option<&str>) -> Result<Cookie> {
        let mut retries = self.config.retries;
        let mut timeout = self.config.timeout;
        while retries > 0 {
            let result = self.create_once(uinfo, bucket, timeout);
            match result {
                Ok(key) => return Ok(key),
                Err(TimedOut) => (),
                Err(Truncated) => return Err(Truncated),
                Err(Other(why)) => return Err(Other(why.to_string()))
            }
            retries -= 1;
            timeout *= 2;
        }
        Err(TimedOut)
    }

    #[doc(hidden)]
    fn get_once(&mut self, key: &Cookie, timeout: u32) -> Result<Option<Vec<u8>>> {
        let mut pkt = Packet::Request {
            key: key.clone(),
            bucket: vec![0_u8; 0]
        };
        pkt.update().expect("failed to update packet");
        match self.xpkt(pkt, timeout) {
            Ok(Packet::NoValue { .. }) => Ok(None),
            Ok(Packet::Value { data_size, data, .. }) =>
                if data.len() == (data_size as usize) {
                    Ok(Some(data))
                } else {
                    Err(Truncated)
                }
            Ok(_) => Err(Other("invalid response packet".to_string())),
            Err(TimedOut) => Err(TimedOut),
            Err(Truncated) => Err(Truncated),
            Err(Other(why)) => Err(Other(why.to_string()))
        }
    }

    /// Performs an old-style KVD request with no bucket (for non-FaKVD KVD)
    pub fn get_classic(&mut self, key: &Cookie) -> Result<Option<UserInfo>> {
        let mut retries = self.config.retries;
        let mut timeout = self.config.timeout;
        while retries > 0 {
            let result = self.get_once(key, timeout);
            match result {
                Ok(None) => return Ok(None),
                Ok(Some(data)) => {
                    let strdata = std::str::from_utf8(&data[..])?;
                    let uinfo: UserInfo = serde_json::from_str(&strdata)?;
                    return Ok(Some(uinfo))
                },
                Err(TimedOut) => (),
                Err(Truncated) => return Err(Truncated),
                Err(Other(why)) => return Err(Other(why.to_string()))
            }
            retries -= 1;
            timeout *= 2;
        }
        Err(TimedOut)
    }

    /// Gets the [`UserInfo`] associated with a given session from the KVD server.
    ///
    /// This function automatically attempts to use a [`Packet::PartialRequest`]
    /// and then falls back to the normal [`Packet::Request`] message (with and
    /// then without a host bucket), so that it can be used against both FaKVD
    /// and classic KVD.
    pub fn get(&mut self, key: &Cookie, bucket: &str) -> Result<Option<UserInfo>> {
        let mut offset: u32 = 0;
        let mut data = vec![0_u8; 0];
        loop {
            match self.get_partial(key, bucket, offset) {
                Ok(NoValue) => return Ok(None),
                Ok(Complete(chunk)) => {
                    data.extend(chunk);
                    let strdata = std::str::from_utf8(&data[..])?;
                    let uinfo: UserInfo = serde_json::from_str(&strdata)?;
                    return Ok(Some(uinfo))
                },
                Ok(Partial(chunk)) => {
                    offset += chunk.len() as u32;
                    data.extend(chunk);
                    continue;
                },
                Err(TimedOut) => break,
                Err(Other(_)) => break,
                Err(Truncated) => panic!("this should never happen")
            }
        }
        match self.get_bucket(key, bucket) {
            Ok(None) => return Ok(None),
            Ok(Some(uinfo)) => return Ok(Some(uinfo)),
            Err(TimedOut) => (),
            Err(Other(why)) => return Err(Other(why)),
            Err(Truncated) => return Err(Truncated)
        }
        self.get_classic(key)
    }
}

use std::fmt;
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
