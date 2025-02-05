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

use threadpool::ThreadPool;
use tiny_http::{Request, Response, Header, StatusCode, HeaderField};
use std::io::Cursor;
use ascii::AsciiString;
use std::path::Path;
use biscotti::{Processor, ProcessorConfig, RequestCookies};
use chumsky::Parser;

use crate::kvd;
use crate::userinfo::UserInfo;
use crate::webacl;

#[derive(Debug, Clone)]
pub struct Config {
    pub log: slog::Logger,
    pub listen_path: String,
    pub workers: usize,
    pub cookie: String,
    pub kvd_host: String,
    pub kvd_port: u16,
}

impl Config {
    pub fn with_log(mut self, log: slog::Logger) -> Self {
        self.log = log;
        self
    }
}

pub struct Server {
    config: Config,
    server: tiny_http::Server,
    pool: ThreadPool,
}

pub type Result<T> = std::result::Result<T, String>;

impl Server {
    pub fn new(config: Config) -> Self {
        let pool = ThreadPool::new(config.workers);
        let path = Path::new(&config.listen_path);
        let server = tiny_http::Server::http_unix(path).unwrap();
        Server { config, server, pool }
    }

    pub fn run(&self) {
        let log = &self.config.log;
        info!(log, "listening for requests on {}", &self.config.listen_path);
        for request in self.server.incoming_requests() {
            let rlog = log.new(o!());
            let config = self.config.clone().with_log(rlog);
            self.pool.execute(move || {
                match Self::process(&config, &request) {
                    Ok(resp) => {
                        request.respond(resp).unwrap()
                    },
                    Err(why) => {
                        let content_type = Header {
                            field: "content-type".parse().unwrap(),
                            value: AsciiString::from_ascii(b"text/plain").unwrap()
                        };
                        let resp = Response::from_string(why)
                            .with_status_code(StatusCode(500))
                            .with_header(content_type);
                        request.respond(resp).unwrap()
                    }
                }
            });
        }
    }

    fn find_cookie(config: &Config, req: &Request) -> Option<String> {
        let ckh: HeaderField = "cookie".parse().unwrap();
        let ck_hdrs = req.headers().iter().filter_map(|h|
            if h.field == ckh { Some(h.value.to_string()) } else { None });
        let ck_proc: Processor = ProcessorConfig::default().into();
        for v in ck_hdrs {
            let cookies = RequestCookies::parse_header(v.as_str(), &ck_proc).ok()?;
            if let Some(cookie) = cookies.get(config.cookie.as_str()) {
                return Some(cookie.value().to_string());
            }
        }
        None
    }

    fn find_one_header(req: &Request, name: &str) -> Result<String> {
        let hf: HeaderField = name.parse().unwrap();
        let mut hdrs = req.headers().iter().filter_map(|h|
            if h.field == hf { Some(h.value.to_string()) } else { None });
        if let Some(value) = hdrs.next() {
            Ok(value)
        } else {
            Err(format!("request contained no {:?} header", name))
        }
    }

    fn process(config: &Config, req: &Request) -> Result<Response<Cursor<Vec<u8>>>> {
        let host = Self::find_one_header(req, "host")?;
        let uri = Self::find_one_header(req, "x-original-uri")?;

        let mut log = config.log.new(o!("host" => host.clone(),
            "uri" => uri.clone()));
        match Self::find_one_header(req, "x-request-id") {
            Ok(req_id) => log = log.new(o!("request-id" => req_id)),
            Err(_) => ()
        }

        let content_type = Header {
            field: "content-type".parse().unwrap(),
            value: AsciiString::from_ascii(b"text/plain").unwrap()
        };

        let mut rhdrs: Vec<Header> = Vec::new();
        let mut uinfo: Option<UserInfo> = None;

        if let Some(cookie) = Self::find_cookie(config, req) {
            let kvd_config = kvd::ClientConfig::default()
                .with_host(config.kvd_host.as_str())
                .with_port(config.kvd_port);
            let mut kvd = kvd::Client::open(kvd_config)?;

            let cookie: kvd::Cookie = cookie.into();
            match kvd.get_auto(&cookie, &host) {
                Ok(Some(mut u)) => {
                    u._bucket = None;
                    uinfo = Some(u.clone());

                    log = log.new(o!("user" => u.user.clone()));

                    rhdrs.push(Header {
                        field: "x-uq-user".parse().unwrap(),
                        value: AsciiString::from_ascii(u.user.as_bytes()).unwrap()
                    });
                    rhdrs.push(Header {
                        field: "x-uq-user-email".parse().unwrap(),
                        value: AsciiString::from_ascii(u.email.as_bytes()).unwrap()
                    });
                    let json = serde_json::to_string(&u).unwrap();
                    rhdrs.push(Header {
                        field: "x-kvd-payload".parse().unwrap(),
                        value: AsciiString::from_ascii(json.as_bytes()).unwrap()
                    });
                },
                Ok(None) => {
                    info!(log, "cookie has expired or never existed")
                },
                Err(err) => {
                    error!(log, "failed to retrieve kvd cookie: {}", err.to_string());
                }
            }
        }

        if let Ok(acl_src) = Self::find_one_header(req, "x-acl") {
            let parser = webacl::Acl::parser();
            match parser.parse(acl_src) {
                Ok(acl) => {
                    let decision = match uinfo.clone() {
                        Some(u) => acl.check(Some(&u)),
                        None => acl.check(None)
                    };

                    log = log.new(o!("acl" => format!("{:?}", acl)));

                    if let webacl::Decision::Deny = decision {
                        if let Some(_) = uinfo {
                            info!(log, "logged-in user denied access");
                            let mut resp = Response::from_string("Logged in user denied access")
                                .with_status_code(StatusCode(403))
                                .with_header(content_type);
                            for h in rhdrs {
                                resp.add_header(h);
                            }
                            return Ok(resp);
                        } else {
                            info!(log, "anon user denied access");
                        }
                    }
                    if let webacl::Decision::Allow = decision {
                        info!(log, "allowed access");
                        let mut resp = Response::from_string("ACL allowed access")
                            .with_status_code(StatusCode(200))
                            .with_header(content_type);
                        for h in rhdrs {
                            resp.add_header(h);
                        }
                        return Ok(resp);
                    }
                },
                Err(parse_errs) => {
                    parse_errs
                        .into_iter()
                        .for_each(|e| error!(log, "ACL parse error: {}", e))
                }
            }
        } else {
            if let Some(_) = uinfo {
                error!(log, "no ACL given by nginx");
                let mut resp = Response::from_string("No ACL given")
                    .with_status_code(StatusCode(403))
                    .with_header(content_type);
                for h in rhdrs {
                    resp.add_header(h);
                }
                return Ok(resp);
            }
        }

        info!(log, "redirecting to login");
        let resp = Response::from_string("Redirecting for login")
            .with_status_code(StatusCode(401))
            .with_header(content_type);
        Ok(resp)
    }
}


