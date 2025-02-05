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

//! KVD user information blob.

use serde::{Deserialize, Serialize};
use serde_json::{Value, Map};

/// KVD user information blob.
///
/// The key properties we want to be able to use for WebACLs or add to our
/// log message are broken out into their own properties, while all remaining
/// properties go into the `rest` Map.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UserInfo {
    /// Username
    pub user: String,
    /// E-mail address
    pub email: String,
    /// List of domain names (e.g. `eait`, `uq`)
    pub domains: Vec<String>,
    /// List of qualified groups the user is a member of (e.g. `eait:foo`)
    pub groups: Vec<String>,
    /// Internal property used by kvd::Client::create() to indicate which
    /// host bucket the cookie should be created in.
    pub _bucket: Option<String>,

    /// All remaining properties.
    #[serde(flatten)]
    pub rest: Map<String, Value>
}
