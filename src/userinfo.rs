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

use serde::{Deserialize, Serialize};
use serde_json::{Result, Value, Map};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UserInfo {
    pub user: String,
    pub email: String,
    pub domains: Vec<String>,
    pub groups: Vec<String>,
    pub _bucket: Option<String>,
    #[serde(flatten)]
    pub rest: Map<String, Value>
}
