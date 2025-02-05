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

use chumsky::prelude::*;

#[derive(Debug, PartialEq, Clone)]
pub struct Acl(Vec<Entry>);

#[derive(Debug, PartialEq, Clone)]
pub enum Entry {
    Allow(Filter),
    Deny(Filter),
}

#[derive(Debug, PartialEq, Clone)]
pub enum Filter {
    User(String),
    Group(String),
    Domain(String),
    LocalUser,
    AnyUser,
    Any,
}

#[derive(Debug, PartialEq)]
pub enum Decision {
    Allow,
    Deny
}

use crate::userinfo::UserInfo;

impl Acl {
    pub fn check(&self, user: Option<&UserInfo>) -> Decision {
        for entry in self.0.iter() {
            match entry.check(user) {
                Some(d) => return d,
                None => ()
            }
        }
        Decision::Deny
    }
}

impl Entry {
    pub fn check(&self, user: Option<&UserInfo>) -> Option<Decision> {
        match self {
            Entry::Allow(filter) =>
                if filter.matches(user) { Some(Decision::Allow) } else { None },
            Entry::Deny(filter)  =>
                if filter.matches(user) { Some(Decision::Deny) } else { None },
        }
    }
}

impl Filter {
    pub fn matches(&self, u: Option<&UserInfo>) -> bool {
        if let Any = self {
            true
        } else {
            if let Some(user) = u {
                match self {
                    Any => true,
                    AnyUser => true,
                    User(username) => user.user == *username,
                    Group(group) => user.groups.contains(group),
                    Domain(domain) => user.domains.contains(domain),
                    LocalUser => local_user_exists(&user.user),
                }
            } else {
                false
            }
        }
    }
}

use Entry::*;
use Filter::*;

impl Acl {
    pub fn parser() -> impl Parser<char, Acl, Error = Simple<char>> {
        let colon = just(":").padded();

        let squoted_string = none_of("'").repeated()
            .delimited_by(just("'"), just("'"))
            .map(|vec| vec.into_iter().collect());
        let dquoted_string = none_of('"').repeated()
            .delimited_by(just('"'), just('"'))
            .map(|vec| vec.into_iter().collect());
        let string = text::ident()
            .or(dquoted_string)
            .or(squoted_string);

        let any_filter = just("*").to(Any);
        let any_user_filter = just("user")
            .then(colon)
            .then(just("*"))
            .to(AnyUser);
        let local_user_filter = just("user")
            .then(colon)
            .then(just("*local"))
            .to(LocalUser);
        let user_filter = just("user")
            .ignore_then(colon)
            .ignore_then(string.clone())
            .map(User);
        let group_filter = just("group")
            .ignore_then(colon)
            .ignore_then(string.clone())
            .map(Group);
        let domain_filter = just("domain")
            .ignore_then(colon)
            .ignore_then(string)
            .map(Domain);

        let filter = any_filter
            .or(local_user_filter)
            .or(any_user_filter)
            .or(user_filter)
            .or(group_filter)
            .or(domain_filter)
            .boxed();

        let allow = just("allow")
            .ignore_then(colon)
            .ignore_then(filter.clone())
            .map(|f| Allow(f));

        let deny = just("deny")
            .ignore_then(colon)
            .ignore_then(filter)
            .map(|f| Deny(f));

        let ace = allow.or(deny).boxed();
        let acl = ace.clone()
            .separated_by(just(",").padded())
            .map(|vec| Acl(vec));

        acl.then_ignore(end())
    }
}

use std::ffi::CString;

pub fn local_user_exists(username: &str) -> bool {
    let username_c = CString::new(username).unwrap();
    unsafe {
        let ptr = libc::getpwnam(username_c.as_ptr());
        !ptr.is_null()
    }
}
