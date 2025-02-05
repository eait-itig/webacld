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

//! Parser and evaluator for the WebACL format.
//!
//! The WebACL format consists of stanzas separated by comma (`,`) characters
//! and whitespace. Each stanza is of the general form `verb:filter`, where
//! filter can be further qualified as e.g. `user:<username>` for a filter
//! matching a specific user by their name.

use chumsky::prelude::*;

/// A WebACL access control list, consisting of multiple Stanzas.
///
/// This is usually constructed by parsing the text form of the WebACL, e.g.
/// with:
/// ```
///   let p = webacl::Acl::parser();
///   match p.parse("allow:user:foobar, deny:group:'what'") {
///     Ok(acl) => { .. },
///     Err(errs) =>
///       errs.into_iter().for_each(|e|
///         error!(log, "ACL parse error: {}", e))
///   }
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct Acl(Vec<Stanza>);

/// A stanza within an WebACL, which can either have an `allow` action or a
/// `deny` action when it matches.
#[derive(Debug, PartialEq, Clone)]
pub enum Stanza {
    Allow(Filter),
    Deny(Filter),
}

/// The filter part of a Stanza.
#[derive(Debug, PartialEq, Clone)]
pub enum Filter {
    /// Matches a specific user by username (`allow:user:uqfoo`)
    User(String),
    /// Matches users who are a member of a given group (`allow:group:foobar`)
    Group(String),
    /// Matches users who exist on the given domain (`allow:domain:eait`)
    Domain(String),
    /// Matches any user that exists on the local machine (`allow:user:*local`)
    LocalUser,
    /// Matches any logged-in user (`allow:user:*`)
    AnyUser,
    /// Matches any request, logged in or not (`allow:*`)
    Any,
}

/// Allow/Deny status as returned during ACL evaluation.
#[derive(Debug, PartialEq)]
pub enum Decision {
    Allow,
    Deny
}

use crate::userinfo::UserInfo;

impl Acl {
    /// Check a given user against the ACL and decide whether they should
    /// be allowed or denied.
    ///
    /// WebACLs are default-deny, meaning that if no Stanzas match the user,
    /// the decision returned is `Deny`.
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

impl Stanza {
    /// Checks whether this Stanza matches the given user, and returns what
    /// decision to make (if any).
    ///
    /// If the Stanza's Filter does not match, returns `None`. Otherwise
    /// returns `Some(Allow)` or `Some(Deny)`.
    pub fn check(&self, user: Option<&UserInfo>) -> Option<Decision> {
        match self {
            Stanza::Allow(filter) =>
                if filter.matches(user) { Some(Decision::Allow) } else { None },
            Stanza::Deny(filter)  =>
                if filter.matches(user) { Some(Decision::Deny) } else { None },
        }
    }
}

impl Filter {
    /// Checks whether this Filter matches the given user.
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

use Stanza::*;
use Filter::*;

impl Acl {
    /// Build a parser for text-format WebACLs
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
            .or(domain_filter);

        let allow = just("allow")
            .ignore_then(colon)
            .ignore_then(filter.clone())
            .map(Allow);

        let deny = just("deny")
            .ignore_then(colon)
            .ignore_then(filter)
            .map(Deny);

        let ace = allow
            .or(deny)
            .boxed();
        let acl = ace
            .separated_by(just(",").padded())
            .map(Acl);

        acl.then_ignore(end())
    }
}

use std::ffi::CString;

/// Uses `libc::getpwnam()` to check whether a given username exists as a
/// local user on the current machine.
///
/// Used by `LocalUser` filters.
fn local_user_exists(username: &str) -> bool {
    let username_c = CString::new(username).unwrap();
    unsafe {
        let ptr = libc::getpwnam(username_c.as_ptr());
        !ptr.is_null()
    }
}
