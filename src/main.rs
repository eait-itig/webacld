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

extern crate tiny_http;
extern crate deku;
extern crate base64;
extern crate getrandom;
extern crate serde;
extern crate serde_json;
extern crate chumsky;
extern crate libc;
extern crate threadpool;
extern crate ascii;
extern crate biscotti;
extern crate clap;

#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate slog_async;

mod kvd;
mod userinfo;
mod webacl;
mod server;

use server::{Server, Config};
use clap::Parser;
use crate::slog::Drain;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "/tmp/webacld.sock")]
    listen_path: String,

    #[arg(short, long, default_value_t = 4)]
    workers: usize,

    #[arg(short = 'k', long, default_value = "172.23.84.20")]
    kvd_host: String,

    #[arg(short = 'p', long, default_value_t = 1080)]
    kvd_port: u16,

    #[arg(short, long, default_value = "EAIT_WEB")]
    cookie: String
}

fn main() {
    let Args { listen_path, workers, kvd_host, kvd_port, cookie } = Args::parse();

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let log = slog::Logger::root(drain, o!());

    info!(log, "deleting old socket: {}", &listen_path);
    let _ = std::fs::remove_file(&listen_path);

    let config = Config { log, listen_path, workers, kvd_host, kvd_port, cookie };
    let server = Server::new(config);

    server.run();
}
