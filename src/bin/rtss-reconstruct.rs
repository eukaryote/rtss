extern crate clap;
extern crate rtss;
extern crate rustc_serialize;

use rustc_serialize::hex::{FromHex,ToHex};
use clap::{Arg, App};

static EXPLANATION:  &'static str = "\
Reconstruct a secret by providing at least K (defined threshold) shares
for a previously shared secret.";

fn main() {
    std::process::exit(run());
}


fn run() -> i32 {
    let matches = App::new("rtss-reconstruct")
        .version("0.1")
        .about("Reconstruct Secret from K Shares")
        .arg(Arg::with_name("share")
            .value_name("SHARE")
            .takes_value(true)
            .required(true)
            .multiple(true)
            .help("base64-encoded share"))
        .after_help(EXPLANATION)
        .get_matches();

    // println!("matches: {:?}", matches);
    let shares: Vec<_> = matches.values_of("share").unwrap().collect();
    let mut share_bytes = Vec::with_capacity(shares.len());
    for share in shares.iter() {
        match share.from_hex() {
            Err(e) => {
                println!("invalid hexadecimal: {:?}", e);
                return 1;
            },
            Ok(bytes) => share_bytes.push(bytes),
        }
    }
    match rtss::reconstruct_rtss(&share_bytes) {
        Ok(secret) => {
            match String::from_utf8(secret.to_owned()) {
                Ok(utf8) => {
                    println!("{}", utf8);
                    return 0;
                },
                Err(_) => {
                    println!("{}", secret.to_hex());
                    return 0;
                },
            }
        },
        Err(msg) => {
            println!("{}", msg);
            return 1;
        },
    }
}
