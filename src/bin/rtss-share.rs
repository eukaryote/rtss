extern crate clap;
extern crate rtss;
extern crate hex;

use clap::{Arg, App};

static EXPLANATION:  &'static str = "Use Shamir's Secret Sharing scheme to \
    encode a secret as N shares in the draft-mcgrew-tss-03 robust format, \
    any K of which is sufficient to reconstruct the secret.";

fn is_nonzero_u8(v: String) -> Result<(), String> {
    let res = v.parse::<u8>();
    if res.is_ok() && res.unwrap() > 0 {
        Ok(())
    } else {
        Err(String::from("expected a positive number from 1 to 255"))
    }
}

fn main() {
    std::process::exit(run());
}


fn run() -> i32 {
    let matches = App::new("rtss")
        .version("0.3.0")
        .about("Share a Secret")
        .arg(Arg::with_name("threshold")
            .value_name("K")
            .short("k")
            .long("threshold")
            .takes_value(true)
            .required(true)
            .validator(is_nonzero_u8)
            .help("minimum number of shares to reconstruct secret \
                  [1-255, no greater than number of shares, and equal to \
                  the number of shares if not provided]"))
        .arg(Arg::with_name("shares")
            .value_name("N")
            .short("n")
            .long("shares")
            .takes_value(true)
            .required(true)
            .validator(is_nonzero_u8)
            .help("number of shares to create [1-255]"))
        .arg(Arg::with_name("secret")
            .value_name("SECRET")
            .takes_value(true)
            .use_delimiter(false)
            .multiple(false)
            .help("secret to be encoded"))
        .after_help(EXPLANATION)
        .get_matches();

    let num_shares = matches.value_of("shares").unwrap();
    let threshold = matches.value_of("threshold").unwrap_or(num_shares);
    let secret: Vec<u8> = matches.value_of("secret").unwrap().into();
    match rtss::share_rtss(&secret,
                           threshold.parse::<u8>().unwrap(),
                           num_shares.parse::<u8>().unwrap()) {
        Err(msg) => {
            println!("{}", msg);
            return 1;
        }
        Ok(shares) => {
            for share in shares.iter() {
                println!("{}\n", hex::encode(share));
            }
            return 0;
        }
    }
}
