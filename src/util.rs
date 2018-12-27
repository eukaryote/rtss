//! Utilities for IO and generation of digest used in robust serialization.

use sodiumoxide;
use sodiumoxide::crypto::hash::sha256;

use std::error::Error;
use std::io::prelude::*;
use std::fs::File;
use std::sync::{Once, ONCE_INIT};

static INIT: Once = ONCE_INIT;

pub fn nacl_init() {
        INIT.call_once(|| sodiumoxide::init().unwrap() );
}

/// Read no more than `max_size` bytes from file at given path.
///
/// If there are no more than n bytes in the file, the success branch of the
/// `Result` will contain all the bytes of the file, otherwise the `Result`
/// will be an error message.
#[allow(dead_code)]
fn readn(path: &str, max_size: usize) -> Result<Vec<u8>, String> {
    match File::open(path) {
        Err(why) => {
            return Err(why.description().to_string());
        }
        Ok(mut file) => {
            let mut buffer = vec![0; max_size + 1];
            match file.read(&mut buffer) {
                Err(why) => return Err(why.description().to_string()),
                Ok(n) => {
                    if n > max_size {
                        return Err("file too large to read".to_string());
                    } else {
                        return Ok(buffer[0..n].to_vec());
                    }
                }
            }
        }
    }
}

/// Calcuate the SHA-256 digest of the given data.
pub fn digest(message: &[u8]) -> sha256::Digest {
    nacl_init();
    sha256::hash(message)
}

#[cfg(test)]
mod tests {

    use std::fmt;

    use super::{readn, digest};

    struct ByteBuf<'a>(&'a [u8]);

    impl<'a> fmt::LowerHex for ByteBuf<'a> {
        fn fmt(&self, fmtr: &mut fmt::Formatter) -> Result<(), fmt::Error> {
            for byte in self.0 {
                try!(fmtr.write_fmt(format_args!("{:02x}", byte)));
            }
            Ok(())
        }
    }
    const EMPTY_STR_SHA256_HEX: &'static str = "\
        e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    const HELLO_STR_SHA256_HEX: &'static str = "\
        2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    #[test]
    fn test_readn_success() {
        let res = readn("data/test1.txt", 100).unwrap();
        let expected: &[u8] = b"hello, world!";
        assert_eq!(expected.to_vec(), res);
    }
    #[test]
    fn test_readn_exactly_max() {
        let res = readn("data/test1.txt", 13).unwrap();
        let expected: &[u8] = b"hello, world!";
        assert_eq!(expected.to_vec(), res);
    }
    #[test]
    fn test_readn_overflow() {
        let res = readn("data/test1.txt", 12);
        assert!(res.is_err());
    }
    #[test]
    fn test_digest_empty_string() {
        let s: [u8; 0] = [];
        let res = digest(&s);
        let hex_digest = format!("{:x}", ByteBuf(&res.as_ref()));
        assert_eq!(EMPTY_STR_SHA256_HEX, hex_digest);
    }
    #[test]
    fn test_digest_nonempty_string() {
        let s: &[u8] = b"hello";
        let res = digest(&s);
        let hex_digest = format!("{:x}", ByteBuf(&res.as_ref()));
        assert_eq!(HELLO_STR_SHA256_HEX, hex_digest);
    }
}
