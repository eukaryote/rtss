use rand;
use rand::Rng;

use sodiumoxide::crypto::verify;

use byteorder::{BigEndian, WriteBytesExt};


use gf256;
use util;

const IDENTIFIER_SIZE: usize = 16;
const SHARES_MAX: usize = 255;
const SHARE_DATA_MAX: usize = 65534;  // 2**16 - 2

const SHA256_DIGEST_SIZE: usize = 32;

#[derive(Copy, Clone, PartialEq, Debug)]
enum HashAlgId {
    NullHash = 0,
    Sha1 = 1,
    Sha256 = 2,
}

#[derive(Debug)]
struct RTSS {
    pub identifier: [u8; IDENTIFIER_SIZE],
    pub hash_alg_id: HashAlgId,
    pub threshold: u8,
    pub data: Vec<u8>,
}

impl RTSS {
    fn new(identifier: [u8; IDENTIFIER_SIZE], hash_alg_id: HashAlgId,
           threshold: u8, data: Vec<u8>) -> Result<RTSS, String> {
        if threshold == 0 {
            return Err(String::from("threshold must be at least 1"));
        }
        Ok(RTSS{
            identifier: identifier,
            hash_alg_id: hash_alg_id,
            threshold: threshold,
            data: data
        })
    }
    fn to_bytes(&mut self) -> Vec<u8> {
        let size = self.data.len() as u16;
        // - identifier [16 bytes]
        // - hash algorithm identifier [1 byte]
        // - threshold [1 byte]
        // - share length [2 bytes]
        // - share data [number of bytes specified in 'share length']
        let mut buff: Vec<u8> = Vec::with_capacity(size as usize);
        for byte in self.identifier.iter() {
            buff.write_u8(*byte).unwrap();
        }
        buff.write_u8(self.hash_alg_id as u8).unwrap();
        buff.write_u8(self.threshold).unwrap();
        buff.write_u16::<BigEndian>(size).unwrap();
        for octet in self.data.iter() {
            buff.write_u8(*octet).unwrap();
        }
        return buff.to_vec();
    }
    fn from_bytes(data: &Vec<u8>) -> Result<RTSS, String> {
        if data.len() < 21 {
            return Err(String::from("invalid data"));
        }
        let mut identifier = [0; IDENTIFIER_SIZE];
        for (i, byte) in data[0..IDENTIFIER_SIZE].iter().enumerate() {
            identifier[i] = *byte;
        }
        // TODO: improve this when FromPrimitive is available again:
        let hash_alg_id = match data[IDENTIFIER_SIZE] {
            0 => HashAlgId::NullHash,
            1 => HashAlgId::Sha1,
            2 => HashAlgId::Sha256,
            n => return Err(format!("invalid hash_alg_id {}", n)),
        };
        if (hash_alg_id as usize) != 2 {
            return Err(
                String::from("only Sha256 is supported for hash algorithm id.")
            );
        }
        return Ok(RTSS{
            identifier: identifier,
            hash_alg_id: hash_alg_id as HashAlgId,
            threshold: data[IDENTIFIER_SIZE + 1],
            data: data[IDENTIFIER_SIZE + 4..].to_vec(),
        });
    }
}

fn f(x: u8, arr: &[u8]) -> u8 {
    let mut x_i: u8 = 1;
    let mut total: u8 = 0;
    for octet in arr {
        total = gf256::add(total, gf256::multiply(*octet, x_i));
        x_i = gf256::multiply(x_i, x);
    }
    total
}

fn lagrange(i: usize, u: &[u8]) -> u8 {
    let mut result = 1;
    let gi = u[i];
    for (j, gj) in u.iter().enumerate() {
        if j != i {
            result = gf256::multiply(result, gf256::divide(*gj, *gj ^ gi));
        }
    }
    result
}

fn interpolate(u: &[u8], v: &[u8]) -> u8 {
    if u.len() != v.len() {
        panic!("arrays to be interpolated must be same length");
    }
    let mut result = 0u8;
    for j in 0..u.len() {
        result ^= gf256::multiply(lagrange(j, &u), v[j as usize]);
    }
    return result;
}

fn mkidentifier() -> [u8; IDENTIFIER_SIZE] {
    let mut rng = rand::os::OsRng::new()
        .expect("couldn't acquire secure PSRNG");
    let mut id = [1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8];
    rng.fill_bytes(&mut id);
    id
}

fn validate_share_args(secret: &Vec<u8>, k: u8, n: u8) -> Result<(), String> {
    if secret.len() > SHARE_DATA_MAX {
        return Err(format!("secret must be no larger than {} bytes",
                           SHARE_DATA_MAX));
    }
    if k > n {
        return Err(String::from(
            "threshold k should be less than number of shares n"));
    }
    Ok(())
}

fn share_tss(secret: &Vec<u8>, k: u8, n: u8) -> Result<Vec<Vec<u8>>, String> {
    try!(validate_share_args(secret, k, n));
    let mut rng = match rand::OsRng::new() {
        Ok(rng) => rng,
        Err(_) => return Err(String::from("couldn't acquire secure PSRNG")),
    };
    let mut vs: Vec<Vec<u8>> = Vec::with_capacity(n as usize);

    for i in 0..(n as usize) {
        let mut v: Vec<u8> = Vec::with_capacity(secret.len() + 1);
        v.push((i + 1) as u8);
        vs.push(v);
    }
    for octet in secret {
        let mut a: Vec<u8> = Vec::with_capacity(k as usize);
        a.push(*octet);
        for _ in 0..k-1 {
            a.push(rng.gen::<u8>());
        }
        for i in 0..n {
            let res = f(vs[i as usize][0], a.as_slice());
            vs[i as usize].push(res);
        }
    }
    return Ok(vs);
}

pub fn share_rtss(secret: &Vec<u8>, k: u8, n: u8) -> Result<Vec<Vec<u8>>, String> {
    try!(validate_share_args(secret, k, n));
    let digest = util::hash(secret);
    assert_eq!(SHA256_DIGEST_SIZE, digest.as_ref().len());
    let hash_alg_id = HashAlgId::Sha256;
    let mut secret_and_digest = Vec::new();
    secret_and_digest.extend_from_slice(secret);
    secret_and_digest.extend_from_slice(digest.as_ref());
    let data = secret_and_digest;
    assert_eq!(secret.len() + digest.as_ref().len(), data.len());

    let shares = try!(share_tss(&data, k, n));

    let identifier = mkidentifier();
    let mut vs: Vec<Vec<u8>> = Vec::with_capacity(n as usize);


    for share in shares.iter() {
        vs.push(try!(RTSS::new(identifier, hash_alg_id, k, share.to_vec())).to_bytes());
    }
    return Ok(vs);
}

fn reconstruct_precheck(shares: &Vec<Vec<u8>>) -> Result<u16, String> {
    if shares.len() >= SHARES_MAX {
        return Err(format!("no more than {} shares are allowed", SHARES_MAX));
    }
    if shares.len() == 0 {
        return Err(String::from("at least 1 share is required"));
    }
    let size = shares[0].len();
    for share in shares.iter() {
        if share.len() != size {
            return Err(String::from("all shares must have same length"));
        }
    }
    return Ok(size as u16);
}

fn reconstruct_tss(shares: &Vec<Vec<u8>>) -> Result<Vec<u8>, String> {
    let size = try!(reconstruct_precheck(shares)) as usize;

    let mut seen = [false; 256];

    for share in shares.iter() {
        let first_byte = share[0] as usize;
        if seen[first_byte] {
            return Err(
                String::from("initial byte of each share should be distinct")
            );
        } else {
            seen[first_byte] = true;
        }
    }
    let u: Vec<u8> = shares.iter().map(|ref s| s[0]).collect();
    let mut secret: Vec<u8> = Vec::with_capacity(size - 1);
    for i in 1..size {
        let v: Vec<u8> = shares.iter().map(|ref s| s[i]).collect();
        secret.push(interpolate(u.as_slice(), v.as_slice()));
    }
    return Ok(secret);
}

pub fn reconstruct_rtss(shares: &Vec<Vec<u8>>) -> Result<Vec<u8>, String> {
    try!(reconstruct_precheck(shares)) as usize;

    let mut rtss_vals: Vec<RTSS> = Vec::with_capacity(shares.len());
    for share in shares.iter() {
        let rtss = try!(RTSS::from_bytes(share));
        rtss_vals.push(rtss);
    }
    let identifier = rtss_vals[0].identifier;
    let hash_alg_id = rtss_vals[0].hash_alg_id;
    let threshold = rtss_vals[0].threshold;
    let mut rtss_data: Vec<Vec<u8>> = Vec::with_capacity(shares.len());
    for rtss in rtss_vals[..].iter() {
        if rtss.identifier != identifier {
            return Err(String::from("all shares must have same identifier"));
        }
        if rtss.hash_alg_id != hash_alg_id {
            return Err(String::from("all shares must have same hash_alg_id"));
        }
        if rtss.threshold != threshold {
            return Err(String::from("all shares must have same threshold"));
        }
        rtss_data.push(rtss.data.to_owned());
    }
    if shares.len() < (threshold as usize) {
        return Err(format!("expected at least {} shares", threshold));
    }
    let rtss_data = rtss_data;

    let secret = try!(reconstruct_tss(&rtss_data));
    if secret.len() <= SHA256_DIGEST_SIZE {
        return Err(String::from("share data is incomplete"));
    }
    let index = secret.len() - SHA256_DIGEST_SIZE;
    let secret_data = secret[0..index].to_vec();
    let mut secret_digest = [0u8; SHA256_DIGEST_SIZE];
    let mut i = 0;
    for octet in secret[index..].iter() {
        secret_digest[i] = *octet;
        i += 1;
    }
    i = 0;
    let mut data_digest = [0u8; SHA256_DIGEST_SIZE];
    for octet in util::hash(&secret_data).as_ref().iter() {
        data_digest[i] = *octet;
        i += 1;
    }
    util::nacl_init();
    if !verify::verify_32(&data_digest, &secret_digest) {
        return Err(String::from("data digest doesn't match expected digest"));
    }
    return Ok(secret_data);
}

#[cfg(test)]
mod tests {
    use super::{mkidentifier, share_tss, share_rtss, reconstruct_tss,
                reconstruct_rtss};

    use rand::{OsRng, Rng};

    const SECRET: [u8; 4] = [3, 1, 4, 1];
    const K: u8 = 2;
    const N: u8 = 3;

    #[test]
    fn test_mkidentifier_size() {
        let id = mkidentifier();
        assert_eq!(16, id.len());
    }

    #[test]
    fn test_mkidentifier_distinct() {
        let id1 = mkidentifier();
        let id2 = mkidentifier();
        assert!(id1 != id2);
    }

    #[test]
    fn test_share_tss() {
        let shares = share_tss(&SECRET.to_vec(), K, N).unwrap();
        assert_eq!(N as usize, shares.len());
        for val in shares.iter() {
            assert_eq!(SECRET.len() + 1, val.len());
        }
    }

    #[test]
    fn test_share_rtss() {
        let shares = share_rtss(&SECRET.to_vec(), K, N).unwrap();
        assert_eq!(N as usize, shares.len());
        let expected_size = SECRET.len() + 1 + 20 + 32;
        for val in shares.iter() {
            assert_eq!(expected_size, val.len());
        }
    }

    #[test]
    fn test_reconstruct_tss() {
        let shares = share_tss(&SECRET.to_vec(), K, N).unwrap();
        assert_eq!(SECRET.to_vec(), reconstruct_tss(&shares[0..2].to_vec()).unwrap());
        assert_eq!(SECRET.to_vec(), reconstruct_tss(&shares[1..3].to_vec()).unwrap());
        assert_eq!(SECRET.to_vec(), reconstruct_tss(&vec![shares[0].to_owned(), shares[2].to_owned()]).unwrap());
    }

    #[test]
    fn test_reconstruct_tss_large() {
        let mut rng = match OsRng::new() {
            Ok(g) => g,
            Err(_) => panic!("couldn't acquire secure PSRNG"),
        };
        let mut secret: Vec<u8> = vec![0u8; 65534];
        rng.fill_bytes(secret.as_mut_slice());
        let secret = secret;
        let shares = share_tss(&secret, K, N).unwrap();
        assert_eq!(secret, reconstruct_tss(&shares[0..2].to_vec()).unwrap());
        assert_eq!(secret, reconstruct_tss(&shares[1..3].to_vec()).unwrap());
        assert_eq!(secret, reconstruct_tss(&vec![shares[0].to_owned(), shares[2].to_owned()]).unwrap());
    }

    #[test]
    fn test_reconstruct_rtss() {
        let shares = share_rtss(&SECRET.to_vec(), K, N).unwrap();
        let secret = SECRET.to_vec();
        assert_eq!(secret, reconstruct_rtss(&shares[0..2].to_vec()).unwrap());
        assert_eq!(secret, reconstruct_rtss(&shares[1..3].to_vec()).unwrap());
        assert_eq!(secret, reconstruct_rtss(&vec![shares[0].to_owned(), shares[2].to_owned()]).unwrap());
    }
}
