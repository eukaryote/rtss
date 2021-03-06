//! Integration tests for the library

extern crate rtss;

#[test]
fn test_roundtrip_exact_threshold() {
    let secret = b"Hello, world!".to_vec();
    let shares = rtss::share_rtss(&secret, 2, 3).unwrap();
    let result = rtss::reconstruct_rtss(&shares[0..2].to_vec()).unwrap();
    assert_eq!(secret, result);
}

#[test]
fn test_roundtrip_more_than_threshold() {
    let secret = b"Hello, world!".to_vec();
    let shares = rtss::share_rtss(&secret, 2, 3).unwrap();
    let result = rtss::reconstruct_rtss(&shares).unwrap();
    assert_eq!(secret, result);
}

#[test]
fn test_roundtrip_less_than_threshold() {
    let secret = b"Hello, world!".to_vec();
    let shares = rtss::share_rtss(&secret, 2, 3).unwrap();
    let result = rtss::reconstruct_rtss(&shares[0..1].to_vec());
    assert!(!result.is_ok());
    let msg = match result {
        Err(msg) => msg,
        Ok(_) => unreachable!(),
    };
    assert_eq!("expected at least 2 shares", msg);
}
