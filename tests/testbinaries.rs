//! Integration tests for app binaries.

use std::process::{Command, Output};

fn share(args: &Vec<&str>) -> std::io::Result<Output> {
    Command::new("./target/debug/rtss-share")
        .args(args)
        .output()
}

fn reconstruct(args: &Vec<&str>) -> std::io::Result<Output> {
    Command::new("./target/debug/rtss-reconstruct")
        .args(args)
        .output()
}

#[test]
fn test_roundtrip() {
    let args = vec!["-k", "2", "-n", "3", "helloworld!"];
    let output = share(&args).unwrap();
    assert!(output.status.success());
    assert_eq!(0, output.status.code().unwrap());
    assert_eq!("", String::from_utf8(output.stderr).unwrap());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines = stdout.split_whitespace().collect::<Vec<&str>>();
    assert_eq!(3, lines.len());

    let output = reconstruct(&lines[0..2].to_vec()).unwrap();
    assert!(output.status.success());
    assert_eq!(0, output.status.code().unwrap());
    assert_eq!("", String::from_utf8(output.stderr).unwrap());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines = stdout.split_whitespace().collect::<Vec<&str>>();
    assert_eq!(1, lines.len());
    assert_eq!("helloworld!", lines[0]);
}
