#![feature(test)]

extern crate rand;
extern crate test;
extern crate rtss;

#[cfg(test)]
mod small {
    use test::Bencher;
    use rtss;

    #[bench]
    fn empty(b: &mut Bencher) {
        b.iter(|| 1)
    }

    #[bench]
    fn one_byte_share_rtss_one_of_one(b: &mut Bencher) {
        let v: Vec<u8> = vec![42];
        b.iter(|| { rtss::share_rtss(&v, 1, 1); });
    }

    #[bench]
    fn two_bytes_share_rtss_one_of_two(b: &mut Bencher) {
        let v: Vec<u8> = vec![42, 77];
        b.iter(|| { rtss::share_rtss(&v, 1, 2); });
    }

    #[bench]
    fn two_bytes_share_rtss_two_of_two(b: &mut Bencher) {
        let v: Vec<u8> = vec![42, 77];
        b.iter(|| { rtss::share_rtss(&v, 2, 2); });
    }

    #[bench]
    fn two_bytes_share_rtss_one_of_three(b: &mut Bencher) {
        let v: Vec<u8> = vec![42, 77];
        b.iter(|| { rtss::share_rtss(&v, 1, 3); });
    }

    #[bench]
    fn two_bytes_share_rtss_two_of_three(b: &mut Bencher) {
        let v: Vec<u8> = vec![42, 77];
        b.iter(|| { rtss::share_rtss(&v, 2, 3); });
    }

    #[bench]
    fn two_bytes_share_rtss_three_of_three(b: &mut Bencher) {
        let v: Vec<u8> = vec![42, 77];
        b.iter(|| { rtss::share_rtss(&v, 3, 3); });
    }

    #[bench]
    fn five_bytes_share_rtss_one_of_five(b: &mut Bencher) {
        let v: Vec<u8> = vec![42, 77, 33, 111, 51];
        b.iter(|| { rtss::share_rtss(&v, 1, 5); });
    }

    #[bench]
    fn five_bytes_share_rtss_two_of_five(b: &mut Bencher) {
        let v: Vec<u8> = vec![42, 77, 33, 111, 51];
        b.iter(|| { rtss::share_rtss(&v, 2, 5); });
    }


    #[bench]
    fn five_bytes_share_rtss_three_of_five(b: &mut Bencher) {
        let v: Vec<u8> = vec![42, 77, 33, 111, 51];
        b.iter(|| { rtss::share_rtss(&v, 3, 5); });
    }

    #[bench]
    fn five_bytes_share_rtss_four_of_five(b: &mut Bencher) {
        let v: Vec<u8> = vec![42, 77, 33, 111, 51];
        b.iter(|| { rtss::share_rtss(&v, 4, 5); });
    }

    #[bench]
    fn five_bytes_share_rtss_five_of_five(b: &mut Bencher) {
        let v: Vec<u8> = vec![42, 77, 33, 111, 51];
        b.iter(|| { rtss::share_rtss(&v, 5, 5); });
    }

}

#[cfg(test)]
mod large {
    use rand::{OsRng, Rng};
    use test::Bencher;
    use rtss;

    #[bench]
    fn max_size_share_rtss_three_of_five(b: &mut Bencher) {
        let mut v: Vec<u8> = vec![0u8; 65534];
        OsRng::new().unwrap().fill_bytes(v.as_mut_slice());
        b.iter(|| rtss::share_rtss(&v, 3, 5));
    }

    #[bench]
    fn max_size_share_rtss_thirty_one_of_forty_two(b: &mut Bencher) {
        let mut v: Vec<u8> = vec![0u8; 65534];
        OsRng::new().unwrap().fill_bytes(v.as_mut_slice());
        b.iter(|| rtss::share_rtss(&v, 31, 42));
    }

    #[bench]
    fn max_size_share_rtss_ninety_nine_of_two_hundred_fifty_five(b: &mut Bencher) {
        let mut v: Vec<u8> = vec![0u8; 65534];
        OsRng::new().unwrap().fill_bytes(v.as_mut_slice());
        b.iter(|| rtss::share_rtss(&v, 99, 255));
    }
}
