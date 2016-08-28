//! GF256 arithmetic helpers, implemented using lookup tables.

/// EXP[i] values, for i in range [0, 255).
#[cfg_attr(rustfmt, rustfmt_skip)]
static EXP: [u8; 255] = [
    0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff,
    0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
    0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4,
    0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
    0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26,
    0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
    0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc,
    0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
    0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7,
    0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
    0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f,
    0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
    0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0,
    0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
    0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec,
    0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
    0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2,
    0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
    0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0,
    0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
    0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e,
    0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
    0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf,
    0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
    0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09,
    0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
    0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91,
    0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
    0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c,
    0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
    0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd,
    0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6
];

/// LOG[i] values, for i in range [1, 256).
#[cfg_attr(rustfmt, rustfmt_skip)]
static LOG: [u8; 256] = [
    0x00, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6,
    0x4b, 0xc7, 0x1b, 0x68, 0x33, 0xee, 0xdf, 0x03,
    0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d, 0x81, 0xef,
    0x4c, 0x71, 0x08, 0xc8, 0xf8, 0x69, 0x1c, 0xc1,
    0x7d, 0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a,
    0x4d, 0xe4, 0xa6, 0x72, 0x9a, 0xc9, 0x09, 0x78,
    0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1, 0x24,
    0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e,
    0x96, 0x8f, 0xdb, 0xbd, 0x36, 0xd0, 0xce, 0x94,
    0x13, 0x5c, 0xd2, 0xf1, 0x40, 0x46, 0x83, 0x38,
    0x66, 0xdd, 0xfd, 0x30, 0xbf, 0x06, 0x8b, 0x62,
    0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10,
    0x7e, 0x6e, 0x48, 0xc3, 0xa3, 0xb6, 0x1e, 0x42,
    0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85, 0x3d, 0xba,
    0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca,
    0x4e, 0xd4, 0xac, 0xe5, 0xf3, 0x73, 0xa7, 0x57,
    0xaf, 0x58, 0xa8, 0x50, 0xf4, 0xea, 0xd6, 0x74,
    0x4f, 0xae, 0xe9, 0xd5, 0xe7, 0xe6, 0xad, 0xe8,
    0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5,
    0x59, 0xcb, 0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0,
    0x7f, 0x0c, 0xf6, 0x6f, 0x17, 0xc4, 0x49, 0xec,
    0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7,
    0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60, 0xb1, 0x86,
    0x3b, 0x52, 0xa1, 0x6c, 0xaa, 0x55, 0x29, 0x9d,
    0x97, 0xb2, 0x87, 0x90, 0x61, 0xbe, 0xdc, 0xfc,
    0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1,
    0x53, 0x39, 0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47,
    0x14, 0x2a, 0x9e, 0x5d, 0x56, 0xf2, 0xd3, 0xab,
    0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e, 0x89,
    0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99, 0xe3, 0xa5,
    0x67, 0x4a, 0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18,
    0x0d, 0x63, 0x8c, 0x80, 0xc0, 0xf7, 0x70, 0x07,
];

/// Adds two GF(256) elements.
pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Multiplies two GF(256) elements.
pub fn multiply(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    EXP[(((LOG[a as usize] as u16) + (LOG[b as usize] as u16)) % 255) as usize]
}

/// Divides GF(256) element `a` by non-zero GF(256) element `b`, panicking if `b` is zero.
pub fn divide(a: u8, b: u8) -> u8 {
    if b == 0 {
        panic!("ZeroDivisionError");
    }
    if a == 0 {
        return 0;
    }
    let (loga, logb) = (LOG[a as usize], LOG[b as usize]);
    let diff = if logb > loga {
        255 - (logb - loga)
    } else {
        loga - logb
    };
    EXP[diff as usize]
}

#[cfg(test)]
mod tests {
    use super::{add, multiply, divide, EXP, LOG};

    #[test]
    fn it_adds_any_two_elems() {
        for a in 0u16..256u16 {
            for b in 0..256u16 {
                let a = a as u8;
                let b = b as u8;
                assert_eq!(a ^ b, add(a, b));
                assert_eq!(a ^ b, add(b, a));
            }

        }

    }

    #[test]
    fn it_multiplies_zero_elems() {
        assert_eq!(0u8, multiply(0u8, 0u8));
    }

    #[test]
    fn it_multiplies_zero_and_nonzero_elems() {
        for b in 1u16..256u16 {
            assert_eq!(0u8, multiply(0u8, b as u8));
        }
    }

    #[test]
    fn it_multiplies_nonzero_and_zero_elems() {
        for a in 1u16..256u16 {
            assert_eq!(0u8, multiply(a as u8, 0u8));
        }
    }

    #[test]
    fn it_multiplies_any_two_nonzero_elems() {
        for a in 1u16..256u16 {
            for b in 1u16..256u16 {
                let expected = if a == 1 {
                    b as u8
                } else if b == 1 {
                    a as u8
                } else {
                    let loga = LOG[a as usize] as u16;
                    let logb = LOG[b as usize] as u16;
                    let index = (loga + logb) % 255;
                    EXP[index as usize]
                };
                assert_eq!(expected, multiply(a as u8, b as u8));
            }
        }
    }

    #[test]
    #[should_panic]
    fn it_panics_dividing_zero_by_zero() {
        divide(0, 0);
    }
    #[test]
    #[should_panic]
    fn it_panics_dividing_nonzero_by_zero() {
        divide(1, 0);
    }

    #[test]
    fn it_divides_zero_by_nonzero() {
        for n in 1u16..256u16 {
            assert_eq!(0, divide(0, n as u8));
        }
    }

    #[test]
    fn it_divides_nonzero_by_nonzero() {
        for numerator in 1..256 {
            for denominator in 1..256 {
                let mut index = 0;
                if numerator != 0 {
                    let (logn, logd) = (LOG[numerator], LOG[denominator]);
                    if logn < logd {
                        index = 255 - (logd - logn)
                    } else {
                        index = logn - logd
                    }
                }
                let expected = EXP[(index % 255) as usize];
                assert_eq!(expected, divide(numerator as u8, denominator as u8));
            }
        }
    }

    #[test]
    fn it_has_valid_exp_table() {
        assert_eq!(255, EXP.len());
        let gen = 3;
        assert_eq!(1, EXP[0]);
        assert_eq!(gen, EXP[1]);

        let mut val = gen;
        for i in 2..255 {
            val = multiply(gen, val);
            assert_eq!(EXP[i as usize], val);
        }
    }

    #[test]
    fn it_has_valid_log_table() {
        assert_eq!(256, LOG.len());
        for i in 1u16..256u16 {
            assert_eq!(i as u8, EXP[LOG[i as usize] as usize]);
            if i < 255 {
                assert_eq!(i as u8, LOG[EXP[i as usize] as usize]);
            }
        }
    }
}
