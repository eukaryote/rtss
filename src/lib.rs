//! Public API for rtss library.

extern crate rand;
extern crate sodiumoxide;

mod util;
mod gf256;
mod core;

pub use self::core::{share_rtss, reconstruct_rtss};
