#![allow(dead_code)]

use key_schedule::KeySchedule;
use round_operations::Round;
mod utils;
mod round_operations;
mod key_schedule;
mod aes128;


pub const BLOCK_SIZE: usize = 16;
pub(crate) const BYTES_PER_ROW: usize = 4;

pub trait AES: KeySchedule + Round {
    fn encrypt_block(&self, block: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE];
    fn encrypt_string(&self, s: &str) -> Vec<u8>;
}
