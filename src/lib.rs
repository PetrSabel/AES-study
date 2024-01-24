#![allow(dead_code)]

use key_schedule::KeySchedule;
use round_operations::Round;
mod utils;
mod round_operations;
mod key_schedule;
mod aes128;


pub const BLOCK_SIZE: usize = 16;
pub(crate) const BYTES_PER_ROW: usize = 4;

// TODO: read from file
// TODO: add modes
// TODO: write simple function to encode/decode HEX
// TODO: add more tests
pub trait AES: KeySchedule + Round {
    fn encrypt_block(&self, block: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE];
    // Take UTF-8 string and produces encypted string encoded in HEX
    fn encrypt_string(&self, s: &str) -> String;
    fn decrypt_block(&self, block: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE];
    // Take HEX encoded string and produces UTF-8 string
    fn decrypt_string(&self, s: &str) -> String;
}
