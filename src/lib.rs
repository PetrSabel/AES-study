#![allow(dead_code)]

use key_schedule::KeySchedule;
use round_operations::Round;
mod utils;
mod round_operations;
mod key_schedule;
mod aes128;


pub const BLOCK_SIZE: usize = 16;
pub(crate) const BYTES_PER_ROW: usize = 4;

#[derive(Debug, Clone, Copy)]
pub enum AESMode {
    ECB,
    CBC,
    OFB
}

// TODO: add tests
#[derive(Debug)]
pub enum AESError {
    DataNotDivisibleInBlocks(usize, usize),
    WrongKeySize(usize, usize),
    ModeRequiresIV(AESMode),
    TryDecodeNotHEXString(String),
    WrongPaddingLength(usize, usize),
    WrongPaddingValue(u8, u8),
    DecryptedStringNotUTF8(Vec<u8>),
}

// TODO: read from file
// TODO: add more advanced modes
// TODO: write simple function to encode/decode HEX
// TODO: add more tests
pub trait AES: KeySchedule + Round {
    // Create instance of AES structure
    fn new(key: &[u8], iv: Option<[u8;BLOCK_SIZE]>) -> Result<Box<Self>, AESError>;

    // Encrypt only one block
    fn encrypt_block(&self, block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE];
    // Encrypt sequence of block using given mode
    fn encrypt_blocks(&self, data: &[[u8; BLOCK_SIZE]], mode: AESMode)
                        -> Result<Vec<[u8; BLOCK_SIZE]>, AESError>;
    // Take UTF-8 string and produces encypted string encoded in HEX
    fn encrypt_string(&self, s: &str) -> Result<String, AESError>;

    // Decrypt only one block
    fn decrypt_block(&self, block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE];
    fn decrypt_blocks(&self, data: &[[u8; BLOCK_SIZE]], mode: AESMode)
                        -> Result<Vec<[u8; BLOCK_SIZE]>, AESError>;
    // Take HEX encoded string and produces UTF-8 string
    fn decrypt_string(&self, s: &str) -> Result<String, AESError>;
}
