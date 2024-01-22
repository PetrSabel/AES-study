#![allow(dead_code)]
mod utils;
mod round_operations;

use std::str::from_utf8;

use round_operations::encrypt_block;

const BLOCK_SIZE: usize = 16;

// TODO: make a separate function for conversion of string into a Vec of [u8;16] (blocks)
pub fn encrypt_string(s: &str, key: &str) -> Vec<u8> {
    let len = s.len();
    let padding_len = if len % BLOCK_SIZE == 0 { 0 } else { 16 - len % BLOCK_SIZE };
    let vec_padding = vec![' ' as u8; padding_len];
    let padding = from_utf8(&vec_padding).expect("Padding not created");
    let padded = s.clone().to_string() + padding;

    if key.as_bytes().len() != 16 {
        panic!("Key size should be 16 bytes!");
    }
    let key: [u8;16] = key.as_bytes().try_into().unwrap();

    let chunks: Vec<[u8;16]> = padded.as_bytes().chunks(16)
        .map(|c| c.try_into().unwrap()).collect();
    let encypted_chunks: Vec<_> = chunks.into_iter().map(|b| encrypt_block(b, key)).collect();
    let result: Vec<_> = encypted_chunks.into_iter().flatten().collect();
    println!("{:x?}", result);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_string() {
        encrypt_string("crypto{MYAES128}", "aaaabbbbccccdddd");
    }
}
