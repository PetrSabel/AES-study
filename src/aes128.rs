use hex::{decode, encode};

use crate::{key_schedule::KeySchedule, round_operations::Round, utils::{add_iv, array_into_matrix, matrix_to_array, padding, split_in_blocks, transpose, unpadding}, AESError, AESMode, AES, BLOCK_SIZE, BYTES_PER_ROW};

const KEY_SIZE_BYTES: usize  = 16;
const ROUNDS_NUMBER: usize = 11;

pub struct AES128 {
    keys: Vec<[[u8; BYTES_PER_ROW]; BYTES_PER_ROW]>,
    iv: Option<[u8;BLOCK_SIZE]>,
}

impl AES128 {
    pub fn new_str_key(key: &str, iv: Option<[u8;BLOCK_SIZE]>) -> Result<AES128, AESError> {
        // Key size is fixed to 16 for AES-128
        if key.as_bytes().len() != KEY_SIZE_BYTES {
            dbg!(format!("Key size should be {} bytes!", KEY_SIZE_BYTES));
            return Err(AESError::WrongKeySize(key.as_bytes().len(), KEY_SIZE_BYTES));
        }
        let key: [u8;KEY_SIZE_BYTES] = key.as_bytes().try_into().unwrap();

        let keys = Self::key_schedule(&key)?;
        Ok(AES128 {
            keys,
            iv
        })
    }
}

impl KeySchedule for AES128 {
    fn key_schedule(key: &[u8]) -> Result<Vec<[[u8; BYTES_PER_ROW]; BYTES_PER_ROW]>, AESError> {
        if key.len() != KEY_SIZE_BYTES {
            return Err(AESError::WrongKeySize(key.len(), KEY_SIZE_BYTES));
        }
        // At this point key should have the needed size
        let key = key.try_into().unwrap();

        let mut first_key: [[u8; BYTES_PER_ROW]; BYTES_PER_ROW] = array_into_matrix(&key);
        // // Temporally store keys by-columns
        transpose(&mut first_key);
        let mut generated_keys = [first_key; ROUNDS_NUMBER];
        // Leave first key untouched
        for i in 1..ROUNDS_NUMBER {
            let last_key = generated_keys[i-1];
            let mut new_key = last_key.clone();
            let last_column = &mut last_key[3].clone();
            
            Self::rot_word(last_column);
            Self::sub_word(last_column);
            Self::r_con(last_column, i);
            
            // New first column
            Self::add_to_column(&mut new_key[0], &last_column);
            // New second, third and fourth columns
            for i in 1..BYTES_PER_ROW {
                let new_column = new_key[i-1].clone();
                Self::add_to_column(&mut new_key[i], &new_column);
            }

            // Add new key to array
            generated_keys[i] = new_key;
        }

        // Return keys to normal (by-row) view
        for i in 0..generated_keys.len() {
            transpose(&mut generated_keys[i]);
        }

        Ok(generated_keys.to_vec())
    }
}

impl Round for AES128 {

}

impl AES for AES128 {
    fn new(key: &[u8], iv: Option<[u8;16]>) -> Result<Box<Self>, AESError> {
        if key.len() != KEY_SIZE_BYTES {
            dbg!("Key has wrong size");
            return Err(AESError::WrongKeySize(key.len(), KEY_SIZE_BYTES))
        }
        // The size should be know at this time
        let key: [u8;KEY_SIZE_BYTES] = key.try_into().unwrap();
        let keys = Self::key_schedule(&key)?;

        Ok(Box::new(
            Self {
                keys,
                iv
        }))
    }

    // Apply all round to one block
    fn encrypt_block(&self, block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let mut block = array_into_matrix(block);
        let keys = &self.keys;

        // First round
        Self::add_round_key(&mut block, &keys, 0);

        // For 9 rounds
        for i in 1..ROUNDS_NUMBER-1 {
            Self::substitute_bytes(&mut block, false);
            Self::shift_rows(&mut block);
            Self::mix_columns(&mut block);
            Self::add_round_key(&mut block, keys, i);
        }

        // Final round
        Self::substitute_bytes(&mut block, false);
        Self::shift_rows(&mut block);
        Self::add_round_key(&mut block, keys, 10);

        let result = matrix_to_array(&block);
        result
    }

    fn encrypt_blocks(&self, data: &[[u8; BLOCK_SIZE]], mode: AESMode) 
                        -> Result<Vec<[u8; BLOCK_SIZE]>, AESError> {
        let result = match mode {
            AESMode::ECB => {
                // Encrypt each block separately
                let mut tmp = Vec::new();
                for block in data {
                    tmp.push(self.encrypt_block(block));
                }
                tmp
            }, 
            AESMode::CBC => {
                // Encrypt block in chain
                let mut tmp = Vec::new();
                let mut iv = self.iv.as_ref()
                            .ok_or(AESError::ModeRequiresIV(mode))?;

                for block in data {
                    tmp.push(self.encrypt_block(&add_iv(block, iv)));
                    // Just pushed so must be present
                    iv = tmp.last().unwrap();
                }
                tmp
            },
            _ => panic!("Not recognized mode")
        };

        Ok(result)
    }

    fn encrypt_string(&self, s: &str) -> String {
        let bytes: Vec<u8> = s.as_bytes().to_owned();
        let padded = padding(&bytes);
        // Padding should work correctly
        let chunks: Vec<[u8; 16]> = split_in_blocks(&padded).unwrap();
        let encrypted_chunks: Vec<_> = chunks.into_iter().map(|b| self.encrypt_block(&b)).collect();
        let result: Vec<_> = encrypted_chunks.into_iter().flatten().collect();

        let result = encode(result);
        result
    }

    fn decrypt_block(&self, block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let mut block = array_into_matrix(block);
        let keys = &self.keys;

        // First round
        Self::add_round_key(&mut block, keys, ROUNDS_NUMBER-1);

        // For 9 rounds
        for i in (1..ROUNDS_NUMBER-1).rev() {
            Self::inverse_shift_rows(&mut block);
            Self::substitute_bytes(&mut block, true);
            Self::add_round_key(&mut block, keys, i);
            Self::inverse_mix_columns(&mut block);
        }

        // Final round
        Self::inverse_shift_rows(&mut block);
        Self::substitute_bytes(&mut block, true);
        Self::add_round_key(&mut block, keys, 0);

        let result = matrix_to_array(&block);
        result
    }

    // Get string of bytes in hex and return normal string
    fn decrypt_string(&self, s: &str) -> Result<String, AESError> {
        let bytes: Vec<u8> = decode(s).ok().ok_or(AESError::TryDecodeNotHEXString(s.to_string()))?;
        let chunks: Vec<[u8; 16]> = split_in_blocks(&bytes)?;
        let decrypted_chunks: Vec<_> = chunks.into_iter().map(|b| self.decrypt_block(&b)).collect();
        let result: Vec<_> = decrypted_chunks.into_iter().flatten().collect();
        
        let result = unpadding(&result)?;
        // TODO: Maybe declare new error for this (but it is not inside AES trait)
        let result = String::from_utf8(result)
                .expect("Decrypted string cannot be decoded as UTF-8.");
        
        Ok(result)
    }
}

#[cfg(test)]
mod aes128_tests {
    use crate::{aes128::AES128, key_schedule::KeySchedule, AESMode, AES};


    #[test]
    fn test_key128_schedule() {
        let key = [0xc3, 0x2c, 0x5c, 166, 181, 128, 94, 12, 219, 141, 165, 122, 42, 182, 254, 92];
        let keys = AES128::key_schedule(&key).unwrap();

        let last_key = [[9, 119, 111, 46], [99, 40, 31, 86], [11, 176, 173, 94], [19, 155, 174, 232]];
        assert_eq!(keys[10], last_key);
    }

    #[test]
    fn test_encrypt_block() {
        let block: [u8;16] = "crypto{MYAES128}".as_bytes().try_into().unwrap();
        let key: [u8;16] = [0xc3, 0x2c, 0x5c, 166, 181, 128, 94, 12, 219, 141, 165, 122, 42, 182, 254, 92];
        let aes = AES128::new(&key, None).unwrap();
        let result = aes.encrypt_block(&block);

        let expected_result = [209, 79, 20, 106, 164, 43, 79, 182, 161, 196, 8, 66, 41, 143, 18, 221];
        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_encrypt_blocks_ecb() {
        let block: [u8;16] = "crypto{MYAES128}".as_bytes().try_into().unwrap();
        let key: [u8;16] = [0xc3, 0x2c, 0x5c, 166, 181, 128, 94, 12, 219, 141, 165, 122, 42, 182, 254, 92];
        let aes = AES128::new(&key, None).unwrap();
        let data = [block; 2];

        let result = aes.encrypt_blocks(&data, AESMode::ECB).unwrap();

        assert_eq!(result[0], result[1]);
    }

    #[test]
    fn test_encrypt_blocks_cbc() {
        let block: [u8;16] = "crypto{MYAES128}".as_bytes().try_into().unwrap();
        let key: [u8;16] = [0xc3, 0x2c, 0x5c, 166, 181, 128, 94, 12, 219, 141, 165, 122, 42, 182, 254, 92];
        let aes = AES128::new(&key, Some(block.clone())).unwrap();
        let data = [block; 2];

        let result = aes.encrypt_blocks(&data, AESMode::CBC).unwrap();

        println!("{:?}", result);
        assert_ne!(result[0], result[1]);
    }

    #[test]
    fn test_encrypt_string() {
        let aes = AES128::new_str_key("aaaabbbbccccdddd", None).expect("The key size is wrong");
        let result = aes.encrypt_string("crypto{MYAES128}");
        let expected = "f1c7205c1673507d92530837341bcaca6351bbed02ca98ca6f3ea54112e8a720";

        assert_eq!(expected, result);
    }

    #[test]
    fn test_decrypt_block() {
        let block = [209, 79, 20, 106, 164, 43, 79, 182, 161, 196, 8, 66, 41, 143, 18, 221];
        let key: [u8;16] = [0xc3, 0x2c, 0x5c, 166, 181, 128, 94, 12, 219, 141, 165, 122, 42, 182, 254, 92];
        let aes = AES128::new(&key, None).unwrap();
        let result = aes.decrypt_block(&block);

        let expected_result: [u8;16] = "crypto{MYAES128}".as_bytes().try_into().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_encrypt_decrypt_block() {
        let block: [u8;16] = "crypto{MYAES128}".as_bytes().try_into().unwrap();
        let key: [u8;16] = [0xc3, 0x2c, 0x5c, 166, 181, 128, 94, 12, 219, 141, 165, 122, 42, 182, 254, 92];
        let aes = AES128::new(&key, None).unwrap();

        let crypted = aes.encrypt_block(&block);
        let result = aes.decrypt_block(&crypted);

        assert_eq!(result, block);
    }    

    #[test]
    fn test_decrypt_string() {
        let aes = AES128::new_str_key("aaaabbbbccccdddd", None).expect("The key size is wrong");
        let result = aes.decrypt_string("f1c7205c1673507d92530837341bcaca6351bbed02ca98ca6f3ea54112e8a720").unwrap();
        let expected = "crypto{MYAES128}";

        assert_eq!(expected, result);
    }

    #[test]
    fn test_encrypt_decrypt_string() {
        let aes = AES128::new_str_key("aaaabbbbccccdddd", None).expect("The key size is wrong");
        let s = "crypto{MYAES128}";
        let result = aes.encrypt_string(s);
        let decrypted = aes.decrypt_string(&result).unwrap();
        assert_eq!(s, decrypted);
    }
}