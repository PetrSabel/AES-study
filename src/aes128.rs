use crate::{key_schedule::KeySchedule, round_operations::Round, BYTES_PER_ROW, utils::{array_into_matrix, matrix_to_array, padding, transpose}, AES, BLOCK_SIZE};

const KEY_SIZE_BYTES: usize  = 16;
const ROUNDS_NUMBER: usize = 11;

pub struct AES128 {
    key: [u8; KEY_SIZE_BYTES],
}

impl AES128 {

    // TODO: change String to actual Error
    pub fn new(key: [u8;KEY_SIZE_BYTES]) -> AES128 {
        AES128 {
            key
        }
    }

    pub fn new_str_key(key: &str) -> Result<AES128, String> {
        // 16 is fixed for AES-128
        if key.as_bytes().len() != KEY_SIZE_BYTES {
            return Err(String::from("Key size should be 16 bytes!"));
        }
        let key: [u8;KEY_SIZE_BYTES] = key.as_bytes().try_into().unwrap();

        Ok(AES128 {
            key
        })
    }
}

impl KeySchedule for AES128 {
    fn key_schedule(key: &[u8; KEY_SIZE_BYTES]) -> Vec<[[u8; BYTES_PER_ROW]; BYTES_PER_ROW]> {

        let mut first_key: [[u8; BYTES_PER_ROW]; BYTES_PER_ROW] = array_into_matrix(key.clone());
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

        generated_keys.to_vec()
    }
}

impl Round for AES128 {

}

impl AES for AES128 {
    // Apply all round to one block
    fn encrypt_block(&self, block: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let mut block = array_into_matrix(block);
        let keys = AES128::key_schedule(&self.key);

        // First round
        Self::add_round_key(&mut block, &keys, 0);

        // For 9 rounds
        for i in 1..ROUNDS_NUMBER-1 {
            AES128::substitute_bytes(&mut block);
            AES128::shift_rows(&mut block);
            AES128::mix_columns(&mut block);
            AES128::add_round_key(&mut block, &keys, i);
        }

        // Final round
        AES128::substitute_bytes(&mut block);
        AES128::shift_rows(&mut block);
        AES128::add_round_key(&mut block, &keys, 10);

        let result = matrix_to_array(block);
        result
    }

    // TODO: make a separate function for conversion of string into a Vec of [u8;16] (blocks)
    fn encrypt_string(&self, s: &str) -> Vec<u8> {
        let bytes: Vec<u8> = s.as_bytes().to_owned();
        let chunks: Vec<[u8; 16]> = padding(&bytes).chunks(16)
            .map(|c| c.try_into().unwrap()).collect();
        let encypted_chunks: Vec<_> = chunks.into_iter().map(|b| self.encrypt_block(b)).collect();
        let result: Vec<_> = encypted_chunks.into_iter().flatten().collect();

        result
    }
}

#[cfg(test)]
mod aes128_tests {
    use crate::{aes128::AES128, key_schedule::KeySchedule, AES};


    #[test]
    fn test_key128_schedule() {
        let key = [0xc3, 0x2c, 0x5c, 166, 181, 128, 94, 12, 219, 141, 165, 122, 42, 182, 254, 92];
        let keys = AES128::key_schedule(&key);

        let last_key = [[9, 119, 111, 46], [99, 40, 31, 86], [11, 176, 173, 94], [19, 155, 174, 232]];
        assert_eq!(keys[10], last_key);
    }

    #[test]
    fn test_encrypt_block() {
        let block: [u8;16] = "crypto{MYAES128}".as_bytes().try_into().unwrap();
        let key: [u8;16] = [0xc3, 0x2c, 0x5c, 166, 181, 128, 94, 12, 219, 141, 165, 122, 42, 182, 254, 92];
        let aes = AES128::new(key);
        let result = aes.encrypt_block(block);

        let expected_result = [209, 79, 20, 106, 164, 43, 79, 182, 161, 196, 8, 66, 41, 143, 18, 221];
        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_encrypt_string() {
        let aes = AES128::new_str_key("aaaabbbbccccdddd").expect("The key size is wrong");
        let result = aes.encrypt_string("crypto{MYAES128}");
        let expected = vec![241, 199, 32, 92, 22, 115, 80, 125, 146, 83, 8, 55, 52,
         27, 202, 202, 99, 81, 187, 237, 2, 202, 152, 202, 111, 62, 165, 65, 18, 232, 167, 32];

        assert_eq!(expected, result);
    }
}