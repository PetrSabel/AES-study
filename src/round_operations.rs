use crate::utils::{add_to_column, array_into_matrix, compute_s_box, gf_multiplication, matrix_to_array, r_con, rot_word, sub_word, transpose};

const BYTES_PER_ROW: usize = 4;

// Substitute bytes method
fn substitute_bytes(bytes: &mut [[u8; 4]; 4]) {
    let s_box = compute_s_box();
    for i in 0..4 {
        for j in 0..4 {
            bytes[i][j] = s_box[bytes[i][j] as usize];
        }
    }
}

fn shift_rows(bytes: &mut [[u8; BYTES_PER_ROW]; BYTES_PER_ROW]) {
    for i in 0..bytes[0].len() {
        bytes[i].rotate_left(i);
    }
}

// TODO: add tests
fn mix_column(column: &mut [u8; 4]) {
    // Perform explicit matrix multiplication
    let mut temp = [0; 4];
    temp[0] = gf_multiplication(0x02, column[0]) ^ gf_multiplication(0x03, column[1])
            ^ column[2] ^ column[3];
    temp[1] = column[0] ^ gf_multiplication(0x02, column[1])
            ^ gf_multiplication(0x03, column[2]) ^ column[3];
    temp[2] = column[0] ^ column[1]
            ^ gf_multiplication(0x02, column[2]) ^ gf_multiplication(0x03, column[3]);
    temp[3] = gf_multiplication(0x03, column[0]) ^ column[1]
            ^ column[2] ^ gf_multiplication(0x02, column[3]);

    *column = temp;
}

fn mix_columns(bytes: &mut [[u8; 4]; 4]) {
    transpose(bytes);
    for i in 0..4 {
        mix_column(&mut bytes[i]);
    }
    transpose(bytes);
}

fn key128_schedule(key: [u8; 16]) -> [[[u8; 4]; 4]; 11] {
    const KEYS_NUMBER: usize = 11;
    let mut first_key: [[u8; 4]; 4] = array_into_matrix(key);
    // // Temporally store keys by-columns
    transpose(&mut first_key);
    let mut generated_keys = [first_key; KEYS_NUMBER];
    // Leave first key untouched
    for i in 1..generated_keys.len() {
        let last_key = generated_keys[i-1];
        let mut new_key = last_key.clone();
        let last_column = &mut last_key[3].clone();
        // println!("HERE {:?}", last_column);
        
        rot_word(last_column);
        // println!("ROT {:?}", last_column);
        sub_word(last_column);
        // println!("S {:?}", last_column);
        r_con(last_column, i);
        // println!("AFTER {:?}", last_column);
        
        // New first column
        add_to_column(&mut new_key[0], &last_column);
        // New second column
        for i in 1..4 {
            let new_column = new_key[i-1].clone();
            add_to_column(&mut new_key[i], &new_column);
        }

        // Add new key to array
        generated_keys[i] = new_key;
    }

    // Return keys to normal (by-row) view
    for i in 0..generated_keys.len() {
        transpose(&mut generated_keys[i]);
    }

    generated_keys
}

fn add_round_key(bytes: &mut [[u8; 4]; 4], keys: &[[[u8; 4]; 4]; 11], round: usize) {
    for i in 0..4 {
        for j in 0..4 {
            bytes[i][j] ^= keys[round][i][j];
        }
    }
}

pub fn encrypt_block(block: [u8; 16], key: [u8; 16]) -> [u8; 16] {
    let mut block = array_into_matrix(block);
    let keys = key128_schedule(key);

    // First round
    add_round_key(&mut block, &keys, 0);

    // For 9 rounds
    for i in 1..10 {
        substitute_bytes(&mut block);
        shift_rows(&mut block);
        mix_columns(&mut block);
        add_round_key(&mut block, &keys, i);
    }

    // Final round
    substitute_bytes(&mut block);
    shift_rows(&mut block);
    add_round_key(&mut block, &keys, 10);

    let result = matrix_to_array(block);
    result
}



#[cfg(test)]
mod tests {
    use crate::{round_operations::{mix_column, mix_columns}, utils::transpose};

    use super::{encrypt_block, key128_schedule, shift_rows};

    #[test]
    fn test_shift_rows() {
        let mut rows: [[u8; 4]; 4] = [[0, 1, 2, 3],
                                    [4, 5, 6, 7],
                                    [8, 9, 10, 11],
                                    [12, 13, 14, 15]];
        let shifted_rows: [[u8; 4]; 4] = [[0, 1, 2, 3],
                                        [5, 6, 7, 4],
                                        [10, 11, 8, 9],
                                        [15, 12, 13, 14]];

        shift_rows(&mut rows);
        assert_eq!(rows, shifted_rows);
    }

    #[test]
    fn test_key128_schedule() {
        let key = [0xc3, 0x2c, 0x5c, 166, 181, 128, 94, 12, 219, 141, 165, 122, 42, 182, 254, 92];
        let keys = key128_schedule(key);

        let last_key = [[9, 119, 111, 46], [99, 40, 31, 86], [11, 176, 173, 94], [19, 155, 174, 232]];
        assert_eq!(keys[10], last_key);
    }

    #[test]
    fn test_encrypt_block() {
        let block: [u8;16] = "crypto{MYAES128}".as_bytes().try_into().unwrap();
        println!("{}", std::str::from_utf8(&block).unwrap());
        let key = [0xc3, 0x2c, 0x5c, 166, 181, 128, 94, 12, 219, 141, 165, 122, 42, 182, 254, 92];
        let result = encrypt_block(block, key);

        let expected_result = [209, 79, 20, 106, 164, 43, 79, 182, 161, 196, 8, 66, 41, 143, 18, 221];
        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_mix_column() {
        let mut column = [0xd4, 0xbf, 0x5d, 0x30];
        mix_column(&mut column);

        let expected = [4, 102, 129, 229];
        assert_eq!(column, expected);
    }

    #[test]
    fn test_mix_columns() {
        let column = [0xd4, 0xbf, 0x5d, 0x30];
        let mut mat = [column; 4];
        transpose(&mut mat);

        mix_columns(&mut mat);
        
        let expected = [[4;4], [102;4], [129;4], [229;4]];
        assert_eq!(expected, mat);
    }
}
