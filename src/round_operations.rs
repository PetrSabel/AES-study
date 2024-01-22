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
    // Temporally store keys by-columns
    transpose(&mut first_key);
    let mut generated_keys = [first_key; KEYS_NUMBER];
    // Leave first key untouched
    for i in 1..generated_keys.len() {
        let last_key = generated_keys[i-1];
        let mut new_key = last_key.clone();
        let last_column = &mut last_key[3].clone();
        rot_word(last_column);
        sub_word(last_column);
        r_con(last_column, i);
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

fn encrypt_block(block: [u8; 16], key: [u8; 16]) -> [u8; 16] {
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
    use super::{encrypt_block, shift_rows};

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
    fn test_encrypt_block() {
        let block = [0xff; 16];
        let result = encrypt_block(block, block.clone());
        println!("{:x?}", result);
    }
}
