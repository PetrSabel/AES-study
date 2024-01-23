use crate::{utils::{gf_multiplication, transpose, S_BOX}, BYTES_PER_ROW};


pub trait Round {
    // Substitute bytes method
    fn substitute_bytes(state: &mut [[u8; BYTES_PER_ROW]; BYTES_PER_ROW]) {
        let s_box = S_BOX;
        for i in 0..BYTES_PER_ROW {
            for j in 0..BYTES_PER_ROW {
                state[i][j] = s_box[state[i][j] as usize];
            }
        }
    }

    fn shift_rows(state: &mut [[u8; BYTES_PER_ROW]; BYTES_PER_ROW]) {
        for i in 0..state[0].len() {
            state[i].rotate_left(i);
        }
    }

    // Optional method, used to implement mix_columns
    fn mix_column(column: &mut [u8; BYTES_PER_ROW]) {
        // Perform explicit matrix multiplication
        let mut temp = [0; BYTES_PER_ROW];
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

    fn mix_columns(state: &mut [[u8; BYTES_PER_ROW]; BYTES_PER_ROW]) {
        transpose(state);
        for i in 0..BYTES_PER_ROW {
            Self::mix_column(&mut state[i]);
        }
        transpose(state);
    }

    // Add current round key to the state
    fn add_round_key(state: &mut [[u8; BYTES_PER_ROW]; BYTES_PER_ROW],
                    keys: &Vec<[[u8; BYTES_PER_ROW]; BYTES_PER_ROW]>, round: usize) {
        for i in 0..BYTES_PER_ROW {
            for j in 0..BYTES_PER_ROW {
                state[i][j] ^= keys[round][i][j];
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use crate::utils::transpose;
    use super::Round;

    // Define empty struct with default Trait methods
    struct Test;
    impl Round for Test {}

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

        Test::shift_rows(&mut rows);
        assert_eq!(rows, shifted_rows);
    }

    #[test]
    fn test_mix_column() {
        let mut column = [0xd4, 0xbf, 0x5d, 0x30];
        Test::mix_column(&mut column);

        let expected = [4, 102, 129, 229];
        assert_eq!(column, expected);
    }

    #[test]
    fn test_mix_columns() {
        let column = [0xd4, 0xbf, 0x5d, 0x30];
        let mut mat = [column; 4];
        transpose(&mut mat);

        Test::mix_columns(&mut mat);
        
        let expected = [[4;4], [102;4], [129;4], [229;4]];
        assert_eq!(expected, mat);
    }
}
