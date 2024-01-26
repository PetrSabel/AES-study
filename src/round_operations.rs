use crate::{utils::{gf_multiplication, transpose, INVERSE_S_BOX, S_BOX}, BYTES_PER_ROW};


pub trait Round {
    // Substitute bytes method
    fn substitute_bytes(state: &mut [[u8; BYTES_PER_ROW]; BYTES_PER_ROW], inverse: bool) {
        let s_box = if inverse { INVERSE_S_BOX } else { S_BOX };
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

    fn inverse_shift_rows(state: &mut [[u8; BYTES_PER_ROW]; BYTES_PER_ROW]) {
        for i in 0..state[0].len() {
            state[i].rotate_right(i);
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

    // Optional method, used to implement inverse_mix_columns
    fn inverse_mix_column(column: &mut [u8; BYTES_PER_ROW]) {
        // Perform explicit matrix multiplication
        let mut temp = [0; BYTES_PER_ROW];
        temp[0] = gf_multiplication(0x0e, column[0]) ^ gf_multiplication(0x0b, column[1])
                ^ gf_multiplication(0x0d, column[2]) ^ gf_multiplication(0x09, column[3]);

        temp[1] = gf_multiplication(0x09, column[0]) ^ gf_multiplication(0x0e, column[1])
                ^ gf_multiplication(0x0b, column[2]) ^ gf_multiplication(0x0d, column[3]);

        temp[2] = gf_multiplication(0x0d, column[0]) ^ gf_multiplication(0x09, column[1])
                ^ gf_multiplication(0x0e, column[2]) ^ gf_multiplication(0x0b, column[3]);

        temp[3] = gf_multiplication(0x0b, column[0]) ^ gf_multiplication(0x0d, column[1])
                ^ gf_multiplication(0x09, column[2]) ^ gf_multiplication(0x0e, column[3]);

        *column = temp;
    }

    fn inverse_mix_columns(state: &mut [[u8; BYTES_PER_ROW]; BYTES_PER_ROW]) {
        transpose(state);
        for i in 0..BYTES_PER_ROW {
            Self::inverse_mix_column(&mut state[i]);
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
    fn test_substitute_and_reverse() {
        let mut rows: [[u8; 4]; 4] = [[0, 1, 2, 3],
                                    [4, 5, 6, 7],
                                    [8, 9, 10, 11],
                                    [12, 13, 14, 15]];
        let expected = rows.clone();

        Test::substitute_bytes(&mut rows, false);
        Test::substitute_bytes(&mut rows, true);

        assert_eq!(rows, expected);
    }

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
    fn test_inverse_shift_rows() {

        let rows: [[u8; 4]; 4] = [[0, 1, 2, 3],
                                    [4, 5, 6, 7],
                                    [8, 9, 10, 11],
                                    [12, 13, 14, 15]];
        let mut shifted_rows: [[u8; 4]; 4] = [[0, 1, 2, 3],
                                        [5, 6, 7, 4],
                                        [10, 11, 8, 9],
                                        [15, 12, 13, 14]];

        Test::inverse_shift_rows(&mut shifted_rows);
        assert_eq!(rows, shifted_rows);
    }

    #[test]
    fn test_shift_rows_and_reverse() {

        let mut rows: [[u8; 4]; 4] = [[0, 1, 2, 3],
                                    [4, 5, 6, 7],
                                    [8, 9, 10, 11],
                                    [12, 13, 14, 15]];
        let expected = rows.clone();

        Test::shift_rows(&mut rows);
        Test::inverse_shift_rows(&mut rows);

        assert_eq!(rows, expected);
    }

    #[test]
    fn test_mix_column() {
        let mut column = [0xd4, 0xbf, 0x5d, 0x30];
        Test::mix_column(&mut column);

        let expected = [4, 102, 129, 229];
        assert_eq!(column, expected);
    }

    #[test]
    fn test_inverse_mix_column() {
        let column = [0xd4, 0xbf, 0x5d, 0x30];
        let mut expected = [4, 102, 129, 229];
        
        Test::inverse_mix_column(&mut expected);

        assert_eq!(column, expected);
    }

    #[test]
    fn test_mix_column_and_reverse() {
        let mut column = [0xd4, 0xbf, 0x5d, 0x30];
        let expected = column.clone();
        
        Test::mix_column(&mut column);
        Test::inverse_mix_column(&mut column);

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

    #[test]
    fn test_inverse_mix_columns() {
        let column = [[0xd4;4], [0xbf;4], [0x5d;4], [0x30;4]];
        let expected = [4, 102, 129, 229];
        let mut mat = [expected; 4];
        transpose(&mut mat);

        Test::inverse_mix_columns(&mut mat);
        
        assert_eq!(column, mat);
    }

    #[test]
    fn test_mix_columns_and_reverse() {
        let column = [0xd4, 0xbf, 0x5d, 0x30];
        let expected = column.clone();

        let mut mat = [column; 4];
        transpose(&mut mat);

        Test::mix_columns(&mut mat);
        Test::inverse_mix_columns(&mut mat);
        transpose(&mut mat);

        assert_eq!(expected, mat[0]);
    }

    #[test]
    fn test_add_round_key() {
        let mut state = [[0xd4, 0xbf, 0x5d, 0x30]; 4];
        let key = [[0x1, 0x3, 0xd, 0xf]; 4];

        Test::add_round_key(&mut state, &vec![key], 0);

        let expected = [[0xd5, 0xbc, 0x50, 0x3f]; 4];
        assert_eq!(state, expected);
    }
}
