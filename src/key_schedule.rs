use crate::{BYTES_PER_ROW, utils::S_BOX};

const R_CON: [u8;10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];


pub trait KeySchedule {
    // TODO: make key size variable
    fn key_schedule(key: &[u8; 16]) -> Vec<[[u8; BYTES_PER_ROW]; BYTES_PER_ROW]>;

    // Add col2 values to col1
    fn add_to_column(col1: &mut [u8; BYTES_PER_ROW], col2: &[u8; BYTES_PER_ROW]) {
        for i in 0..col1.len() {
            col1[i] ^= col2[i];
        }
    }

    fn rot_word(column: &mut [u8; BYTES_PER_ROW]) {
        column.rotate_left(1);
    }

    // Substitute bytes in a word using S-box
    fn sub_word(column: &mut [u8; BYTES_PER_ROW]) {
        let s_box = S_BOX;
        for c in column {
            *c = s_box[*c as usize];
        }
    }

    // Add to first value a specific number (following the specification)
    fn r_con(column: &mut [u8; BYTES_PER_ROW], round: usize) {
        column[0] ^= match R_CON.get(round-1) {
            Some(v) => v,
            None => panic!("This round is not defined!")
        };
    }
}


#[cfg(test)]
mod tests {
    use crate::BYTES_PER_ROW;
    use super::KeySchedule;

    // Create empty struct with default Trait implementation
    struct Test;
    impl KeySchedule for Test {
        fn key_schedule(_key: &[u8; 16]) -> Vec<[[u8; BYTES_PER_ROW]; BYTES_PER_ROW]> {
            Vec::new()
        }
    }

    #[test]
    fn test_rot_word() {
        let mut word = [42, 182, 254, 92];
        Test::rot_word(&mut word);
        let expected = [182, 254, 92, 42];

        assert_eq!(expected, word);
    }
}
