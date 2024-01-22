fn rotl8(x: u8, mut shift: u32) -> u8 {
    shift %= 8;
    x.rotate_left(shift)
}

pub(crate) fn compute_s_box() -> [u8;256] {
    let mut p: u8 = 1;
    let mut q: u8 = 1;
    let mut sbox: [u8; 256] = [0; 256];

    /* loop invariant: p * q == 1 in the Galois field */
    loop {
        // TODO: multiply normally maybe
        /* multiply p by 3 */
		p = p ^ (p << 1) ^ (if (p & 0x80) != 0 { 0x1B } else { 0 });

        /* divide q by 3 (equals multiplication by 0xf6) */
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= if q & 0x80 != 0 { 0x09 } else { 0 };

        let xformed: u8 = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);

		sbox[p as usize] = xformed ^ 0x63;

        if p == 1 {
            break
        }
    }

    /* 0 is a special case since it has no inverse */
	sbox[0] = 0x63;

    sbox 
}

fn compute_inverse_s_box() -> [u8;256] {
    let s_box = compute_s_box();
    let mut inverse_s_box = [0; 256];

    // Just swap index with value taken from original s_box
    for (i, v) in s_box.into_iter().enumerate() {
        inverse_s_box[v as usize] = i as u8;
    }

    inverse_s_box 
}

// Logarithmic approach for multiplication in GF(256) field
pub(crate) fn gf_multiplication(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0;
    let mut shift_greater_than255;

    // Look at each bit of 'b'
    for _ in 0..8 {
        if b & 1 > 0 {
            result ^= a; // adding 'a'
        }

        shift_greater_than255 = a & 0x80;
        a <<= 1; // double 'a' but check if it is still in the field

        if shift_greater_than255 > 0 {
            a ^= 0x1b;
        }

        b >>= 1;
    }

    result
}

pub(crate) fn rot_word(column: &mut [u8; 4]) {
    column.rotate_left(1);
}

// TODO: use predefined s_box
pub(crate) fn sub_word(column: &mut [u8; 4]) {
    let s_box = compute_s_box();
    for c in column {
        *c = s_box[*c as usize];
    }
}

pub(crate) fn r_con(column: &mut [u8; 4], round: usize) {
    // TODO: use pow of 2
    column[0] ^= match round {
        1 => 0x01,
        2 => 0x02,
        3 => 0x04,
        4 => 0x08,
        5 => 0x10,
        6 => 0x20,
        7 => 0x40,
        8 => 0x80,
        9 => 0x1b,
        10 => 0x36,
        _ => panic!("This round is not defined!")
    };
}

pub(crate) fn transpose(matrix: &mut [[u8; 4]; 4]) {
    let tmp = matrix.clone();
    for i in 0..matrix.len() {
        for j in 0..matrix[0].len() {
            matrix[i][j] = tmp[j][i];
        }
    }
}

pub(crate) fn array_into_matrix(arr: [u8; 16]) -> [[u8; 4]; 4] {
    let mut result = [[0; 4]; 4];
    for i in 0..arr.len() {
        result[i%4][i/4] = arr[i];
    }
    result
}

pub(crate) fn matrix_to_array(mut matrix: [[u8; 4]; 4]) -> [u8; 16] {
    let mut result = [0; 16];

    transpose(&mut matrix);
    for (i, m) in matrix.into_iter().flatten().enumerate() {
        result[i] = m;
    }
    result
}

pub(crate) fn add_to_column(col1: &mut [u8; 4], col2: &[u8; 4]) {
    for i in 0..col1.len() {
        col1[i] ^= col2[i];
    }
}


#[cfg(test)]
mod tests {
    use crate::utils::gf_multiplication;

    use super::{array_into_matrix, compute_inverse_s_box, compute_s_box, rot_word};

    #[test]
    fn test_s_box() {
        let s_box = compute_s_box();
        let first_row:[u8;16] = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 
                                0x30, 0x1, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76];
        assert_eq!(&s_box[..16], &first_row);
    }

    #[test]
    fn test_inverse_s_box() {
        let inverse_s_box = compute_inverse_s_box();
        // println!("{:x?}", &inverse_s_box[..16]);
        let first_row:[u8;16] = [0x52, 0x9, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 
                                0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb];
        assert_eq!(&inverse_s_box[..16], &first_row);
    }

    #[test]
    fn test_array_into_matrix() {
        let array = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let matrix = [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]];
        assert_eq!(array_into_matrix(array), matrix);
    }

    #[test]
    fn test_gf_multiplication() {
        let a = 0xd4;
        let b = 0x02;
        assert_eq!(0xb3, gf_multiplication(a, b));
        assert_eq!(a, gf_multiplication(a, 0x1));
    }

    #[test]
    fn test_rot_word() {
        let mut word = [42, 182, 254, 92];
        rot_word(&mut word);
        let expected = [182, 254, 92, 42];

        assert_eq!(expected, word);
    }
}
