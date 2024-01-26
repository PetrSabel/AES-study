use std::io::{Error, Read};
use std::{fs::File, vec};
use std::fmt::Write;
use std::fs::OpenOptions;

use crate::{AESError, BLOCK_SIZE, BYTES_PER_ROW};

const IRREDUCIBLE_POLY: u8 = 0x1B;
pub const S_BOX: [u8;256] = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 
                        202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 
                        183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 
                        199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 
                        26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 
                        252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 
                        51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 
                        245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 
                        196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 
                        238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 
                        98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 
                        234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 
                        75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 
                        193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 
                        85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22];

pub const INVERSE_S_BOX: [u8;256] = [82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 
                                124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 
                                84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 
                                46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37, 114, 
                                248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, 
                                108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132, 
                                144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6, 208, 
                                44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107, 58, 145, 
                                17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115, 150, 
                                172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110, 71, 
                                241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, 252, 
                                86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244, 31, 
                                221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 
                                127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 
                                59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 
                                126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125];


// Note: not sure how to test these functions
// This function reads chunks from the given file
pub(crate) fn read_from_file(filename: &str) -> Result<Vec<u8>, Error> {
    let mut f = File::open(filename)?;
    let mut result = Vec::new();
    f.read_to_end(&mut result)?;

    Ok(result)
}

// Write data (crypted) in the given file
pub(crate) fn write_to_file(filename: &str, data: &Vec<u8>) -> Result<(),Error> {
    let mut f = OpenOptions::new()
            .truncate(true)
            .write(true)
            .create(true)
            .open(filename)?;

    std::io::Write::write_all(&mut f, data)?;
    Ok(())
}

pub fn encode(bytes: Vec<u8>) -> String {
    let mut s: String = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }

    s
}

pub fn decode(s: &str) -> Result<Vec<u8>, AESError> {
    let mut result = Vec::new();

    for i in (0..s.len()).step_by(2) {
        result.push(u8::from_str_radix(&s[i..i + 2], 16)
                    .ok().ok_or(AESError::TryDecodeNotHEXString(s.to_string()))?);
    }
    
    Ok(result)
}

pub fn add_iv(block: &[u8;BLOCK_SIZE], iv: &[u8;BLOCK_SIZE]) -> [u8;BLOCK_SIZE] {
    let mut result = [0; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        result[i] = block[i] ^ iv[i];
    }

    result
}

pub fn padding(data: &Vec<u8>) -> Vec<u8> {
    let len = data.len();
    let padding_len = BLOCK_SIZE - (len % BLOCK_SIZE);
    // Padding length is between 0 and 16, so u8 is enough
    let mut padding = vec![padding_len as u8; padding_len];
    let mut result = data.clone();
    result.append(&mut padding);

    result
}

pub fn unpadding(data: &Vec<u8>) -> Result<Vec<u8>, AESError> {
    let padding = data[data.len()-1]; // Take last byte to understand the padding length
    if padding as usize > BLOCK_SIZE {
        return Err(AESError::WrongPaddingValue(BLOCK_SIZE as u8, padding));
    }
    let mut result = data.clone();
    for i in 0..(padding as usize) {
        let tmp = result.pop().ok_or(AESError::WrongPaddingLength(i+1, padding as usize))?;
        if tmp != padding {
            return Err(AESError::WrongPaddingValue(tmp, padding));
        }
    }

    Ok(result)
}

pub fn split_in_blocks(data: &Vec<u8>) -> Result<Vec<[u8;BLOCK_SIZE]>, AESError> {
    if data.len() % BLOCK_SIZE != 0 {
        dbg!(format!("String must be clearly divisible in blocks of {} size. 
                    Consider to use first padding method.", BLOCK_SIZE));
        return Err(AESError::DataNotDivisibleInBlocks(data.len(), BLOCK_SIZE));
    }

    // At this point data should be separable in chunks
    let chunks: Vec<[u8; 16]> = data.chunks(16)
            .map(|c| c.try_into().unwrap()).collect();

    Ok(chunks)
}

pub fn unite_blocks(data: &Vec<[u8;16]>) -> Vec<u8> {
    data.clone().into_iter().flatten().collect()
}

fn rotl8(x: u8, mut shift: u32) -> u8 {
    shift %= 8;
    x.rotate_left(shift)
}

pub fn compute_s_box() -> [u8;256] {
    let mut p: u8 = 1;
    let mut q: u8 = 1;
    let mut sbox: [u8; 256] = [0; 256];

    /* loop invariant: p * q == 1 in the Galois field */
    // q is the multiplication inverse of p
    loop {
        /* multiply p by 3 */
        // p + (2*p) but if it will overflow, we substract (same as add the irreducible polynomial)
		p = p ^ (p << 1) ^ (if (p & 0x80) != 0 { IRREDUCIBLE_POLY } else { 0 });

        /* divide q by 3 (equals multiplication by 0xf6) */
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= if q & 0x80 != 0 { 0x09 } else { 0 };

        // Compute the affine transformation using given formula
        let xformed: u8 = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);
        // 0x63 is a part of transformation
		sbox[p as usize] = xformed ^ 0x63;

        // When we finish all numbers, exit
        if p == 1 {
            break
        }
    }

    /* 0 is a special case since it has no inverse */
	sbox[0] = 0x63;

    sbox 
}

// TODO: use some method
pub fn compute_inverse_s_box() -> [u8;256] {
    let s_box = S_BOX;
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
            a ^= IRREDUCIBLE_POLY;  // we don't add 0x11b because it two bytes word (exploit the oveflow of u8)
        }

        b >>= 1;
    }

    result
}

// Swap columns with rows
pub(crate) fn transpose(matrix: &mut [[u8; BYTES_PER_ROW]; BYTES_PER_ROW]) {
    // Assume matrix is square
    for i in 0..matrix.len() {
        for j in 0..i {
            let tmp = matrix[i][j];
            matrix[i][j] = matrix[j][i];
            matrix[j][i] = tmp;
        }
    }
}

// Transform 16-byte array into 4x4 bytes matrix
pub(crate) fn array_to_matrix(arr: &[u8; 16]) -> [[u8; BYTES_PER_ROW]; BYTES_PER_ROW] {
    let mut result = [[0; BYTES_PER_ROW]; BYTES_PER_ROW];
    for i in 0..arr.len() {
        result[i%BYTES_PER_ROW][i/BYTES_PER_ROW] = arr[i];
    }
    result
}

// Transform 4x4 bytes matrix into 16-byte array
pub(crate) fn matrix_to_array(matrix: &[[u8; BYTES_PER_ROW]; BYTES_PER_ROW]) -> [u8; 16] {
    let mut result = [0; 16];

    let mut tmp = matrix.clone();
    transpose(&mut tmp);
    for (i, m) in tmp.into_iter().flatten().enumerate() {
        result[i] = m;
    }
    result
}



#[cfg(test)]
mod tests {
    use crate::{utils::{add_iv, decode, encode, gf_multiplication, matrix_to_array, rotl8, transpose, INVERSE_S_BOX}, BLOCK_SIZE};

    use super::{array_to_matrix, compute_inverse_s_box, compute_s_box, padding, unite_blocks, unpadding, S_BOX};

    #[test]
    fn test_encode() {
        let bytes = vec![0x01, 0x10, 0xff];
        assert_eq!(encode(bytes), "0110ff");
    }

    #[test]
    fn test_decode() {
        let bytes = vec![0x01, 0x10, 0xff];
        assert_eq!(bytes, decode("0110ff").unwrap());
    }

    #[test]
    fn test_padding() {
        for i in 1..17 {
            let data = vec![0; i];
            let result = padding(&data);

            for p in result[i..].iter() {
                assert_eq!(*p, (16-i%16) as u8);
            }
        }
    }

    #[test]
    fn test_unpadding() {
        for i in 1..17 {
            let mut data = vec![0xab;i];
            let expected = data.clone();
            data.append(&mut vec![(16-i%16) as u8; 16-i%16]);
            let unpadded = unpadding(&data).unwrap();

            assert_eq!(expected, unpadded);
        }
    }

    #[test]
    fn test_padding_unpadding() {
        for i in 1..17 {
            let data = vec![0; i];
            let result = padding(&data);

            let unpadded = unpadding(&result).unwrap();
            assert_eq!(unpadded, data);
        }
    }

    #[test]
    fn test_unite_blocks() {
        let v = vec![[0xff;16], [0xaa;16], [0x12;16]];
        let result = unite_blocks(&v);

        let mut expected = vec![0xff;16];
        expected.append(&mut vec![0xaa;16]);
        expected.append(&mut vec![0x12;16]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_rotl8() {
        let test = 8;
        let result = rotl8(test, 4);
        assert_eq!(result, 128);

        // Circular
        let test = 0xfe;
        let result = rotl8(test, 4);
        assert_eq!(result, 0xef);
    }

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
        let first_row:[u8;16] = [0x52, 0x9, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 
                                0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb];
        assert_eq!(&inverse_s_box[..16], &first_row);
    }

    #[test]
    fn test_s_box_and_inverse() {
        for i in 0..256 {
            let s = S_BOX[i];
            let reversed = INVERSE_S_BOX[s as usize];
            assert_eq!(i as u8, reversed);
        }
    }

    #[test]
    fn test_array_to_matrix() {
        let array = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let matrix = [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]];
        assert_eq!(array_to_matrix(&array), matrix);
    }

    #[test]
    fn test_matrix_to_array() {
        let array = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let matrix = [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]];
        assert_eq!(matrix_to_array(&matrix), array);
    }

    #[test]
    fn test_gf_multiplication() {
        let a = 0xd4;
        let b = 0x02;
        assert_eq!(0xb3, gf_multiplication(a, b));
        assert_eq!(a, gf_multiplication(a, 0x1));
    }

    #[test]
    fn test_add_iv() {
        let a = [0xd4;BLOCK_SIZE];
        let b = [0x02;BLOCK_SIZE];

        let result = add_iv(&a, &b);
        assert_eq!(result, [0xd6;BLOCK_SIZE]);
    }

    #[test]
    fn test_transpose() {
        let mut mat = [[0,1,2,3],[4,5,6,7],[8,9,10,11],[12,13,14,15]];
        let expected = [[0,4,8,12],[1,5,9,13],[2,6,10,14],[3,7,11,15]];

        transpose(&mut mat);
        assert_eq!(expected, mat);
    }
}
