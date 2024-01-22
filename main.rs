use aes::encrypt_block;

fn main() {
    let block = [0xff; 16];
    println!("{:x?}", encrypt_block(block, block.clone()));
}