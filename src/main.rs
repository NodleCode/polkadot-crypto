// Copyright 2019-2020 @polkadot/wasm-crypto authors & contributors
// This software may be modified and distributed under the terms
// of the Apache-2.0 license. See the LICENSE file for details.

use hex_literal::hex;

pub mod bip39;
pub mod ed25519;
pub mod hashing;
pub mod sr25519;

fn print_test_vector(payload: &[u8]) {
    let mnemonic_phrase = bip39::ext_bip39_generate(12);
    let seed = bip39::ext_bip39_to_mini_secret(&mnemonic_phrase, "");

    println!("{:#?}", seed);
}

fn main() {
    let test_vectors: Vec<&[u8]> = vec![
        &hex!("00"),
        &hex!("01"),
        &hex!("10"),
        &hex!("0729879a"),
        &hex!("78"),
        &hex!("54657374"),
        &hex!("6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"),
        &hex!("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60"),
        &hex!("ffffffffffffffffffffffffffffffff"),
        &hex!("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60"),
    ];
    test_vectors
        .iter()
        .for_each(|test_vector| print_test_vector(&test_vector[..]));
}
