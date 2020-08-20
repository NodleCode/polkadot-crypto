// Copyright 2019-2020 @polkadot/wasm-crypto authors & contributors
// This software may be modified and distributed under the terms
// of the Apache-2.0 license. See the LICENSE file for details.

use hex::encode as hex_encode;
use hex_literal::hex as hex_decode;

pub mod bip39;
pub mod ed25519;
pub mod hashing;
pub mod sr25519;

fn print_test_vector(payload: &[u8]) {
    let mnemonic_phrase = bip39::ext_bip39_generate(12);
    let seed = bip39::ext_bip39_to_mini_secret(&mnemonic_phrase, "");
    let keypair = ed25519::ext_ed_from_seed(&seed);
    let private = &keypair[0..32];
    let public = &keypair[32..keypair.len()];
    let hash = hashing::ext_blake2b(payload, &[], 32);
    let signature = ed25519::ext_ed_sign(public, private, &hash);

    println!(
        "{}, {}, {}, {}, {}",
        hex_encode(public),
        hex_encode(private),
        hex_encode(payload),
        hex_encode(hash),
        hex_encode(signature)
    );
}

fn main() {
    println!("Hex Encoded Signer Public Key, Hex Encoded Signer Private Key, Hex Encoded Payload, Hex Encoded Hash, Hex Encoded Signature");

    let test_vectors: Vec<&[u8]> = vec![
        &hex_decode!("00"),
        &hex_decode!("01"),
        &hex_decode!("10"),
        &hex_decode!("0729879a"),
        &hex_decode!("78"),
        &hex_decode!("54657374"),
        &hex_decode!("6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"),
        &hex_decode!("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60"),
        &hex_decode!("ffffffffffffffffffffffffffffffff"),
        &hex_decode!("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60"),
    ];
    test_vectors
        .iter()
        .for_each(|test_vector| print_test_vector(&test_vector[..]));
}
