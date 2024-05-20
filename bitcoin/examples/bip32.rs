// extern crate bitcoin_arch_v2 as bitcoin;

use std::str::FromStr;
use std::{env, process};

use bitcoin::address::{Address, KnownHrp};
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::hex::FromHex;
use bitcoin::{CompressedPublicKey, NetworkKind};

fn main() {
    // This example derives root xprv from a 32-byte seed,
    // derives the child xprv with path m/84h/0h/0h,
    // prints out corresponding xpub,
    // calculates and prints out the first receiving segwit address.
    // Run this example with cargo and seed(hex-encoded) argument:
    // cargo run --example bip32 7934c09359b234e076b9fa5a1abfd38e3dc2a9939745b7cc3c22a48d831d14bd

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "not enough arguments. usage: {} <hex-encoded 32-byte seed>",
            &args[0]
        );
        process::exit(1);
    }

    let seed_hex = &args[1];
    println!("Seed: {}", seed_hex);
    println!("Using mainnet network");

    let seed = Vec::from_hex(seed_hex).unwrap();

    // calculate root key from seed
    let root = Xpriv::new_master(NetworkKind::Main, &seed).unwrap();
    println!("Root key: {}", root);

    // derive child xpub
    let path = DerivationPath::from_str("84h/0h/0h").unwrap();
    let child = root.derive_priv(&path).unwrap();
    println!("Child at {}: {}", path, child);
    let xpub = Xpub::from_priv(&child);
    println!("Public key at {}: {}", path, xpub);

    // generate first receiving address at m/0/0
    // manually creating indexes this time
    let zero = ChildNumber::from_normal_idx(0).unwrap();
    let public_key = xpub.derive_pub(&[zero, zero]).unwrap().public_key;
    let address = Address::p2wpkh(&CompressedPublicKey(public_key.inner), KnownHrp::Mainnet);
    println!("First receiving address: {}", address);
}
