extern crate ripemd160;
extern crate base58;

use ripemd160::{Digest, Ripemd160};
use base58::{ToBase58};

extern crate curv;

use curv::elliptic::curves::traits::*;

use crate::computation::crypto::ecdsa::{EcdsaKey, EcdsaSign};
extern crate hex;

pub fn get_public_key(ecdsa_key: &EcdsaKey) -> String {
    let key = ecdsa_key.shared_key.y.get_element();
    let key_u8arr = key.serialize();

    let mut hasher = Ripemd160::new();
    hasher.input(&key_u8arr.as_ref());
    let checksum = hasher.result();

    let key_checksum_vec = [&key_u8arr.as_ref(), &checksum[0..4]].concat();

    let eos_publickey = "EOS".to_string() + &key_checksum_vec.to_base58();
    
    eos_publickey
}

pub fn get_signed_msg(ecdsa_sig: &EcdsaSign) -> String {
    let r = &((&ecdsa_sig.signature.r.get_element())[..]);
    let s = &((&ecdsa_sig.signature.s.get_element())[..]);

    let rs_vec = [r, s].concat();

    let mut recover_id = 1; // 0~3
    recover_id += 4 + 27; // 31~34

    let mut rsi_vec: Vec<u8> = Vec::new();
    rsi_vec.push(recover_id);
    rsi_vec.extend_from_slice(&rs_vec[..]);

    let rsi_arr = &(rsi_vec.clone())[..];

    rsi_vec.extend_from_slice("K1".as_bytes());

    let mut hasher = Ripemd160::new();
    hasher.input(&rsi_vec[..].as_ref());
    let checksum = hasher.result();

    let rsi_checksum_vec = [&rsi_arr, &checksum[0..4]].concat();

    let signed_msg = "SIG_K1_".to_string() + &rsi_checksum_vec.to_base58();

    signed_msg
}