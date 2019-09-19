#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;
//extern crate subtle;

pub mod computation;
pub mod network;
pub mod blockchain;
pub mod wrap;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    BadRequest,
}

#[derive(Copy, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub enum CryptoType {
    ECDSA,
    EDDSA,
    Schnorr,
}