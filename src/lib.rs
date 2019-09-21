#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

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

#[derive(Copy, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub enum ChainType {
    EOS,
    ETH,
    BTC,
}