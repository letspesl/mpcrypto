use crate::computation::crypto::traits::Sign;
use crate::computation::crypto::ecdsa::{EcdsaKey, EcdsaSign};
use crate::blockchain::*;
use crate::CryptoType;
use crate::ChainType;

#[derive(Serialize, Deserialize)]
pub struct SignGenerateInput {
    pub crypto_type: CryptoType,
    pub chain_type: ChainType,
    pub key_str: String,
    pub message: String,
    pub parties: Vec<String>,
    pub threshold: usize
}

#[derive(Serialize, Deserialize)]
pub struct SignGenerateOutput {
    pub sign: String,
    pub sign_hex: String
}

pub fn generate_sign(input_str: &str) -> String {
    let input: SignGenerateInput = serde_json::from_str(input_str).unwrap();
    
    match input.crypto_type {
        CryptoType::ECDSA => {
            let key: EcdsaKey = serde_json::from_str(&input.key_str).unwrap();
            let ecdsa_sign: EcdsaSign = Sign::new(
                &key,
                &input.message,
                input.parties, 
                input.threshold
            );

            let sign = match input.chain_type {
                ChainType::EOS => eos::get_signed_msg(&ecdsa_sign),
                ChainType::ETH => String::new(),
                ChainType::BTC => String::new()
            };
            
            let output = SignGenerateOutput {
                sign: sign,
                sign_hex: ecdsa_sign.to_string()
            };

            serde_json::to_string(&output).unwrap()
        },
        CryptoType::EDDSA => {
            String::new()
        },
        CryptoType::Schnorr => {
            String::new()
        }
    }
}