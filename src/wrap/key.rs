use crate::computation::crypto::traits::Key;
use crate::computation::crypto::ecdsa::EcdsaKey;
use crate::blockchain::*;
use crate::CryptoType;
use crate::ChainType;

#[derive(Serialize, Deserialize)]
pub struct KeyGenerateInput {
    pub crypto_type: CryptoType,
    pub chain_type: ChainType,
    pub parties: Vec<String>,
    pub share_count: usize,
    pub threshold: usize
}

#[derive(Serialize, Deserialize)]
pub struct KeyGenerateOutput {
    pub public_key: String,
    pub shares: String
}

pub fn generate_key(input_str: &str) -> String {
    let input: KeyGenerateInput = serde_json::from_str(input_str).unwrap();
    
    match input.crypto_type {
        CryptoType::ECDSA => {
            let ecdsa_key: EcdsaKey = Key::new(
                input.parties, 
                input.share_count, 
                input.threshold
            );
            
            let public_key = match input.chain_type {
                ChainType::EOS => eos::get_public_key(&ecdsa_key),
                ChainType::ETH => String::new(),
                ChainType::BTC => String::new()
            };
            
            let output = KeyGenerateOutput {
                public_key: public_key,
                shares: ecdsa_key.to_string()
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

pub fn backup_key() {
    
}

pub fn recover_key() {
    
}