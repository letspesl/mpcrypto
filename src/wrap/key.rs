use crate::computation::crypto::traits::Key;
use crate::computation::crypto::ecdsa::EcdsaKey;
use crate::blockchain::*;
use crate::CryptoType;

#[derive(Serialize, Deserialize)]
pub struct KeyGenerateInput {
    pub crypto_type: CryptoType,
    pub parties: Vec<String>,
    pub share_count: usize,
    pub threshold: usize
}

// #[derive(Serialize, Deserialize)]
// pub struct KeyGenerateOutput {
//     pub key: String
// }

pub fn generate_key(input_str: &str) -> String {
    let input: KeyGenerateInput = serde_json::from_str(input_str).unwrap();
    
    match input.crypto_type {
        CryptoType::ECDSA => {
            let ecdsa_key: EcdsaKey = Key::new(
                input.parties, 
                input.share_count, 
                input.threshold
            );
            let public_key = eos::get_public_key(&ecdsa_key);
            println!("generate_key: {:?}", public_key);
            ecdsa_key.to_string()
        },
        CryptoType::EDDSA => {
            // let eddsa_key: EddsaKey = Key::new(
            //     input.parties, 
            //     input.share_count, 
            //     input.threshold
            // );
            // eddsa_key.to_string()
            String::new()
        },
        CryptoType::Schnorr => {
            // let schnorr_key: SchnorrKey = Key::new(
            //     input.parties, 
            //     input.share_count, 
            //     input.threshold
            // );
            // schnorr_key.to_string()
            String::new()
        }
    }
}

pub fn backup_key() {
    
}

pub fn recover_key() {
    
}