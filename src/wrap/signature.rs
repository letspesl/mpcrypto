use crate::computation::crypto::traits::Sign;
use crate::computation::crypto::ecdsa::{EcdsaKey, EcdsaSign};
use crate::blockchain::*;
use crate::CryptoType;

#[derive(Serialize, Deserialize)]
pub struct SignGenerateInput {
    pub crypto_type: CryptoType,
    pub key_str: String,
    pub message: String,
    pub parties: Vec<String>,
    pub threshold: usize
}

// #[derive(Serialize, Deserialize)]
// pub struct SignGenerateOutput {
//     pub sign: String
// }

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
            let signed_msg = eos::get_signed_msg(&ecdsa_sign);
            println!("generate_sign: {:?}", signed_msg);
            ecdsa_sign.to_string()
        },
        CryptoType::EDDSA => {
            // let key: EddsaKey = serde_json::from_str(&input.key_str).unwrap();
            // let eddsa_sign: EddsaSign = Sign::new(
            //     key,
            //     input.message,
            //     input.parties, 
            //     input.threshold
            // );
            String::new()
        },
        CryptoType::Schnorr => {
            // let key: SchnorrKey = serde_json::from_str(&input.key_str).unwrap();
            // let schnorr_sign: SchnorrSign = Sign::new(
            //     key,
            //     input.message,
            //     input.parties, 
            //     input.threshold
            // );
            String::new()
        }
    }
}