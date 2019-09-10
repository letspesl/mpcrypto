extern crate multi_party_ecdsa;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::*;

extern crate curv;
extern crate paillier;

use paillier::EncryptionKey;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;

////////////////////////////////////////////////////////////////////////////
// commit message aes encryption
extern crate rust_crypto;
use rust_crypto::aead::AeadEncryptor;
use rust_crypto::aead::AeadDecryptor;
use rust_crypto::aes::KeySize::KeySize256;
use rust_crypto::aes_gcm::AesGcm;
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

use curv::BigInt;
use curv::{FE, GE};
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;

use curv::arithmetic::traits::Converter; // BigInt::to_vec
use curv::elliptic::curves::traits::*;  //ECPoint.x_coor()

use std::iter::repeat;

////////////////////////////////////////////////////////////////////////////

use crate::network::traits::*;
use crate::network::c2s::*;
use super::traits::{Key, Sign};

#[derive(Serialize, Deserialize)]
pub struct EcdsaKey {
    pub party_key: Keys,
    pub shared_key: SharedKeys,
    pub vss_scheme_vec: Vec<VerifiableSS>,
    pub paillier_key_vec: Vec<EncryptionKey>
}

impl EcdsaKey {
    pub fn execute<T>(net: &T, params: &Parameters) -> EcdsaKey 
    where
        T: Net,
    {
        // round 1
        let party_num_int = net.get_info().client_id.clone() as usize;
        let party_key = Keys::create(party_num_int);
        let (bc_i, decom_i) = party_key.phase1_broadcast_phase3_proof_of_correct_key();
        
        assert!(net.send(SendType::Broadcast, "set", "round1", &bc_i).is_ok());
        let round1_ans_vec: Vec<String> = net.receive(ReceiveType::PollBroadcast, "get", "round1").unwrap();

        ////////////////////////////////////////////////////////////////////////////
        // round 2
        let mut j = 0;
        let bc1_vec = (1..params.share_count + 1)
            .map(|i| {
                if i == party_num_int {
                    bc_i.clone()
                } else {
                    let bc1_j: KeyGenBroadcastMessage1 =
                        serde_json::from_str(&round1_ans_vec[j]).unwrap();
                    j = j + 1;
                    bc1_j
                }
            })
            .collect::<Vec<KeyGenBroadcastMessage1>>();

        assert!(net.send(SendType::Broadcast, "set", "round2", &decom_i).is_ok());
        let round2_ans_vec: Vec<String> = net.receive(ReceiveType::PollBroadcast, "get", "round2").unwrap();

        ////////////////////////////////////////////////////////////////////////////
        // round 3
        let mut j = 0;
        let mut y_vec: Vec<GE> = Vec::new();
        let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
        let mut enc_keys: Vec<BigInt> = Vec::new();
        for i in 1..params.share_count + 1 {
            if i == party_num_int {
                y_vec.push(party_key.y_i.clone());
                decom_vec.push(decom_i.clone());
            } else {
                let decom_j: KeyGenDecommitMessage1 = serde_json::from_str(&round2_ans_vec[j]).unwrap();
                y_vec.push(decom_j.y_i.clone());
                decom_vec.push(decom_j.clone());
                enc_keys.push(
                    (party_key.y_i.clone() + decom_j.y_i.clone())
                        .x_coor()
                        .unwrap(),
                );
                j = j + 1;
            }
        }

        let mut y_vec_iter = y_vec.iter();
        let head = y_vec_iter.next().unwrap();
        let tail = y_vec_iter;
        let y_sum = tail.fold(head.clone(), |acc, x| acc + x);

        let (vss_scheme, secret_shares, _index) = party_key
            .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
                &params, &decom_vec, &bc1_vec,
            )
            .expect("invalid key");

        let mut j = 0;
        let mut k = 0;
        let round = 3;
        for i in 1..params.share_count + 1 {
            if i != party_num_int {
                // prepare encrypted ss for party i:
                let key_i = BigInt::to_vec(&enc_keys[j]);
                let nonce: Vec<u8> = repeat(round).take(12).collect();
                let aad: [u8; 0] = [];
                let mut gcm = AesGcm::new(KeySize256, &key_i[..], &nonce[..], &aad);
                let plaintext = BigInt::to_vec(&secret_shares[k].to_big_int());
                let mut out: Vec<u8> = repeat(0).take(plaintext.len()).collect();
                let mut out_tag: Vec<u8> = repeat(0).take(16).collect();
                gcm.encrypt(&plaintext[..], &mut out[..], &mut out_tag[..]);
                let aead_pack_i = AEAD {
                    ciphertext: out.to_vec(),
                    tag: out_tag.to_vec(),
                };

                let path = serde_json::to_string(&("set", i.to_string())).unwrap();
                assert!(net.send(SendType::ToPeer, &path, "round3", &aead_pack_i).is_ok());
                
                j = j + 1;
            }
            k = k + 1;
        }
        
        let round3_ans_vec: Vec<String> = net.receive(ReceiveType::FromPeer, "get", "round3").unwrap();

        ////////////////////////////////////////////////////////////////////////////        
        // round 4
        let mut j = 0;
        let mut party_shares: Vec<FE> = Vec::new();
        for i in 1..params.share_count + 1 {
            if i == party_num_int {
                party_shares.push(secret_shares[(i - 1) as usize].clone());
            } else {
                let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
                let mut out: Vec<u8> = repeat(0).take(aead_pack.ciphertext.len()).collect();
                let key_i = BigInt::to_vec(&enc_keys[j]);
                let nonce: Vec<u8> = repeat(round).take(12).collect();
                let aad: [u8; 0] = [];
                let mut gcm = AesGcm::new(KeySize256, &key_i[..], &nonce[..], &aad);
                let result = gcm.decrypt(&aead_pack.ciphertext[..], &mut out, &aead_pack.tag[..]);
                assert!(result);
                let out_bn = BigInt::from(&out[..]);
                let out_fe = ECScalar::from(&out_bn);
                party_shares.push(out_fe);

                j = j + 1;
            }
        }
  
        assert!(net.send(SendType::Broadcast, "set", "round4", &vss_scheme).is_ok());
        let round4_ans_vec: Vec<String> = net.receive(ReceiveType::PollBroadcast, "get", "round4").unwrap();

        ////////////////////////////////////////////////////////////////////////////
        // round 5
        let mut j = 0;
        let mut vss_scheme_vec: Vec<VerifiableSS> = Vec::new();
        for i in 1..params.share_count + 1 {
            if i == party_num_int {
                vss_scheme_vec.push(vss_scheme.clone());
            } else {
                let vss_scheme_j: VerifiableSS = serde_json::from_str(&round4_ans_vec[j]).unwrap();
                vss_scheme_vec.push(vss_scheme_j);
                j = j + 1;
            }
        }

        let (shared_key, dlog_proof) = party_key
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                &params,
                &y_vec,
                &party_shares,
                &vss_scheme_vec,
                &(party_num_int as usize),
            )
            .expect("invalid vss");
        
        assert_eq!(shared_key.y, y_sum);
        
        assert!(net.send(SendType::Broadcast, "set", "round5", &dlog_proof).is_ok());
        let round5_ans_vec: Vec<String> = net.receive(ReceiveType::PollBroadcast, "get", "round5").unwrap();

        let mut j = 0;
        let mut dlog_proof_vec: Vec<DLogProof> = Vec::new();
        for i in 1..params.share_count + 1 {
            if i == party_num_int {
                dlog_proof_vec.push(dlog_proof.clone());
            } else {
                let dlog_proof_j: DLogProof = serde_json::from_str(&round5_ans_vec[j]).unwrap();
                dlog_proof_vec.push(dlog_proof_j);
                j = j + 1;
            }
        }
        Keys::verify_dlog_proofs(&params, &dlog_proof_vec, &y_vec).expect("bad dlog proof");
        
        let paillier_key_vec = (0..params.share_count)
            .map(|i| bc1_vec[i as usize].e.clone())
            .collect::<Vec<EncryptionKey>>();

        // return
        EcdsaKey {
            party_key: party_key,
            shared_key: shared_key,
            vss_scheme_vec: vss_scheme_vec,
            paillier_key_vec: paillier_key_vec
        }
    }
}

impl Key for EcdsaKey {
    fn new(
        parties: Vec<String>, 
        share_count: usize, 
        threshold: usize
    ) -> EcdsaKey {
        assert!(parties.len() > 0);
        assert!(share_count > 1);
        assert!(threshold > 0);

        let params = Parameters {
            threshold: threshold as usize,
            share_count: share_count as usize,
        };

        let key: Option<EcdsaKey> =
        match parties.len() {
            1 => {
                let net: ClientToServer = Net::new(share_count, parties);
                Some(EcdsaKey::execute(&net, &params))
            },
            _ => {
                // let net: PeerToPeer = Net::new(share_count, parties);
                // Some(EcdsaKey::execute(&net, &params))
                None
            }
        };

        key.unwrap()
    }

    fn from_backup(input: String) -> Self {
        serde_json::from_str(&input).unwrap()
    }

    fn get_backup(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    fn to_string(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
}

////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////

#[derive(Serialize, Deserialize)]
pub struct EcdsaSign {
    pub signature: Signature
}

impl EcdsaSign {
    pub fn execute<T>(net: &T, threshold: &usize, key: EcdsaKey, message: &str) -> EcdsaSign 
    where
        T: Net,
    {
        

        EcdsaSign {
            signature: Signature {
                r: ECScalar::new_random(),
                s: ECScalar::new_random()
            }
        }
    }
}

impl Sign for EcdsaSign {
    fn new<T>(key: &T, message: &str, parties: Vec<String>, threshold: usize) -> Self 
    where T: Key + serde::ser::Serialize
    {
        assert!(message.len() > 0);
        assert!(parties.len() > 0);
        assert!(threshold > 0);

        let key_str = serde_json::to_string(&key).unwrap();
        let ecdsa_key: EcdsaKey = serde_json::from_str(&key_str).unwrap();

        let sign: Option<EcdsaSign> =
        match parties.len() {
            1 => {
                let net: ClientToServer = Net::new(threshold, parties);
                Some(EcdsaSign::execute(&net, &threshold, ecdsa_key, message))
            },
            _ => {
                // let net: PeerToPeer = Net::new(threshold, parties);
                // Some(EcdsaSign::execute(&net, &threshold))
                None
            }
        };

        sign.unwrap()
    }

    fn verify(input: String) -> String {
        input
    }

    fn to_string(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
}