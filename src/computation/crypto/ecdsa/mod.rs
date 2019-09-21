extern crate hex;
extern crate rust_crypto;
extern crate curv;
extern crate paillier;
extern crate multi_party_ecdsa;

use rust_crypto::aead::AeadEncryptor;
use rust_crypto::aead::AeadDecryptor;
use rust_crypto::aes::KeySize::KeySize256;
use rust_crypto::aes_gcm::AesGcm;

use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::arithmetic::traits::Converter;
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use curv::{FE, GE};

use paillier::EncryptionKey;

use std::iter::repeat;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::mta::*;

use crate::network::traits::*;
use crate::network::c2s::*;
use super::traits::{Key, Sign};

use rust_crypto::digest::Digest;
use rust_crypto::sha2::Sha256;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

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
                let net: ClientToServer = Net::new("keygen".to_string(), share_count, parties);
                Some(EcdsaKey::execute(&net, &params))
            },
            _ => {
                // let net: PeerToPeer = Net::new("keygen".to_string(), share_count, parties);
                // Some(EcdsaKey::execute(&net, &params))
                None
            }
        };

        key.unwrap()
    }

    fn from_backup(input: String) -> EcdsaKey {
        let key: EcdsaKey = serde_json::from_str(&input).unwrap();
        key
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
    pub message: String,
    pub signature: Signature
}

impl EcdsaSign {
    pub fn format_vec_from_reads<'a, T: serde::Deserialize<'a> + Clone>(
        ans_vec: &'a Vec<String>,
        party_num: usize,
        value_i: T,
        new_vec: &'a mut Vec<T>,
    ) {
        let mut j = 0;
        for i in 1..ans_vec.len() + 2 {
            if i == party_num {
                new_vec.push(value_i.clone());
            } else {
                let value_j: T = serde_json::from_str(&ans_vec[j]).unwrap();
                new_vec.push(value_j);
                j = j + 1;
            }
        }
    }

    #[allow(non_snake_case)]
    pub fn execute<T>(net: &T, threshold: &usize, key: EcdsaKey, message: &str) -> EcdsaSign 
    where
        T: Net,
    {
        // round 0
        let party_num_int = net.get_info().client_id.clone() as usize;
        let party_id = key.party_key.party_index.clone();

        assert!(net.send(SendType::Broadcast, "set", "round0", &party_id).is_ok());
        let round0_ans_vec: Vec<String> = net.receive(ReceiveType::PollBroadcast, "get", "round0").unwrap();
        
        ////////////////////////////////////////////////////////////////////////////        
        // round 1
        let mut j = 0;
        let mut signers_vec: Vec<usize> = Vec::new();
        for i in 1..threshold + 2 {
            if i == party_num_int {
                signers_vec.push((party_id - 1) as usize);
            } else {
                let signer_j: u32 = serde_json::from_str(&round0_ans_vec[j]).unwrap();
                signers_vec.push((signer_j - 1) as usize);
                j = j + 1;
            }
        }

        let private = PartyPrivate::set_private(key.party_key.clone(), key.shared_key.clone());
        
        let sign_keys = SignKeys::create(
            &private,
            &key.vss_scheme_vec[signers_vec[(party_num_int - 1) as usize]],
            signers_vec[(party_num_int - 1) as usize],
            &signers_vec,
        );

        let xi_com_vec = Keys::get_commitments_to_xi(&key.vss_scheme_vec);

        let (com, decommit) = sign_keys.phase1_broadcast();
        let m_a_k = MessageA::a(&sign_keys.k_i, &key.party_key.ek);
        
        let data = (com.clone(), m_a_k.clone());
        assert!(net.send(SendType::Broadcast, "set", "round1", &data).is_ok());
        let round1_ans_vec: Vec<String> = net.receive(ReceiveType::PollBroadcast, "get", "round1").unwrap();
        
        ////////////////////////////////////////////////////////////////////////////
        // round 2
        let mut j = 0;
        let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
        let mut m_a_vec: Vec<MessageA> = Vec::new();

        for i in 1..threshold + 2 {
            if i == party_num_int {
                bc1_vec.push(com.clone());
            //   m_a_vec.push(m_a_k.clone());
            } else {
                //     if signers_vec.contains(&(i as usize)) {
                let (bc1_j, m_a_party_j): (SignBroadcastPhase1, MessageA) =
                    serde_json::from_str(&round1_ans_vec[j]).unwrap();
                bc1_vec.push(bc1_j);
                m_a_vec.push(m_a_party_j);

                j = j + 1;
                //       }
            }
        }
        assert_eq!(signers_vec.len(), bc1_vec.len());

        let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
        let mut beta_vec: Vec<FE> = Vec::new();
        let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
        let mut ni_vec: Vec<FE> = Vec::new();
        let mut j = 0;
        for i in 1..threshold + 2 {
            if i != party_num_int {
                let (m_b_gamma, beta_gamma) = MessageB::b(
                    &sign_keys.gamma_i,
                    &key.paillier_key_vec[signers_vec[(i - 1) as usize]],
                    m_a_vec[j].clone(),
                );
                let (m_b_w, beta_wi) = MessageB::b(
                    &sign_keys.w_i,
                    &key.paillier_key_vec[signers_vec[(i - 1) as usize]],
                    m_a_vec[j].clone(),
                );
                m_b_gamma_send_vec.push(m_b_gamma);
                m_b_w_send_vec.push(m_b_w);
                beta_vec.push(beta_gamma);
                ni_vec.push(beta_wi);
                j = j + 1;
            }
        }

        let mut j = 0;
        for i in 1..threshold + 2 {
            if i != party_num_int {
                let path = serde_json::to_string(&("set", i.to_string())).unwrap();
                let data = (m_b_gamma_send_vec[j].clone(), m_b_w_send_vec[j].clone());
                
                assert!(net.send(SendType::ToPeer, &path, "round2", &data).is_ok());
                
                j = j + 1;
            }
        }

        let round2_ans_vec: Vec<String> = net.receive(ReceiveType::FromPeer, "get", "round2").unwrap();
        
        ////////////////////////////////////////////////////////////////////////////
        // round 3
        let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
        let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();

        for i in 0..(threshold.clone()) {
            //  if signers_vec.contains(&(i as usize)) {
            let (m_b_gamma_i, m_b_w_i): (MessageB, MessageB) =
                serde_json::from_str(&round2_ans_vec[i as usize]).unwrap();
            m_b_gamma_rec_vec.push(m_b_gamma_i);
            m_b_w_rec_vec.push(m_b_w_i);
            //     }
        }

        let mut alpha_vec: Vec<FE> = Vec::new();
        let mut miu_vec: Vec<FE> = Vec::new();

        let mut j = 0;
        for i in 1..threshold + 2 {
            if i != party_num_int {
                let m_b = m_b_gamma_rec_vec[j].clone();

                let alpha_ij_gamma = m_b
                    .verify_proofs_get_alpha(&key.party_key.dk, &sign_keys.k_i)
                    .expect("wrong dlog or m_b");
                let m_b = m_b_w_rec_vec[j].clone();
                let alpha_ij_wi = m_b
                    .verify_proofs_get_alpha(&key.party_key.dk, &sign_keys.k_i)
                    .expect("wrong dlog or m_b");
                alpha_vec.push(alpha_ij_gamma);
                miu_vec.push(alpha_ij_wi);
                let g_w_i = Keys::update_commitments_to_xi(
                    &xi_com_vec[signers_vec[(i - 1) as usize]],
                    &key.vss_scheme_vec[signers_vec[(i - 1) as usize]],
                    signers_vec[(i - 1) as usize],
                    &signers_vec,
                );
                assert_eq!(m_b.b_proof.pk.clone(), g_w_i);
                j = j + 1;
            }
        }
        
        let delta_i = sign_keys.phase2_delta_i(&alpha_vec, &beta_vec);
        let sigma = sign_keys.phase2_sigma_i(&miu_vec, &ni_vec);
        
        assert!(net.send(SendType::Broadcast, "set", "round3", &delta_i).is_ok());
        let round3_ans_vec: Vec<String> = net.receive(ReceiveType::PollBroadcast, "get", "round3").unwrap();
        
        ////////////////////////////////////////////////////////////////////////////
        // round 4
        let mut delta_vec: Vec<FE> = Vec::new();
        EcdsaSign::format_vec_from_reads(
            &round3_ans_vec,
            party_num_int.clone() as usize,
            delta_i,
            &mut delta_vec,
        );
        let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

        // decommit to gamma_i
        assert!(net.send(SendType::Broadcast, "set", "round4", &decommit).is_ok());
        let round4_ans_vec: Vec<String> = net.receive(ReceiveType::PollBroadcast, "get", "round4").unwrap();
        
        ////////////////////////////////////////////////////////////////////////////
        // round 5
        let mut decommit_vec: Vec<SignDecommitPhase1> = Vec::new();
        EcdsaSign::format_vec_from_reads(
            &round4_ans_vec,
            party_num_int.clone() as usize,
            decommit,
            &mut decommit_vec,
        );
        let decomm_i = decommit_vec.remove((party_num_int - 1) as usize);
        bc1_vec.remove((party_num_int - 1) as usize);
        let b_proof_vec = (0..m_b_gamma_rec_vec.len())
            .map(|i| &m_b_gamma_rec_vec[i].b_proof)
            .collect::<Vec<&DLogProof>>();
        let R = SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec, &bc1_vec)
           .expect("bad gamma_i decommit");

        // adding local g_gamma_i
        let R = R + decomm_i.g_gamma_i * &delta_inv;

        // sha256 hasing message (ref. eosjs-ecc)
        let mut hasher = Sha256::new();
        hasher.input_str(message);
        let message_sha256_hex = hasher.result_str();

        // hashed message casting: hex string to u8 array
        let message_sha256_u8_vec = match hex::decode(&message_sha256_hex) {
            Ok(x) => x,
            Err(_e) => message_sha256_hex.as_bytes().to_vec(),
        };
        let message_hash_arr = &message_sha256_u8_vec[..];

        let message_bn = BigInt::from(message_hash_arr);
        let two = BigInt::from(2);
        let message_bn = message_bn.modulus(&two.pow(256));        
        let local_sig =
            LocalSignature::phase5_local_sig(&sign_keys.k_i, &message_bn, &R, &sigma, &key.shared_key.y);

        let (phase5_com, phase_5a_decom, helgamal_proof) = local_sig.phase5a_broadcast_5b_zkproof();

        //phase (5A)  broadcast commit
        assert!(net.send(SendType::Broadcast, "set", "round5", &phase5_com).is_ok());
        let round5_ans_vec: Vec<String> = net.receive(ReceiveType::PollBroadcast, "get", "round5").unwrap();
        
        ////////////////////////////////////////////////////////////////////////////
        // round 6
        let mut commit5a_vec: Vec<Phase5Com1> = Vec::new();
        EcdsaSign::format_vec_from_reads(
            &round5_ans_vec,
            party_num_int.clone() as usize,
            phase5_com,
            &mut commit5a_vec,
        );

        //phase (5B)  broadcast decommit and (5B) ZK proof
        let data = (phase_5a_decom.clone(), helgamal_proof.clone());
        assert!(net.send(SendType::Broadcast, "set", "round6", &data).is_ok());
        let round6_ans_vec: Vec<String> = net.receive(ReceiveType::PollBroadcast, "get", "round6").unwrap();
        
        ////////////////////////////////////////////////////////////////////////////
        // round 7
        let mut decommit5a_and_elgamal_vec: Vec<(Phase5ADecom1, HomoELGamalProof)> = Vec::new();
        EcdsaSign::format_vec_from_reads(
            &round6_ans_vec,
            party_num_int.clone() as usize,
            (phase_5a_decom.clone(), helgamal_proof.clone()),
            &mut decommit5a_and_elgamal_vec,
        );
        let decommit5a_and_elgamal_vec_includes_i = decommit5a_and_elgamal_vec.clone();
        decommit5a_and_elgamal_vec.remove((party_num_int - 1) as usize);
        commit5a_vec.remove((party_num_int - 1) as usize);
        let phase_5a_decomm_vec = (0..threshold.clone())
            .map(|i| decommit5a_and_elgamal_vec[i as usize].0.clone())
            .collect::<Vec<Phase5ADecom1>>();
        let phase_5a_elgamal_vec = (0..threshold.clone())
            .map(|i| decommit5a_and_elgamal_vec[i as usize].1.clone())
            .collect::<Vec<HomoELGamalProof>>();
        let (phase5_com2, phase_5d_decom2) = local_sig
            .phase5c(
                &phase_5a_decomm_vec,
                &commit5a_vec,
                &phase_5a_elgamal_vec,
                &phase_5a_decom.V_i,
                &R.clone(),
            )
            .expect("error phase5");

        assert!(net.send(SendType::Broadcast, "set", "round7", &phase5_com2).is_ok());
        let round7_ans_vec: Vec<String> = net.receive(ReceiveType::PollBroadcast, "get", "round7").unwrap(); 
        
        ////////////////////////////////////////////////////////////////////////////
        // round 8
        let mut commit5c_vec: Vec<Phase5Com2> = Vec::new();
        EcdsaSign::format_vec_from_reads(
            &round7_ans_vec,
            party_num_int.clone() as usize,
            phase5_com2,
            &mut commit5c_vec,
        );

        //phase (5B)  broadcast decommit and (5B) ZK proof
        assert!(net.send(SendType::Broadcast, "set", "round8", &phase_5d_decom2).is_ok());
        let round8_ans_vec: Vec<String> = net.receive(ReceiveType::PollBroadcast, "get", "round8").unwrap(); 
        
        ////////////////////////////////////////////////////////////////////////////
        // round 9
        let mut decommit5d_vec: Vec<Phase5DDecom2> = Vec::new();
        EcdsaSign::format_vec_from_reads(
            &round8_ans_vec,
            party_num_int.clone() as usize,
            phase_5d_decom2.clone(),
            &mut decommit5d_vec,
        );

        let phase_5a_decomm_vec_includes_i = (0..threshold + 1)
            .map(|i| decommit5a_and_elgamal_vec_includes_i[i as usize].0.clone())
            .collect::<Vec<Phase5ADecom1>>();
        let s_i = local_sig
            .phase5d(
                &decommit5d_vec,
                &commit5c_vec,
                &phase_5a_decomm_vec_includes_i,
            )
            .expect("bad com 5d");
        
        assert!(net.send(SendType::Broadcast, "set", "round9", &s_i).is_ok());
        let round9_ans_vec: Vec<String> = net.receive(ReceiveType::PollBroadcast, "get", "round9").unwrap(); 

        let mut s_i_vec: Vec<FE> = Vec::new();
        EcdsaSign::format_vec_from_reads(
            &round9_ans_vec,
            party_num_int.clone() as usize,
            s_i,
            &mut s_i_vec,
        );

        s_i_vec.remove((party_num_int - 1) as usize);
        let sig = local_sig
            .output_signature(&s_i_vec)
            .expect("verification failed");
      
        EcdsaSign {
            message: message.to_string(),
            signature: Signature {
                r: sig.r.clone(),
                s: sig.s.clone()
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
                let net: ClientToServer = Net::new("sign".to_string(), threshold+1, parties);
                Some(EcdsaSign::execute(&net, &threshold, ecdsa_key, message))
            },
            _ => {
                // let net: PeerToPeer = Net::new("sign".to_string(), threshold, parties);
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