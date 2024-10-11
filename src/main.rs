use hex::{FromHex, ToHex};
use serde::{Deserialize, Serialize};
use serde_json;
use std::time::SystemTime;

use ff::Field;
use zk_engine::nova::{
    provider::{ipa_pc, PallasEngine, VestaEngine},
    spartan::{ppsnark, snark},
    traits::{
        circuit::TrivialCircuit,
        snark::{default_ck_hint, RelaxedR1CSSNARKTrait},
        Engine,
    },
    CompressedSNARK, PublicParams, RecursiveSNARK,
};

use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use sha2::{self, Digest};
use zk_engine::precompiles::signing::SigningCircuit;

#[derive(Serialize, Deserialize, Debug)]
struct Position {
    latitude: f64,
    longitude: f64,
    timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct SignedPosition {
    position: Position,
    signature: String,
    public_key: String,
}

type E1 = PallasEngine;
type E2 = VestaEngine;
type EE1 = ipa_pc::EvaluationEngine<E1>;
type EE2 = ipa_pc::EvaluationEngine<E2>;
type S1 = ppsnark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = snark::RelaxedR1CSSNARK<E2, EE2>;

fn main() {
    // Simulate inputs
    let secret_key_hex = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let secret_key = hex::decode(secret_key_hex).unwrap();

    let public_key_hex = "034646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff";
    let public_key = deser_pubkey(public_key_hex);

    let latitude = 48.8566;
    let longitude = 2.3522;
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // build position object
    let position = Position {
        latitude,
        longitude,
        timestamp,
    };

    let hash = hash_position(&position);

    /*
     * BUILDING THE PUBLIC PARAMETERS
     */

    // create signing circuit
    type C1 = SigningCircuit<<E1 as Engine>::Scalar>;
    type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;

    let circuit_primary = C1::new(hash.clone(), secret_key);
    let circuit_secondary = C2::default();

    // produce public parameters
    println!("Producing public parameters...");
    let pp = PublicParams::<E1>::setup(
        &circuit_primary,
        &circuit_secondary,
        &*S1::ck_floor(),
        &*S2::ck_floor(),
    )
    .unwrap();

    /*
     * PROVING CODE EXECUTION
     */
    let z0_primary = [<E1 as Engine>::Scalar::ZERO; 4];
    let z0_secondary = [<E2 as Engine>::Scalar::ZERO];

    // produce a recursive SNARK
    println!("Generating a RecursiveSNARK...");
    let mut recursive_snark: RecursiveSNARK<E1> = RecursiveSNARK::<E1>::new(
        &pp,
        &circuit_primary,
        &circuit_secondary,
        &z0_primary,
        &z0_secondary,
    )
    .unwrap();

    recursive_snark
        .prove_step(&pp, &circuit_primary, &circuit_secondary)
        .unwrap();

    /*
     * VERIFYING PROOF
     */

    // verify the recursive SNARK
    println!("Verifying a RecursiveSNARK...");
    let res = recursive_snark.verify(&pp, 1, &z0_primary, &z0_secondary);
    println!("RecursiveSNARK::verify: {:?}", res.is_ok());

    /*
     * COMPRESS PROOF
     */
    println!("Compressing...");
    let (pk, vk) = CompressedSNARK::<E1, S1, S2>::setup(&pp).unwrap();
    let snark = CompressedSNARK::prove(&pp, &pk, &recursive_snark).unwrap();

    snark
        .verify(&vk, recursive_snark.num_steps(), &z0_primary, &z0_secondary)
        .unwrap();

    /*
     * RECOVERING SIGNATURE
     */

    let (signature, _) = res.unwrap();
    let mut signature_bytes: [u8; 64] = [0; 64];
    for (i, signature_part) in signature.into_iter().enumerate() {
        let part: [u8; 32] = signature_part.into();
        signature_bytes[i * 16..(i + 1) * 16].copy_from_slice(&part[0..16]);
    }
    println!("Signature : {:?}", signature_bytes.encode_hex::<String>());

    /*
     * VERIFYING SIGNATURE
     */

    let is_valid = verify_signature(&public_key, &signature_bytes, &hash);
    println!("Signature is valid: {:?}", is_valid);
}

fn hash_position(position: &Position) -> Vec<u8> {
    let payload = serde_json::to_string(&position).expect("JSON serialization");
    let result = hash_message(&payload);
    result.to_vec()
}

fn hash_message(message: &str) -> Box<[u8]> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(message.as_bytes());
    hasher.finalize().as_slice().into()
}

fn verify_signature(public_key: &PublicKey, sig: &[u8], hash: &[u8]) -> bool {
    let secp = Secp256k1::new();
    let message = Message::from_digest_slice(&hash).expect("32 bytes");
    let signature = Signature::from_compact(sig).expect("64 bytes");
    secp.verify_ecdsa(&message, &signature, &public_key).is_ok()
}

fn deser_pubkey(pubkey_str: &str) -> PublicKey {
    PublicKey::from_slice(<[u8; 33]>::from_hex(&pubkey_str).unwrap().as_ref()).expect("33 bytes")
}
