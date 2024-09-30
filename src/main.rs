use hex::{FromHex, ToHex}; // to pretty print hash
use serde::{Deserialize, Serialize};
use serde_json;
use std::time::SystemTime;

use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{self, Digest};

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

fn main() {
    // build SignedPosition object, to be sent
    let signed_position = sign_coordinates(
        37.7749,
        -122.4194,
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );
    println!(
        "Built a SignedPosition object, containing the position object, signature and public key\nThis object can be serialized and sent to other party for verification\n"
    );
    println!("SignedPosition: {:#?}\n", signed_position);

    // serialize SignedPosition object
    let signed_payload = serde_json::to_string(&signed_position).expect("JSON serialization");

    /*
     * Here the SignedPosition object would be sent to another party
     */

    println!("Upon receiving the SignedPosition object, the other party would deserialize it and verify the signature\n");
    // deserialize SignedPosition object
    let deserialized_signed_position: SignedPosition =
        serde_json::from_str(&signed_payload).expect("JSON deserialization");

    let recovered_position = deserialized_signed_position.position;
    let recovered_ser_sig = deserialized_signed_position.signature;

    // recover signature
    let recovered_sig = secp256k1::ecdsa::Signature::from_compact(
        <[u8; 64]>::from_hex(&recovered_ser_sig).unwrap().as_ref(),
    )
    .expect("64 bytes");
    println!("Recovered signature: {:?}", recovered_sig);

    // recover public key
    let recovered_ser_pub_key = deserialized_signed_position.public_key;
    let recovered_pub_key = deser_pubkey(&recovered_ser_pub_key);

    // hash recovered position object
    println!("The position object is recovered and a hash of it is computed\nThen the signature is verified using the recovered hash and public key\n");
    let recovered_payload = serde_json::to_string(&recovered_position).expect("JSON serialization");
    let recovered_result = hash_message(&recovered_payload);
    let recieved_payload_hash = recovered_result.as_ref();

    // verify signature
    let is_valid = verify_signature(&recovered_pub_key, &recovered_sig, recieved_payload_hash);
    println!("Signature is valid: {}", is_valid);
}

#[no_mangle]
fn sign_coordinates(latitude: f64, longitude: f64, timestamp: u64) {
    // convert hex encoded secret key to bytes
    let secret_key = "3132333435363738393031323334353637383930313233343536373839303131";
    let secret_key_bytes = hex::decode(&secret_key).expect("Invalid hex");
    let secret_key_slice = secret_key_bytes.as_slice();

    let position = Position {
        latitude,
        longitude,
        timestamp,
    };

    // serialize position for hashing purpose
    let payload = serde_json::to_string(&position).expect("JSON serialization");

    // hash payload
    let result = hash_message(&payload);
    let hash = result.as_ref();

    // sign hash
    let (secret_key, public_key) = create_key_pair_from_bytes(secret_key_slice);
    let sig = sign_hash_slice(&secret_key, hash);

    // serialize signature and public key - needed as ecdsa::Signature does not implement Serialize
    let serialized_signature = sig.serialize_compact().encode_hex::<String>();
    let serialized_public_key = public_key.serialize().encode_hex::<String>();

    SignedPosition {
        position,
        signature: serialized_signature,
        public_key: serialized_public_key,
    };
}

fn create_key_pair_from_bytes(secret_bytes: &[u8]) -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(secret_bytes).expect("32 bytes");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    (secret_key, public_key)
}

fn hash_message(message: &str) -> Box<[u8]> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(message.as_bytes());
    hasher.finalize().as_slice().into()
}

fn sign_hash_slice(secret_key: &SecretKey, hash: &[u8]) -> secp256k1::ecdsa::Signature {
    let message = Message::from_digest_slice(&hash).expect("32 bytes");
    let secp = Secp256k1::new();
    secp.sign_ecdsa(&message, &secret_key)
}

fn verify_signature(
    public_key: &PublicKey,
    sig: &secp256k1::ecdsa::Signature,
    hash: &[u8],
) -> bool {
    let secp = Secp256k1::new();
    let message = Message::from_digest_slice(&hash).expect("32 bytes");
    secp.verify_ecdsa(&message, &sig, &public_key).is_ok()
}

fn deser_pubkey(pubkey_str: &str) -> PublicKey {
    PublicKey::from_slice(<[u8; 33]>::from_hex(&pubkey_str).unwrap().as_ref()).expect("33 bytes")
}
