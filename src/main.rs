use hex::ToHex;
use serde::{Deserialize, Serialize};
use serde_json;

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
    let _signed_position = sign_coordinates(37.7749, -122.4194, 10);
}

#[no_mangle]
fn sign_coordinates(latitude: f64, longitude: f64, timestamp: u64) {
    // convert hex encoded secret key to bytes
    let secret_key = "3132333435363738393031323334353637383930313233343536373839303131";
    let secret_key_bytes = hex::decode(&secret_key).expect("Invalid hex");
    let secret_key_slice = secret_key_bytes.as_slice();
    // let secret_key_bytes: [u8; 32] = [1; 32];
    // let secret_key_slice = secret_key_bytes.as_ref();

    let position = Position {
        latitude,
        longitude,
        timestamp,
    };

    // serialize position for hashing purpose
    let payload = serde_json::to_string(&position).expect("JSON serialization");

    // hash payload
    let result = hash_message(&payload);
    // let result = hash_message("Hello, world!");
    let hash = result.as_ref();

    // let hash: [u8; 32] = [1; 32];
    // sign hash
    let (secret_key, public_key) = create_key_pair_from_bytes(secret_key_slice);
    let sig = sign_hash_slice(&secret_key, &hash);

    // serialize signature and public key - needed as ecdsa::Signature does not implement Serialize
    let serialized_signature = sig.serialize_compact().encode_hex::<String>();
    let serialized_public_key = public_key.serialize().encode_hex::<String>();
    // let serialized_signature = "oui".to_string();
    // let serialized_public_key = "oui".to_string();
    // let serialized_signature = [1; 64].encode_hex::<String>();
    // let serialized_public_key = [1; 33].encode_hex::<String>();

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

/* fn verify_signature(
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
 */
