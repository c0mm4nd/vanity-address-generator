use bip0039::Mnemonic;
use ed25519_dalek::{Keypair, PublicKey as SolanaPublicKey, SecretKey as SolanaSecretKey};
use hex::ToHex;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::str::FromStr;
use tiny_hderive::bip32::ExtendedPrivKey;
use tiny_hderive::bip44::ChildNumber;

#[inline(always)]
pub fn generate_solana_keypair(mnemonic: &Mnemonic) -> Keypair {
    let seed = mnemonic.to_seed("");

    // Solana uses m/44'/501'/0'/0' derivation path
    let hdwallet = ExtendedPrivKey::derive(&seed, "m/44'/501'/0'/0'").unwrap();
    let account0 = hdwallet.child(ChildNumber::from_str("0").unwrap()).unwrap();

    // Convert the seed to a Solana keypair
    // The seed is 64 bytes, but we need 32 bytes for the Solana secret key
    let secret = account0.secret();

    // Create a SHA-256 hash of the seed to get a 32-byte key
    let mut hasher = Sha256::new();
    hasher.update(secret);
    let hashed_seed = hasher.finalize();

    let secret_key_bytes: [u8; 32] = hashed_seed.as_slice().try_into().unwrap();
    let secret_key = SolanaSecretKey::from_bytes(&secret_key_bytes).unwrap();

    // Create a keypair from the secret key
    let public_key = SolanaPublicKey::from(&secret_key);
    Keypair {
        secret: secret_key,
        public: public_key,
    }
}

#[inline(always)]
pub fn generate_solana_address(mnemonic: &Mnemonic) -> (String, String) {
    let keypair = generate_solana_keypair(mnemonic);
    let address = bs58::encode(&keypair.public.to_bytes()).into_string();
    (keypair.secret.to_bytes().encode_hex(), address)
}