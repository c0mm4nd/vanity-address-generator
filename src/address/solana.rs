use bip0039::Mnemonic;
use ed25519_dalek::{Keypair, PublicKey as SolanaPublicKey, SecretKey as SolanaSecretKey};
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

    // Get the 32-byte secret key from the derived account
    let secret = account0.secret();
    
    // Convert the secret to a fixed 32-byte array
    let secret_key_bytes: [u8; 32] = secret.try_into().unwrap();
    
    // Create Solana secret key directly from derived bytes - no hash needed
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
    
    // use Base58 encoding for the public key
    let address = bs58::encode(&keypair.public.to_bytes()).into_string();
    
    // solana keypair is 64 bytes (32 bytes secret + 32 bytes public)
    let mut keypair_bytes = Vec::with_capacity(64);
    keypair_bytes.extend_from_slice(&keypair.secret.to_bytes());
    keypair_bytes.extend_from_slice(&keypair.public.to_bytes());
    
    // convert to Base58
    let keypair_bs58 = bs58::encode(keypair_bytes).into_string();
    
    (keypair_bs58, address)
}