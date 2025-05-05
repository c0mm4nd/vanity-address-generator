use crate::args::BlockchainType;
use bip0039::Mnemonic;
use hex::ToHex;
use libsecp256k1::{PublicKey, SecretKey};
use tiny_hderive::bip32::ExtendedPrivKey;
use tiny_hderive::bip44::ChildNumber;
use std::str::FromStr;

// Bitcoin-specific imports
use bech32::{self, ToBase32, Variant};
use bs58;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

#[inline(always)]
pub fn generate_bitcoin_address(
    mnemonic: &Mnemonic,
    blockchain_type: &BlockchainType,
) -> (String, String) {
    let seed = mnemonic.to_seed("");

    // Select the derivation path based on the blockchain type
    // P2PKH: m/44'/0'/0'/0
    // P2SH: m/49'/0'/0'/0
    // Bech32 (Segwit): m/84'/0'/0'/0
    let derivation_path = match blockchain_type {
        BlockchainType::BitcoinP2PKH => "m/44'/0'/0'/0",
        BlockchainType::BitcoinP2SH => "m/49'/0'/0'/0",
        BlockchainType::BitcoinBech32 => "m/84'/0'/0'/0",
        _ => "m/44'/0'/0'/0", // Default to P2PKH path
    };

    let hdwallet = ExtendedPrivKey::derive(&seed, derivation_path).unwrap();
    let account0 = hdwallet.child(ChildNumber::from_str("0").unwrap()).unwrap();

    let secret_key = SecretKey::parse(&account0.secret()).unwrap();
    let public_key = PublicKey::from_secret_key(&secret_key);

    // Serialize public key
    let serialized_pub_key = public_key.serialize();

    let address = match blockchain_type {
        BlockchainType::BitcoinP2PKH => {
            // P2PKH address generation (traditional address starting with "1")

            // SHA-256 hash
            let mut sha256_hasher = Sha256::new();
            sha256_hasher.update(serialized_pub_key);
            let sha256_result = sha256_hasher.finalize();

            // RIPEMD-160 hash
            let mut ripemd_hasher = Ripemd160::new();
            ripemd_hasher.update(sha256_result);
            let ripemd_result = ripemd_hasher.finalize();

            // Add version byte (0x00 for mainnet P2PKH)
            let mut address_bytes = vec![0x00];
            address_bytes.extend_from_slice(&ripemd_result);

            // Double SHA-256 checksum calculation
            let mut checksum_hasher1 = Sha256::new();
            checksum_hasher1.update(&address_bytes);
            let checksum_result1 = checksum_hasher1.finalize();

            let mut checksum_hasher2 = Sha256::new();
            checksum_hasher2.update(checksum_result1);
            let checksum_result2 = checksum_hasher2.finalize();

            // Add checksum's first 4 bytes
            address_bytes.extend_from_slice(&checksum_result2[0..4]);

            // Base58 encoding
            bs58::encode(address_bytes).into_string()
        }
        BlockchainType::BitcoinP2SH => {
            // P2SH address generation (starting with "3")

            // SHA-256 hash
            let mut sha256_hasher = Sha256::new();
            sha256_hasher.update(serialized_pub_key);
            let sha256_result = sha256_hasher.finalize();

            // RIPEMD-160 hash
            let mut ripemd_hasher = Ripemd160::new();
            ripemd_hasher.update(sha256_result);
            let ripemd_result = ripemd_hasher.finalize();

            // Create the raw redeem script - OP_0 <pubKeyHash>
            let mut redeem_script = vec![0x00, 0x14];
            redeem_script.extend_from_slice(&ripemd_result);

            // Calculate the hash of the redeem script
            // SHA-256
            let mut script_hasher = Sha256::new();
            script_hasher.update(&redeem_script);
            let script_sha256 = script_hasher.finalize();

            // RIPEMD-160
            let mut script_ripemd = Ripemd160::new();
            script_ripemd.update(script_sha256);
            let script_hash = script_ripemd.finalize();

            // Add version byte (0x05 for mainnet P2SH)
            let mut address_bytes = vec![0x05];
            address_bytes.extend_from_slice(&script_hash);

            // Double SHA-256 checksum calculation
            let mut checksum_hasher1 = Sha256::new();
            checksum_hasher1.update(&address_bytes);
            let checksum_result1 = checksum_hasher1.finalize();

            let mut checksum_hasher2 = Sha256::new();
            checksum_hasher2.update(checksum_result1);
            let checksum_result2 = checksum_hasher2.finalize();

            // Add checksum's first 4 bytes
            address_bytes.extend_from_slice(&checksum_result2[0..4]);

            // Base58 encoding
            bs58::encode(address_bytes).into_string()
        }
        BlockchainType::BitcoinBech32 => {
            // Bech32 address generation (starting with "bc1")

            // SHA-256 hash
            let mut sha256_hasher = Sha256::new();
            sha256_hasher.update(serialized_pub_key);
            let sha256_result = sha256_hasher.finalize();

            // RIPEMD-160 hash
            let mut ripemd_hasher = Ripemd160::new();
            ripemd_hasher.update(sha256_result);
            let ripemd_result = ripemd_hasher.finalize();

            // Bech32 address generation (starting with "bc1")
            let bech32_address =
                bech32::encode("bc", ripemd_result.to_base32(), Variant::Bech32).unwrap();
            bech32_address
        }
        _ => {
            // Default to P2PKH format
            let mut sha256_hasher = Sha256::new();
            sha256_hasher.update(serialized_pub_key);
            let sha256_result = sha256_hasher.finalize();

            let mut ripemd_hasher = Ripemd160::new();
            ripemd_hasher.update(sha256_result);
            let ripemd_result = ripemd_hasher.finalize();

            let mut address_bytes = vec![0x00];
            address_bytes.extend_from_slice(&ripemd_result);

            let mut checksum_hasher1 = Sha256::new();
            checksum_hasher1.update(&address_bytes);
            let checksum_result1 = checksum_hasher1.finalize();

            let mut checksum_hasher2 = Sha256::new();
            checksum_hasher2.update(checksum_result1);
            let checksum_result2 = checksum_hasher2.finalize();

            address_bytes.extend_from_slice(&checksum_result2[0..4]);

            bs58::encode(address_bytes).into_string()
        }
    };

    (account0.secret().to_vec().encode_hex(), address)
}