use bip0039::Mnemonic;
use hex::ToHex;
use sha2::{Digest, Sha256};
use crate::address::ethereum::generate_eth_address;

#[inline(always)]
pub fn generate_tron_address(mnemonic: &Mnemonic) -> (String, String) {
    let (private_key, public_key) = generate_eth_address(mnemonic);

    // For keccak hash function, reusing from Ethereum
    let mut hash_output = [0u8; 32];
    crate::address::ethereum::keccak_hash(public_key, &mut hash_output);

    // Take the last 20 bytes of the keccak hash
    let address_bytes = &hash_output[(hash_output.len() - 20)..];

    // For Tron addresses, we prefix with 0x41 (instead of Ethereum's 0x)
    let mut tron_bytes = vec![0x41];
    tron_bytes.extend_from_slice(address_bytes);

    // Calculate checksum (similar to Bitcoin's method)
    // Double SHA-256 hash of the address bytes
    let mut checksum_hasher1 = Sha256::new();
    checksum_hasher1.update(&tron_bytes);
    let checksum_result1 = checksum_hasher1.finalize();

    let mut checksum_hasher2 = Sha256::new();
    checksum_hasher2.update(checksum_result1);
    let checksum_result2 = checksum_hasher2.finalize();

    // Add checksum's first 4 bytes
    tron_bytes.extend_from_slice(&checksum_result2[0..4]);

    // Base58 encode the resulting bytes to get the Tron address
    (
        private_key.encode_hex(),
        bs58::encode(tron_bytes).into_string(),
    )
}