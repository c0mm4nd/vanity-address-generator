//! Private-key generation: preserve full OS-seeded CSPRNG entropy per candidate.
use crate::args::BlockchainType;
use bech32::{u5, ToBase32, Variant};
use ed25519_dalek::{PublicKey as EdPublic, SecretKey as EdSecret};
use rand::RngCore;
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey, Signing};
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

pub fn random_secret(rng: &mut impl RngCore) -> SecretKey {
    loop {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        if let Ok(key) = SecretKey::from_byte_array(&bytes) {
            return key;
        }
    }
}

pub fn eth_hash(public: &PublicKey) -> [u8; 20] {
    let mut hash = [0; 32];
    let mut keccak = Keccak::v256();
    keccak.update(&public.serialize_uncompressed()[1..]);
    keccak.finalize(&mut hash);
    hash[12..].try_into().unwrap()
}

pub fn base58check(version: u8, payload: &[u8; 20]) -> String {
    let mut bytes = [0; 25];
    bytes[0] = version;
    bytes[1..21].copy_from_slice(payload);
    let checksum = Sha256::digest(Sha256::digest(&bytes[..21]));
    bytes[21..].copy_from_slice(&checksum[..4]);
    bs58::encode(bytes).into_string()
}

pub fn address_from_hash(hash: &[u8; 20], chain: &BlockchainType, case: bool) -> String {
    if matches!(chain, BlockchainType::Tron) {
        return base58check(0x41, hash);
    }
    let mut bytes = [b'0'; 42];
    bytes[1] = b'x';
    hex::encode_to_slice(hash, &mut bytes[2..]).unwrap();
    let address = std::str::from_utf8(&bytes).unwrap();
    if case {
        eip55::checksum(address)
    } else {
        address.to_owned()
    }
}

pub fn secp_address(public: &PublicKey, chain: &BlockchainType, case: bool) -> String {
    match chain {
        BlockchainType::Ethereum | BlockchainType::Tron => {
            address_from_hash(&eth_hash(public), chain, case)
        }
        _ => {
            // New private-key wallets use standard compressed Bitcoin public keys.
            let hash: [u8; 20] = Ripemd160::digest(Sha256::digest(public.serialize())).into();
            match chain {
                BlockchainType::BitcoinP2PKH => base58check(0, &hash),
                BlockchainType::BitcoinP2SH => {
                    let mut script = [0; 22];
                    script[1] = 20;
                    script[2..].copy_from_slice(&hash);
                    let script_hash = Ripemd160::digest(Sha256::digest(script)).into();
                    base58check(5, &script_hash)
                }
                BlockchainType::BitcoinBech32 => {
                    let mut data = vec![u5::try_from_u8(0).unwrap()];
                    data.extend(hash.to_base32());
                    bech32::encode("bc", data, Variant::Bech32).unwrap()
                }
                _ => unreachable!(),
            }
        }
    }
}

pub fn generate<C: Signing>(
    rng: &mut impl RngCore,
    secp: &Secp256k1<C>,
    chain: &BlockchainType,
    case: bool,
) -> ([u8; 32], String) {
    if matches!(chain, BlockchainType::Solana) {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        let secret = EdSecret::from_bytes(&bytes).unwrap();
        let public = EdPublic::from(&secret);
        return (bytes, bs58::encode(public.as_bytes()).into_string());
    }
    let secret = random_secret(rng);
    let public = PublicKey::from_secret_key(secp, &secret);
    (secret.secret_bytes(), secp_address(&public, chain, case))
}

// Encode private material only for a match; Solana exports its usual 64-byte keypair.
pub fn encode_secret(bytes: &[u8; 32], chain: &BlockchainType) -> String {
    if matches!(chain, BlockchainType::Solana) {
        let secret = EdSecret::from_bytes(bytes).unwrap();
        let public = EdPublic::from(&secret);
        let mut keypair = [0; 64];
        keypair[..32].copy_from_slice(bytes);
        keypair[32..].copy_from_slice(public.as_bytes());
        bs58::encode(keypair).into_string()
    } else {
        hex::encode(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_secp_key_one_addresses() {
        let secp = Secp256k1::new();
        let mut bytes = [0; 32];
        bytes[31] = 1;
        let public =
            PublicKey::from_secret_key(&secp, &SecretKey::from_byte_array(&bytes).unwrap());
        assert_eq!(
            secp_address(&public, &BlockchainType::Ethereum, false),
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
        assert_eq!(
            secp_address(&public, &BlockchainType::Ethereum, true),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );
        assert_eq!(
            secp_address(&public, &BlockchainType::Tron, false),
            "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC"
        );
        assert_eq!(
            secp_address(&public, &BlockchainType::BitcoinP2PKH, false),
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
        );
        assert_eq!(
            secp_address(&public, &BlockchainType::BitcoinP2SH, false),
            "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN"
        );
        let segwit = secp_address(&public, &BlockchainType::BitcoinBech32, false);
        let (hrp, data, variant) = bech32::decode(&segwit).unwrap();
        assert_eq!(hrp, "bc");
        assert_eq!(variant, Variant::Bech32);
        assert_eq!(data[0].to_u8(), 0);
        assert_eq!(
            data[1..],
            Ripemd160::digest(Sha256::digest(public.serialize())).to_base32()
        );
    }
    #[test]
    fn solana_export_recovers_address() {
        let bytes = [42; 32];
        let encoded = encode_secret(&bytes, &BlockchainType::Solana);
        let keypair =
            ed25519_dalek::Keypair::from_bytes(&bs58::decode(encoded).into_vec().unwrap()).unwrap();
        assert_eq!(keypair.secret.to_bytes(), bytes);
        assert_eq!(keypair.public, EdPublic::from(&keypair.secret));
    }
}
