use bip0039::{Count, English, Mnemonic};
use hex::ToHex;
use ocl::{Buffer, Error, MemFlags, Queue};
use rand::{thread_rng, Rng};
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use tiny_hderive::bip32::ExtendedPrivKey;
use tiny_hderive::bip44::ChildNumber;

// Batch size for parallel processing
pub const BATCH_SIZE: usize = 1024; // Process 256K keys in parallel
pub const WORK_GROUP_SIZE: usize = 256;

// Structure to store mnemonic and corresponding private key information
pub struct MnemonicPrivateKeyPair {
    pub mnemonic: String,
    pub private_key: Vec<u8>,
}

// Generate a random mnemonic and derive a private key for the specified cryptocurrency
pub fn generate_random_mnemonic_keypair(coin_type: &str) -> MnemonicPrivateKeyPair {
    let mut rng = thread_rng();

    // Randomly choose mnemonic length (12 or 24 words)
    let word_count = if rng.gen_bool(0.5) {
        Count::Words12
    } else {
        Count::Words24
    };

    // Generate random mnemonic
    let mnemonic = Mnemonic::<English>::generate(word_count);
    let mnemonic_str = mnemonic.to_string();

    // Generate seed from mnemonic
    let seed = mnemonic.to_seed("");

    // Derive path based on cryptocurrency
    let derivation_path = match coin_type {
        "ethereum" => "m/44'/60'/0'/0",
        "solana" => "m/44'/501'/0'/0'",
        "tron" => "m/44'/195'/0'/0",
        _ => "m/44'/60'/0'/0", // Default to Ethereum
    };

    // Derive wallet
    let hdwallet = ExtendedPrivKey::derive(&seed, derivation_path).unwrap();
    let account0 = hdwallet.child(ChildNumber::from_str("0").unwrap()).unwrap();
    let private_key = account0.secret().to_vec();

    MnemonicPrivateKeyPair {
        mnemonic: mnemonic_str,
        private_key,
    }
}

pub struct MnemonicKeypairBatch {
    pub mnemonic_pairs: Vec<MnemonicPrivateKeyPair>,
    pub reverse_map: BTreeMap<String, String>,
}

pub fn generate_random_mnemonic_keypair_batch(
    coin_type: &str,
    batch_size: usize,
) -> Result<MnemonicKeypairBatch, String> {
    let mut mnemonic_pairs = Vec::with_capacity(batch_size);
    let mut reverse_map = BTreeMap::new();

    println!("Generating {} random mnemonic keypairs...", batch_size);
    for _ in 0..batch_size {
        for _ in 0..BATCH_SIZE {
            let keypair = generate_random_mnemonic_keypair(coin_type);
            let priv_key_hex = keypair.private_key.clone().encode_hex::<String>();
            let mnemonic_clone = keypair.mnemonic.clone();
            mnemonic_pairs.push(keypair);
            reverse_map.insert(priv_key_hex, mnemonic_clone);
        }
    }
    println!("Generated {} random mnemonic keypairs", batch_size);

    if mnemonic_pairs.len() != batch_size {
        return Err(format!("Failed to generate {} keypairs", batch_size));
    }

    Ok(MnemonicKeypairBatch {
        mnemonic_pairs,
        reverse_map,
    })
}

impl MnemonicKeypairBatch {
    pub fn get_private_key_buffer(&self, queue: &Queue) -> Result<Buffer<u8>, Error> {
        let mut private_keys = Vec::with_capacity(self.mnemonic_pairs.len() * 32);

        for pair in &self.mnemonic_pairs {
            private_keys.extend_from_slice(&pair.private_key);
        }

        Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::WRITE_ONLY)
            .len(BATCH_SIZE * 20) // 20 bytes per Ethereum address
            .build()
    }

    pub fn find_matching_mnemonic_by_private_key(
        &self,
        private_key: Vec<u8>,
    ) -> String {
        // find with BTreeMap
        let private_key_hex: String = private_key.encode_hex();

        if let Some(mnemonic) = self.reverse_map.get(&private_key_hex) {
            return mnemonic.clone();
        }

        panic!("No matching mnemonic found for the given private key");
    }
}
