extern crate num_cpus;

use clap::Parser;
use regex::RegexBuilder;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::Instant;
use std::{collections::HashMap, time::Duration};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use serde::{Serialize, Deserialize};
use serde_json;

#[derive(Serialize, Deserialize)]
struct WalletInfo {
    address: String,
    mnemonic: String,
    duration_seconds: u64,
    duration_human: String,
    timestamp: String,
    chain_type: String,
}

use bip0039::{Count, Mnemonic};
use libsecp256k1::{PublicKey, SecretKey};
use tiny_hderive::bip32::ExtendedPrivKey;
use tiny_hderive::bip44::ChildNumber;
use tiny_keccak::{Hasher, Keccak};

// Bitcoin related imports
use bech32::{self, ToBase32, Variant};
use bs58;
use ripemd::{Digest as RipemdDigest, Ripemd160};
use sha2::{Digest as Sha2Digest, Sha256};

// Solana related imports
use ed25519_dalek::{Keypair, PublicKey as SolanaPublicKey, SecretKey as SolanaSecretKey};

#[derive(Parser, Debug)]
#[clap(about, version, author)]
struct Args {
    #[clap(short, long, default_value = "")]
    regex: String,

    #[clap(short, long, default_value_t = 0)]
    words: i32,

    #[clap(short, long, default_value_t = num_cpus::get())]
    threads: usize,

    #[clap(short = 'W', long, default_value = "")]
    webhook: String,

    #[clap(short, long)]
    benchmark: bool,

    #[clap(long)]
    gpu: bool,

    #[clap(long, default_value_t = 0)]
    gpu_platform: i32,

    #[clap(short, long, default_value = "eth", value_parser = ["eth", "btc", "btc-p2pkh", "btc-p2sh", "btc-bech32", "sol"])]
    chain: String,
}

#[derive(Debug, Clone)]
enum BlockchainType {
    Ethereum,
    BitcoinP2PKH,  // Traditional (P2PKH) address (1...)
    BitcoinP2SH,   // Pay-to-Script-Hash address (3...)
    BitcoinBech32, // Segregated Witness address (bc1...)
    Solana,
}

impl FromStr for BlockchainType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "eth" => Ok(BlockchainType::Ethereum),
            "btc" | "btc-p2pkh" => Ok(BlockchainType::BitcoinP2PKH),
            "btc-p2sh" => Ok(BlockchainType::BitcoinP2SH),
            "btc-bech32" => Ok(BlockchainType::BitcoinBech32),
            "sol" => Ok(BlockchainType::Solana),
            _ => Err(format!("Unknown blockchain type: {}", s)),
        }
    }
}

// Structure to track performance across threads
struct PerformanceTracker {
    address_counter: AtomicUsize,
    start_time: Instant,
}

impl PerformanceTracker {
    fn new() -> Self {
        PerformanceTracker {
            address_counter: AtomicUsize::new(0),
            start_time: Instant::now(),
        }
    }

    fn increment(&self) {
        self.address_counter.fetch_add(1, Ordering::Relaxed);
    }

    fn get_ops_per_second(&self) -> f64 {
        let count = self.address_counter.load(Ordering::Relaxed) as f64;
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            count / elapsed
        } else {
            0.0
        }
    }
}

fn main() {
    let args = Args::parse();
    println!("Threads count: {}", args.threads);
    println!("Matching regex: {}", args.regex);
    println!("Chain: {}", args.chain);

    if args.words > 0 {
        println!("Mnemonic words count: {}", args.words);
    }

    if !args.webhook.is_empty() {
        println!("Webhook: {}", args.webhook);
    }

    // Validate that the regex matches the selected blockchain address format
    let blockchain_type = BlockchainType::from_str(&args.chain).unwrap_or(BlockchainType::Ethereum);
    if let Err(err) = validate_regex_for_chain(&args.regex, &blockchain_type) {
        eprintln!("Error: {}", err);
        eprintln!("Please modify your regex to match the {} address format", args.chain);
        std::process::exit(1);
    }

    println!("\n");

    // Create shared performance tracker
    let performance_tracker = Arc::new(PerformanceTracker::new());
    
    // Clone tracker for worker threads
    let tracker_for_workers = Arc::clone(&performance_tracker);
    
    // Create a thread to display performance statistics
    let display_handle = {
        let tracker = Arc::clone(&performance_tracker);
        thread::spawn(move || {
            // Display hashrate every second
            loop {
                thread::sleep(Duration::from_secs(1));
                let ops_per_second = tracker.get_ops_per_second();
                
                // Clear line and move cursor to beginning
                print!("\r\x1B[K");
                print!("Hashrate: {:.2} addresses/s", ops_per_second);
                std::io::Write::flush(&mut std::io::stdout()).unwrap();
            }
        })
    };

    let mut handles = vec![];

    for i in 0..args.threads {
        let worker_tracker = Arc::clone(&tracker_for_workers);
        handles.push(thread::spawn(move || {
            find_vanity_address(i, worker_tracker);
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
    
    // This is technically unnecessary as we'll never reach this point unless
    // a vanity address is found (in which case the program would exit)
    display_handle.join().unwrap();
}

fn find_vanity_address(thread: usize, performance_tracker: Arc<PerformanceTracker>) {
    let args = Args::parse();
    let blockchain_type = BlockchainType::from_str(&args.chain).unwrap_or(BlockchainType::Ethereum);
    
    println!("Thread {} searching for {} addresses", thread, args.chain);

    let start = Instant::now();

    let mut op_count: u128 = 0;
    let mut op_start = Instant::now();

    // default words to 12 and 24 depends on thread
    // allow to search in different bip39 ranges for each thread
    let mut words = if thread % 2 == 1 {
        Count::Words12
    } else {
        Count::Words24
    };

    // respect user input if specified words count in args
    if args.words == 12 {
        words = Count::Words12;
    } else if args.words == 24 {
        words = Count::Words24;
    }

    let re = RegexBuilder::new(args.regex.as_ref())
        .case_insensitive(false)
        .multi_line(false)
        .dot_matches_new_line(false)
        .ignore_whitespace(true)
        .unicode(true)
        .build()
        .unwrap();

    let mut output = [0u8; 32];
    loop {
        let mnemonic = Mnemonic::generate(words);
        let address = match blockchain_type {
            BlockchainType::Ethereum => {
                let (_, public_key) = generate_eth_address(&mnemonic);
                keccak_hash(public_key, &mut output);
                eip55::checksum(&hex::encode(&output[(output.len() - 20)..]))
            }
            BlockchainType::BitcoinP2PKH => {
                // suggest not using any vanity address regex for bitcoin
                println!("Bitcoin vanity address regex is not suggested, because it is not safe that reusing the same address");
                generate_bitcoin_address(&mnemonic, &blockchain_type)
            }
            BlockchainType::BitcoinP2SH => {
                // suggest not using any vanity address regex for bitcoin
                println!("Bitcoin vanity address regex is not suggested, because it is not safe that reusing the same address");
                generate_bitcoin_address(&mnemonic, &blockchain_type)
            }
            BlockchainType::BitcoinBech32 => {
                // suggest not using any vanity address regex for bitcoin
                println!("Bitcoin vanity address regex is not suggested, because it is not safe that reusing the same address");
                generate_bitcoin_address(&mnemonic, &blockchain_type)
            }
            BlockchainType::Solana => generate_solana_address(&mnemonic),
        };

        if re.is_match(&address) {
            let duration = start.elapsed();
            found_result(&args.webhook, duration, mnemonic.to_string(), address)
        }

        if thread == 1 && args.benchmark {
            op_count += 1;

            if op_count == 10000 {
                let duration = op_start.elapsed().as_millis();
                let per_seconds = (1000 * op_count / duration) * args.threads as u128;

                println!("~{} OP/S", per_seconds);

                op_count = 0;
                op_start = Instant::now();
            }
        }

        performance_tracker.increment();
    }
}

fn found_result(webhook: &String, duration: Duration, mnemonic: String, address: String) -> ! {
    let args = Args::parse();
    let chain_type = args.chain.clone();
    
    // Format the duration as human-readable
    let duration_human = format!("{:?}", duration);
    let timestamp = chrono::Local::now().to_rfc3339();
    
    // Create the wallet info structure
    let wallet_info = WalletInfo {
        address: address.clone(),
        mnemonic: mnemonic.clone(),
        duration_seconds: duration.as_secs(),
        duration_human,
        timestamp,
        chain_type,
    };
    
    // Create a filename based on the address
    let sanitized_address = address.replace("/", "_").replace(":", "_");
    let filename = format!("{}.json", sanitized_address);
    
    // Save to JSON file
    match save_to_json(&wallet_info, &filename) {
        Ok(_) => println!("Result saved to file: {}", filename),
        Err(e) => eprintln!("Error saving result to file: {}", e),
    }
    
    // Print the result
    println!("\n");
    println!("Time: {:?}", duration);
    println!("BIP39: {}", mnemonic);
    println!("Address: {}", address);
    println!("\n");

    // Send to webhook
    if !webhook.is_empty() {
        let mut map = HashMap::new();
        map.insert("duration", duration.as_secs().to_string());
        map.insert("mnemonic", mnemonic);
        map.insert("address", address);
        // Note: webhook sending implementation would go here
    }
    
    // Exit the program after finding a match
    std::process::exit(0);
}

/// Save the wallet information to a JSON file
fn save_to_json(wallet_info: &WalletInfo, filename: &str) -> Result<(), std::io::Error> {
    let json_content = serde_json::to_string_pretty(wallet_info)?;
    let mut file = File::create(filename)?;
    file.write_all(json_content.as_bytes())?;
    Ok(())
}

#[inline(always)]
fn keccak_hash(public_key: PublicKey, output: &mut [u8; 32]) {
    let input = &public_key.serialize()[1..65];
    let mut hasher = Keccak::v256();
    hasher.update(input);
    hasher.finalize(output);
}

#[inline(always)]
fn generate_eth_address(mnemonic: &Mnemonic) -> (Mnemonic, PublicKey) {
    let seed = mnemonic.to_seed("");

    let hdwallet = ExtendedPrivKey::derive(&seed, "m/44'/60'/0'/0").unwrap();
    let account0 = hdwallet.child(ChildNumber::from_str("0").unwrap()).unwrap();

    let secret_key = SecretKey::parse(&account0.secret());
    let secret_key = match secret_key {
        Ok(sk) => sk,
        Err(_) => panic!("Failed to parse secret key"),
    };

    let public_key = PublicKey::from_secret_key(&secret_key);

    (mnemonic.clone(), public_key)
}

#[inline(always)]
fn generate_bitcoin_address(mnemonic: &Mnemonic, blockchain_type: &BlockchainType) -> String {
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

    match blockchain_type {
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
    }
}

#[inline(always)]
fn generate_solana_keypair(mnemonic: &Mnemonic) -> Keypair {
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
fn generate_solana_address(mnemonic: &Mnemonic) -> String {
    let keypair = generate_solana_keypair(mnemonic);
    bs58::encode(&keypair.public.to_bytes()).into_string()
}

/// Validate if the regex pattern matches the specified blockchain address format
fn validate_regex_for_chain(regex: &str, blockchain_type: &BlockchainType) -> Result<(), String> {
    if regex.is_empty() {
        return Err(String::from("Empty regex pattern is not allowed. Please specify a pattern to match addresses."));
    }

    match blockchain_type {
        BlockchainType::Ethereum => {
            // Ethereum addresses are 40 hex digits, optionally prefixed with "0x"
            if regex.starts_with("^") {
                let prefix_check = regex.trim_start_matches('^');
                
                // Check if prefix is 0x (if specified)
                if prefix_check.starts_with("0x") {
                    let hex_part = prefix_check.trim_start_matches("0x");
                    
                    // Check if the remaining part contains valid hex characters only
                    for c in hex_part.chars() {
                        if !c.is_ascii_hexdigit() && c != '.' && c != '*' && c != '+'
                            && c != '?' && c != '|' && c != '[' && c != ']' && c != '(' && c != ')'
                            && c != '{' && c != '}' && c != '\\' && c != '$' {
                            return Err(format!(
                                "Invalid Ethereum address regex: '{}' contains non-hexadecimal character '{}'. Ethereum addresses can only contain hex characters (0-9, a-f, A-F)",
                                regex, c
                            ));
                        }
                    }
                }
            }
        },
        BlockchainType::BitcoinP2PKH => {
            // Validate P2PKH address format (Bitcoin addresses starting with 1)
            if regex.starts_with("^") && !regex.starts_with("^1") && !regex.contains("|^1") {
                return Err(format!(
                    "Invalid Bitcoin P2PKH address regex: '{}'. P2PKH addresses must start with '1'",
                    regex
                ));
            }
        },
        BlockchainType::BitcoinP2SH => {
            // Validate P2SH address format (Bitcoin addresses starting with 3)
            if regex.starts_with("^") && !regex.starts_with("^3") && !regex.contains("|^3") {
                return Err(format!(
                    "Invalid Bitcoin P2SH address regex: '{}'. P2SH addresses must start with '3'",
                    regex
                ));
            }
        },
        BlockchainType::BitcoinBech32 => {
            // Validate Bech32 address format (Bitcoin addresses starting with bc1)
            if regex.starts_with("^") && !regex.starts_with("^bc1") && !regex.contains("|^bc1") {
                return Err(format!(
                    "Invalid Bitcoin Bech32 address regex: '{}'. Bech32 addresses must start with 'bc1'",
                    regex
                ));
            }
        },
        BlockchainType::Solana => {
            // Solana addresses are Base58-encoded 32-byte public keys
            // Base58 charset: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
            let base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

            for c in regex.chars() {
                if !base58_chars.contains(c) && c != '^' && c != '$' && c != '.' && c != '*' 
                   && c != '+' && c != '?' && c != '|' && c != '[' && c != ']' && c != '(' 
                   && c != ')' && c != '{' && c != '}' && c != '\\' {
                    
                    if c == '0' || c == 'O' || c == 'I' || c == 'l' {
                        return Err(format!(
                            "Invalid Solana address regex: '{}' contains character '{}', which is not in Base58 charset (Note: Base58 doesn't include 0, O, I, l)",
                            regex, c
                        ));
                    } else {
                        // If not a regex special character or Base58 character, might be invalid
                        if !c.is_whitespace() {  // Ignore whitespace
                            return Err(format!(
                                "Invalid Solana address regex: '{}' contains character '{}', which is not in Base58 charset",
                                regex, c
                            ));
                        }
                    }
                }
            }
        },
    }

    Ok(())
}
