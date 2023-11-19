extern crate num_cpus;

use clap::Parser;
use regex::RegexBuilder;
use std::str::FromStr;
use std::thread;
use std::time::Instant;
use std::{collections::HashMap, time::Duration};

use bip0039::{Count, Mnemonic};
use libsecp256k1::{PublicKey, SecretKey};
use tiny_hderive::bip32::ExtendedPrivKey;
use tiny_hderive::bip44::ChildNumber;
use tiny_keccak::{Hasher, Keccak};

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
}

fn main() {
    let args = Args::parse();
    println!("Threads count: {}", args.threads);
    println!("Matching regex: {}", args.regex);

    if args.words > 0 {
        println!("Mnemonic words count: {}", args.words);
    }

    if !args.webhook.is_empty() {
        println!("Webhook: {}", args.webhook);
    }

    if args.benchmark {
        println!("Benchmark: true");
    }

    println!("\n");

    let mut handles = vec![];

    for i in 0..args.threads {
        handles.push(thread::spawn(move || {
            find_vanity_address(i);
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

fn find_vanity_address(thread: usize) {
    let args = Args::parse();

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
        .case_insensitive(true)
        .multi_line(false)
        .dot_matches_new_line(false)
        .ignore_whitespace(true)
        .unicode(true)
        .build()
        .unwrap();

    let mut output = [0u8; 32];
    loop {
        let (mnemonic, public_key) = generate_address(words);
        keccak_hash(public_key, &mut output);
        let address = eip55::checksum(&hex::encode(&output[(output.len() - 20)..]));

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
    }
}

fn found_result(webhook: &String, duration: Duration, mnemonic: String, address: String) {
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
        map.insert("address", address.to_string());
    }
}

#[inline(always)]
fn keccak_hash(public_key: PublicKey, output: &mut [u8; 32]) {
    let input = &public_key.serialize()[1..65];
    let mut hasher = Keccak::v256();
    hasher.update(input);
    hasher.finalize(output);
}

#[inline(always)]
fn generate_address(words: Count) -> (Mnemonic, PublicKey) {
    let mnemonic = Mnemonic::generate(words);
    let seed = mnemonic.to_seed("");

    let hdwallet = ExtendedPrivKey::derive(&seed, "m/44'/60'/0'/0").unwrap();
    let account0 = hdwallet.child(ChildNumber::from_str("0").unwrap()).unwrap();

    let secret_key = SecretKey::parse(&account0.secret());
    let secret_key = match secret_key {
        Ok(sk) => sk,
        Err(_) => panic!("Failed to parse secret key"),
    };

    let public_key = PublicKey::from_secret_key(&secret_key);

    (mnemonic, public_key)
}
