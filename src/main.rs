extern crate num_cpus;

mod args;
mod types;
mod utils;
mod address;
mod gpu;

use args::{Args, BlockchainType};
use types::PerformanceTracker;
use utils::{found_result, validate_regex_for_chain};
use address::{
    ethereum::keccak_hash,
    generate_bitcoin_address,
    generate_eth_address,
    generate_solana_address,
    generate_tron_address,
};
use gpu::run_gpu_mode;

use bip0039::{Count, Mnemonic};
use clap::Parser;
use hex::ToHex;
use regex::RegexBuilder;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

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

    let blockchain_type = BlockchainType::from_str(&args.chain).unwrap_or(BlockchainType::Ethereum);

    // Check if running in GPU mode
    if args.gpu {
        println!("Running in GPU mode");
        match blockchain_type {
            BlockchainType::Ethereum | BlockchainType::Solana | BlockchainType::Tron => {
                run_gpu_mode(&args);
                return;
            }
            _ => {
                eprintln!("GPU mode is currently only supported for Ethereum (eth), Solana (sol) and Tron (trx)");
                std::process::exit(1);
            }
        }
    }

    // Validate that the regex matches the selected blockchain address format
    if let Err(err) = validate_regex_for_chain(&args.regex, &blockchain_type) {
        eprintln!("Error: {}", err);
        eprintln!(
            "Please modify your regex to match the {} address format",
            args.chain
        );
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
        let args_clone = args.clone();
        handles.push(thread::spawn(move || {
            find_vanity_address(i, worker_tracker, &args_clone);
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // This is technically unnecessary as we'll never reach this point unless
    // a vanity address is found (in which case the program would exit)
    display_handle.join().unwrap();
}

fn find_vanity_address(thread: usize, performance_tracker: Arc<PerformanceTracker>, args: &Args) {
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
        .case_insensitive(args.case)
        .multi_line(false)
        .dot_matches_new_line(false)
        .ignore_whitespace(true)
        .unicode(true)
        .build()
        .unwrap();

    let mut output = [0u8; 32];
    loop {
        let mnemonic = Mnemonic::generate(words);
        let (private_key, address) = match blockchain_type {
            BlockchainType::Ethereum => {
                let (private_key, public_key) = generate_eth_address(&mnemonic);
                keccak_hash(public_key, &mut output);
                (
                    private_key.encode_hex(),
                    eip55::checksum(&hex::encode(&output[(output.len() - 20)..])),
                )
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
            BlockchainType::Tron => generate_tron_address(&mnemonic),
        };

        if re.is_match(&address) {
            let duration = start.elapsed();
            found_result(
                &args.webhook,
                duration,
                mnemonic.to_string(),
                address,
                private_key,
                args.chain.clone(),
            )
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
