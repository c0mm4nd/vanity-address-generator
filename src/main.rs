mod address;
mod args;
mod gpu;
mod types;
mod utils;

use address::{
    ethereum::keccak_hash, generate_bitcoin_address, generate_eth_address, generate_solana_address,
    generate_tron_address, private_key,
};
use args::{Args, BlockchainType, GenerationMode};
use bip0039::Mnemonic;
use clap::Parser;
use rand::RngCore;
use regex::{Regex, RegexBuilder};
use secp256k1::Secp256k1;
use std::{
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};
use types::PerformanceTracker;
use utils::found_result;

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    let chain = BlockchainType::from_str(&args.chain)?;
    if args.regex.is_empty() && !args.benchmark {
        return Err("Specify --regex (or --benchmark)".into());
    }
    // Let the regex parser validate syntax: character-by-character checks reject valid
    // ranges, escapes and Bech32 anchors, and cannot prove a regex is satisfiable.
    let re = RegexBuilder::new(&args.regex)
        .case_insensitive(!args.case)
        .ignore_whitespace(true)
        .build()
        .map_err(|e| e.to_string())?;
    println!(
        "Chain: {}, mode: {}, threads: {}",
        args.chain,
        if args.mode == GenerationMode::PrivateKey {
            "private key"
        } else {
            "BIP39 mnemonic"
        },
        args.threads
    );
    if args.gpu {
        return gpu::run_gpu_mode(&args, &re);
    }
    let tracker = Arc::new(PerformanceTracker::new());
    let stop = Arc::new(AtomicBool::new(false));
    let deadline = args
        .benchmark
        .then(|| Instant::now() + Duration::from_secs(args.benchmark_seconds as u64));
    let (done_tx, done_rx) = mpsc::channel();
    let display_tracker = tracker.clone();
    let display = thread::spawn(move || {
        while done_rx.recv_timeout(Duration::from_secs(1)) == Err(mpsc::RecvTimeoutError::Timeout) {
            eprint!(
                "\rHashrate: {:.2} addresses/s",
                display_tracker.get_ops_per_second()
            );
        }
    });
    let mut workers = Vec::new();
    for _ in 0..args.threads {
        let (args, chain, re, tracker, stop) = (
            args.clone(),
            chain.clone(),
            re.clone(),
            tracker.clone(),
            stop.clone(),
        );
        workers.push(thread::spawn(move || {
            search(&args, &chain, &re, &tracker, &stop, deadline)
        }));
    }
    for worker in workers {
        worker.join().map_err(|_| "Worker panicked")?;
    }
    let _ = done_tx.send(());
    let _ = display.join();
    eprintln!();
    if args.benchmark {
        println!(
            "Benchmark: {} addresses in {:.3}s = {:.2} addresses/s",
            tracker.address_counter.load(Ordering::Relaxed),
            tracker.start_time.elapsed().as_secs_f64(),
            tracker.get_ops_per_second()
        );
    }
    Ok(())
}

fn search(
    args: &Args,
    chain: &BlockchainType,
    re: &Regex,
    tracker: &PerformanceTracker,
    stop: &AtomicBool,
    deadline: Option<Instant>,
) {
    let start = Instant::now();
    let mut rng = rand::thread_rng();
    let mut secp = Secp256k1::signing_only();
    let mut blinding = [0; 32];
    rng.fill_bytes(&mut blinding);
    secp.seeded_randomize(&blinding);
    let mut pending = 0;
    loop {
        if pending == 0
            && (stop.load(Ordering::Relaxed) || deadline.is_some_and(|end| Instant::now() >= end))
        {
            break;
        }
        let (mnemonic, secret, legacy_secret, address) = if args.mode == GenerationMode::PrivateKey
        {
            let (secret, address) = private_key::generate(&mut rng, &secp, chain, args.case);
            (None, secret, String::new(), address)
        } else {
            let mnemonic = Mnemonic::generate(args.words);
            let (private, address) = match chain {
                BlockchainType::Ethereum => {
                    let (private, public) = generate_eth_address(&mnemonic);
                    let mut hash = [0; 32];
                    keccak_hash(public, &mut hash);
                    (
                        hex::encode(private),
                        private_key::address_from_hash(
                            hash[12..].try_into().unwrap(),
                            chain,
                            args.case,
                        ),
                    )
                }
                BlockchainType::Solana => generate_solana_address(&mnemonic),
                BlockchainType::Tron => generate_tron_address(&mnemonic),
                _ => generate_bitcoin_address(&mnemonic, chain),
            };
            (Some(mnemonic), [0; 32], private, address)
        };
        let matched = re.is_match(&address);
        pending += 1;
        if matched && !args.benchmark {
            if args.looping || !stop.swap(true, Ordering::Relaxed) {
                let private = if args.mode == GenerationMode::PrivateKey {
                    private_key::encode_secret(&secret, chain)
                } else {
                    legacy_secret
                };
                found_result(
                    &args.webhook,
                    start.elapsed(),
                    mnemonic.map(|m| m.to_string()).unwrap_or_default(),
                    address,
                    private,
                    args.chain.clone(),
                );
            }
            if !args.looping {
                tracker.add(pending);
                return;
            }
        }
        if pending == 64 {
            tracker.add(pending);
            pending = 0;
        }
    }
}
