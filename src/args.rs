use bip0039::Count;
use clap::{Parser, ValueEnum};
use std::str::FromStr;

#[derive(Parser, Debug, Clone)]
#[clap(about, version, author)]
pub struct Args {
    #[clap(short, long, default_value = "")]
    pub regex: String,

    /// Match case sensitively (Ethereum uses EIP-55 when enabled)
    #[clap(short = 'C', long)]
    pub case: bool,

    #[clap(short, long, default_value = "12", value_parser = parse_words_count)]
    pub words: Count,

    #[clap(short, long, default_value_t = num_cpus::get(), value_parser = parse_positive)]
    pub threads: usize,

    #[clap(short = 'W', long, default_value = "")]
    pub webhook: String,

    #[clap(short, long)]
    pub benchmark: bool,

    /// Benchmark duration; benchmark mode never saves wallets
    #[clap(long, default_value_t = 10, value_parser = parse_positive)]
    pub benchmark_seconds: usize,

    /// Wallet recovery mode: BIP39 mnemonic or private key without a mnemonic
    #[clap(long, value_enum, default_value = "mnemonic")]
    pub mode: GenerationMode,

    #[clap(long)]
    pub gpu: bool,

    #[clap(long, default_value_t = 0)]
    pub gpu_platform: i32,

    /// CUDA worker lanes (each lane checks 128 addresses per batch)
    #[clap(long, default_value_t = 16384, value_parser = parse_positive)]
    pub gpu_lanes: usize,

    #[clap(short, long, default_value = "eth", value_parser = ["eth", "btc", "btc-p2pkh", "btc-p2sh", "btc-bech32", "sol", "trx", "tron"])]
    pub chain: String,

    #[clap(short, long, default_value_t = false)]
    pub looping: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum GenerationMode {
    Mnemonic,
    PrivateKey,
}

fn parse_positive(s: &str) -> Result<usize, String> {
    s.parse::<usize>()
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(|| "must be a positive integer".to_string())
}

#[derive(Debug, Clone)]
pub enum BlockchainType {
    Ethereum,
    BitcoinP2PKH,  // Traditional (P2PKH) address (1...)
    BitcoinP2SH,   // Pay-to-Script-Hash address (3...)
    BitcoinBech32, // Segregated Witness address (bc1...)
    Solana,
    Tron, // Tron address (T...)
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
            "trx" | "tron" => Ok(BlockchainType::Tron),
            _ => Err(format!("Unknown blockchain type: {}", s)),
        }
    }
}

fn parse_words_count(s: &str) -> Result<Count, String> {
    match s {
        "12" => Ok(Count::Words12),
        "24" => Ok(Count::Words24),
        _ => Err(format!("Invalid word count: {}, must be 12 or 24", s)),
    }
}
