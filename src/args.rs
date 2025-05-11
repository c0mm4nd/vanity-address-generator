use clap::Parser;
use bip0039::Count;
use std::str::FromStr;

#[derive(Parser, Debug, Clone)]
#[clap(about, version, author)]
pub struct Args {
    #[clap(short, long, default_value = "")]
    pub regex: String,

    /// Case sensitivity for regex matching, default is true
    /// If set to false, the regex will be case insensitive
    #[clap(short='C', long)]
    pub case: bool,

    #[clap(short, long, default_value = "12", value_parser = parse_words_count)]
    pub words: Count,

    #[clap(short, long, default_value_t = num_cpus::get())]
    pub threads: usize,

    #[clap(short = 'W', long, default_value = "")]
    pub webhook: String,

    #[clap(short, long)]
    pub benchmark: bool,

    #[clap(long)]
    pub gpu: bool,

    #[clap(long, default_value_t = 0)]
    pub gpu_platform: i32,

    #[clap(short, long, default_value = "eth", value_parser = ["eth", "btc", "btc-p2pkh", "btc-p2sh", "btc-bech32", "sol", "trx", "tron"])]
    pub chain: String,

    #[clap(short, long, default_value_t = false)]
    pub looping: bool,
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
