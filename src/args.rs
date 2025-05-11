use clap::Parser;
use std::str::FromStr;

#[derive(Parser, Debug, Clone)]
#[clap(about, version, author)]
pub struct Args {
    #[clap(short, long, default_value = "")]
    pub regex: String,

    /// Case sensitivity for regex matching, default is true
    /// If set to false, the regex will be case insensitive
    #[clap(long, default_value_t = true)]
    pub case: bool,

    #[clap(short, long, default_value_t = 0)]
    pub words: i32,

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