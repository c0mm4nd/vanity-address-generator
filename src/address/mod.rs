pub mod ethereum;
pub mod bitcoin;
pub mod solana;
pub mod tron;

// Re-export common functions for convenience
pub use ethereum::generate_eth_address;
pub use bitcoin::generate_bitcoin_address;
pub use solana::generate_solana_address;
pub use tron::generate_tron_address;