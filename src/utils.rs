use crate::args::BlockchainType;
use crate::types::WalletInfo;
use serde_json;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::time::Duration;

/// Save the wallet information to a JSON file
pub fn save_to_json(wallet_info: &WalletInfo, filename: &str) -> Result<(), std::io::Error> {
    let json_content = serde_json::to_string_pretty(wallet_info)?;
    let mut file = File::create(filename)?;
    file.write_all(json_content.as_bytes())?;
    Ok(())
}

/// Process the found vanity address result
pub fn found_result(
    webhook: &String,
    duration: Duration,
    mnemonic: String,
    address: String,
    private_key: String,
    chain_type: String,
) -> ! {
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
    println!("Private Key: {}", private_key);
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

/// Validate if the regex pattern matches the specified blockchain address format
pub fn validate_regex_for_chain(regex: &str, blockchain_type: &BlockchainType) -> Result<(), String> {
    if regex.is_empty() {
        return Err(String::from(
            "Empty regex pattern is not allowed. Please specify a pattern to match addresses.",
        ));
    }

    // Base58 charset used by Solana and Tron
    let base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

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
                        if !c.is_ascii_hexdigit()
                            && c != '.'
                            && c != '*'
                            && c != '+'
                            && c != '?'
                            && c != '|'
                            && c != '['
                            && c != ']'
                            && c != '('
                            && c != ')'
                            && c != '{'
                            && c != '}'
                            && c != '\\'
                            && c != '$'
                        {
                            return Err(format!(
                                "Invalid Ethereum address regex: '{}' contains non-hexadecimal character '{}'. Ethereum addresses can only contain hex characters (0-9, a-f, A-F)",
                                regex, c
                            ));
                        }
                    }
                }
            }
        }
        BlockchainType::BitcoinP2PKH => {
            // Validate P2PKH address format (Bitcoin addresses starting with 1)
            if regex.starts_with("^") && !regex.starts_with("^1") && !regex.contains("|^1") {
                return Err(format!(
                    "Invalid Bitcoin P2PKH address regex: '{}'. P2PKH addresses must start with '1'",
                    regex
                ));
            }
        }
        BlockchainType::BitcoinP2SH => {
            // Validate P2SH address format (Bitcoin addresses starting with 3)
            if regex.starts_with("^") && !regex.starts_with("^3") && !regex.contains("|^3") {
                return Err(format!(
                    "Invalid Bitcoin P2SH address regex: '{}'. P2SH addresses must start with '3'",
                    regex
                ));
            }
        }
        BlockchainType::BitcoinBech32 => {
            // Validate Bech32 address format (Bitcoin addresses starting with bc1)
            if regex.starts_with("^") && !regex.starts_with("^bc1") && !regex.contains("|^bc1") {
                return Err(format!(
                    "Invalid Bitcoin Bech32 address regex: '{}'. Bech32 addresses must start with 'bc1'",
                    regex
                ));
            }
            // Check if the regex contains valid Bech32 characters
            for c in regex.chars() {
                if !c.is_ascii_alphanumeric()
                    && c != '1'
                    && c != 'q'
                    && c != 'p'
                    && c != 'z'
                    && c != 'r'
                    && c != 's'
                    && c != 't'
                    && c != 'u'
                    && c != 'v'
                    && c != 'w'
                    && c != 'x'
                    && c != 'y'
                    && c != 'A'
                    && c != 'B'
                    && c != 'C'
                    && c != 'D'
                    && c != 'E'
                    && c != 'F'
                {
                    return Err(format!(
                        "Invalid Bitcoin Bech32 address regex: '{}' contains invalid character '{}'. Bech32 addresses can only contain alphanumeric characters and specific characters (1, q, p, z, r, s, t, u, v, w, x, y)",
                        regex, c
                    ));
                }
            }
        }
        BlockchainType::Solana => {
            // Solana addresses are Base58-encoded 32-byte public keys
            // Base58 charset is defined above the match statement
            for c in regex.chars() {
                if !base58_chars.contains(c)
                    && c != '^'
                    && c != '$'
                    && c != '.'
                    && c != '*'
                    && c != '+'
                    && c != '?'
                    && c != '|'
                    && c != '['
                    && c != ']'
                    && c != '('
                    && c != ')'
                    && c != '{'
                    && c != '}'
                    && c != '\\'
                {
                    if c == '0' || c == 'O' || c == 'I' || c == 'l' {
                        return Err(format!(
                            "Invalid Solana address regex: '{}' contains character '{}', which is not in Base58 charset (Note: Base58 doesn't include 0, O, I, l)",
                            regex, c
                        ));
                    } else {
                        // If not a regex special character or Base58 character, might be invalid
                        if !c.is_whitespace() {
                            // Ignore whitespace
                            return Err(format!(
                                "Invalid Solana address regex: '{}' contains character '{}', which is not in Base58 charset",
                                regex, c
                            ));
                        }
                    }
                }
            }
        }
        BlockchainType::Tron => {
            // Tron addresses are Base58-encoded and typically start with T
            // Base58 charset: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz

            // Check if the regex starts with T
            if regex.starts_with("^") && !regex.starts_with("^T") && !regex.contains("|^T") {
                return Err(format!(
                    "Invalid Tron address regex: '{}'. Tron addresses typically start with 'T'",
                    regex
                ));
            }

            for c in regex.chars() {
                if !base58_chars.contains(c)
                    && c != '^'
                    && c != '$'
                    && c != '.'
                    && c != '*'
                    && c != '+'
                    && c != '?'
                    && c != '|'
                    && c != '['
                    && c != ']'
                    && c != '('
                    && c != ')'
                    && c != '{'
                    && c != '}'
                    && c != '\\'
                {
                    if c == '0' || c == 'O' || c == 'I' || c == 'l' {
                        return Err(format!(
                            "Invalid Tron address regex: '{}' contains character '{}', which is not in Base58 charset (Note: Base58 doesn't include 0, O, I, l)",
                            regex, c
                        ));
                    } else {
                        // If not a regex special character or Base58 character, might be invalid
                        if !c.is_whitespace() {
                            // Ignore whitespace
                            return Err(format!(
                                "Invalid Tron address regex: '{}' contains character '{}', which is not in Base58 charset",
                                regex, c
                            ));
                        }
                    }
                }
            }
        }
    }

    Ok(())
}