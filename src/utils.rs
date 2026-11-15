use crate::types::WalletInfo;
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
    webhook: &str,
    duration: Duration,
    mnemonic: String,
    address: String,
    private_key: String,
    chain_type: String,
) {
    println!("\n\n====================================================");

    // Format the duration as human-readable
    let duration_human = format!("{:?}", duration);
    let timestamp = chrono::Local::now().to_rfc3339();

    // Create the wallet info structure
    let wallet_info = WalletInfo {
        address: address.clone(),
        private_key: private_key.clone(),
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
    if !mnemonic.is_empty() {
        println!("BIP39: {}", mnemonic);
    } else {
        println!("Recovery: private key (no mnemonic)");
    }
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
}
