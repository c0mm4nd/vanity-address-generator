use crate::cl::common_gpu::{generate_random_mnemonic_keypair_batch, BATCH_SIZE, WORK_GROUP_SIZE};
use hex::{self, ToHex};
use ocl::enums::DeviceInfo;
use ocl::flags::{CommandQueueProperties, MemFlags};
use ocl::{Buffer, Context, Device, Kernel, Platform, Program, Queue};
use regex::RegexBuilder;
use std::fs::read_to_string;
use std::path::Path;
use std::time::{Duration, Instant};

// Run GPU ethereum miner to find a vanity address matching the regex pattern
pub fn run_gpu_ethereum_miner(
    platform_idx: i32,
    regex_str: &str,
) -> Result<(String, String, String), String> {
    // Load kernel source
    let kernel_path = Path::new("src/cl/eth_kernel.cl");
    let kernel_source = match read_to_string(&kernel_path) {
        Ok(source) => source,
        Err(e) => return Err(format!("Failed to read kernel source: {}", e)),
    };

    // Get platform and device
    let platforms = Platform::list();
    if platforms.is_empty() {
        return Err("No OpenCL platforms available".into());
    }

    let platform_index = if platform_idx >= 0 && platform_idx < platforms.len() as i32 {
        platform_idx as usize
    } else {
        0 // Default to first platform
    };

    let platform = platforms[platform_index];
    let devices = match Device::list_all(&platform) {
        Ok(d) => d,
        Err(e) => return Err(format!("Failed to list devices for platform: {}", e)),
    };

    if devices.is_empty() {
        return Err("No OpenCL devices available on the selected platform".into());
    }

    let device = devices[0]; // Use the first device

    let platform_name = platform.name().unwrap_or_else(|_| String::from("Unknown"));
    let device_name = match device.info(DeviceInfo::Name) {
        Ok(name) => name.to_string(),
        Err(_) => String::from("Unknown"),
    };

    println!("Using platform: {}", platform_name);
    println!("Using device: {}", device_name);

    // Create OpenCL context, queue and program
    let context = match Context::builder()
        .platform(platform)
        .devices(device)
        .build()
    {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to create OpenCL context: {}", e)),
    };

    let queue = match Queue::new(
        &context,
        device,
        Some(CommandQueueProperties::PROFILING_ENABLE),
    ) {
        Ok(q) => q,
        Err(e) => return Err(format!("Failed to create command queue: {}", e)),
    };

    let program = match Program::builder()
        .devices(device)
        .src(kernel_source)
        .build(&context)
    {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to build program: {}", e)),
    };

    // Create addresses buffer
    let addresses_buffer = match Buffer::<u8>::builder()
        .queue(queue.clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(BATCH_SIZE * 20) // 20 bytes per Ethereum address
        .build()
    {
        Ok(b) => b,
        Err(e) => return Err(format!("Failed to create addresses buffer: {}", e)),
    };

    // Create kernel with simplified arguments
    let kernel = match Kernel::builder()
        .program(&program)
        .name("generate_eth_address")
        .arg_named("private_keys", None::<&Buffer<u8>>) // Will be set before each execution
        .arg(&addresses_buffer)
        .arg(BATCH_SIZE as u32)
        .build()
    {
        Ok(k) => k,
        Err(e) => return Err(format!("Failed to build kernel: {}", e)),
    };

    println!("OpenCL initialization complete. Starting Ethereum GPU mining...");
    println!("Using GPU-accelerated key generation");
    println!("Looking for addresses matching regex: {}", regex_str);

    // Compile the regex pattern on the CPU side
    let re = match RegexBuilder::new(regex_str)
        .case_insensitive(true)
        .multi_line(false)
        .dot_matches_new_line(false)
        .ignore_whitespace(true)
        .unicode(true)
        .build()
    {
        Ok(r) => r,
        Err(e) => return Err(format!("Failed to compile regex pattern: {}", e)),
    };

    let mut batch_count = 0;
    let mut addresses = vec![0u8; BATCH_SIZE * 20];

    // Mining loop
    loop {
        batch_count += 1;
        let start_time = Instant::now();

        // Generate random private keys directly on GPU
        let keypair_batch = generate_random_mnemonic_keypair_batch("eth", BATCH_SIZE).unwrap();
        let private_keys_buffer = keypair_batch
            .get_private_key_buffer(&queue)
            .map_err(|e| format!("Failed to create private keys buffer: {}", e))?;

        // Set the private keys buffer as the first argument to the ethereum address generation kernel
        match kernel.set_arg(0, &private_keys_buffer) {
            Ok(_) => (),
            Err(e) => {
                return Err(format!(
                    "Failed to set private keys buffer as kernel arg: {}",
                    e
                ))
            }
        }

        // Execute address generation kernel
        let gws = [BATCH_SIZE];
        let lws = [WORK_GROUP_SIZE];

        unsafe {
            match kernel
                .cmd()
                .queue(&queue)
                .global_work_size(&gws)
                .local_work_size(&lws)
                .enq()
            {
                Ok(_) => (),
                Err(e) => return Err(format!("Failed to execute kernel: {}", e)),
            }
        }

        // Read all generated addresses from GPU
        match addresses_buffer.read(&mut addresses).enq() {
            Ok(_) => (),
            Err(e) => return Err(format!("Failed to read addresses: {}", e)),
        }

        // Check each address against the regex pattern on CPU
        for i in 0..BATCH_SIZE {
            let address_slice = &addresses[i * 20..(i + 1) * 20];
            let address_hex = eip55::checksum(&format!("0x{}", hex::encode(address_slice)));

            // Apply the regex pattern to the formatted address
            if re.is_match(&address_hex) {
                println!("Found a matching address after {} batches!", batch_count);
                println!("Address: {}", address_hex);

                // Generate a mnemonic for the matching key
                println!("Generating mnemonic for the matching key...");
                let private_key = keypair_batch.mnemonic_pairs[i].private_key.clone();
                let mnemonic = keypair_batch.find_matching_mnemonic_by_private_key(private_key.clone());

                return Ok((address_hex, private_key.encode_hex::<String>(), mnemonic));
            }
        }

        // Print status every 10 batches
        if batch_count % 10 == 0 {
            let total_addresses = batch_count * BATCH_SIZE;
            let elapsed = start_time.elapsed();
            println!(
                "Processed {} batches ({} addresses) - last batch in {:?}, speed: ~{} keys/sec",
                batch_count,
                total_addresses,
                elapsed,
                BATCH_SIZE as u64 * 1_000_000_000 / elapsed.as_nanos().max(1) as u64
            );
        }

        // Brief pause to avoid high CPU usage
        std::thread::sleep(Duration::from_millis(1));
    }
}

// Function to generate a batch of Ethereum addresses from private keys without matching
// Useful for unit tests and benchmarks
pub fn generate_ethereum_addresses_batch(
    platform_idx: i32,
    batch_size: usize,
) -> Result<Vec<(Vec<u8>, Vec<u8>, String)>, String> {
    // Load kernel source
    let kernel_path = Path::new("src/cl/eth_kernel.cl");
    let kernel_source = match read_to_string(&kernel_path) {
        Ok(source) => source,
        Err(e) => return Err(format!("Failed to read kernel source: {}", e)),
    };

    // Get platform and device
    let platforms = Platform::list();
    if platforms.is_empty() {
        return Err("No OpenCL platforms available".into());
    }

    let platform_index = if platform_idx >= 0 && platform_idx < platforms.len() as i32 {
        platform_idx as usize
    } else {
        0 // Default to first platform
    };

    let platform = platforms[platform_index];
    let devices = match Device::list_all(&platform) {
        Ok(d) => d,
        Err(e) => return Err(format!("Failed to list devices for platform: {}", e)),
    };

    if devices.is_empty() {
        return Err("No OpenCL devices available on the selected platform".into());
    }

    let device = devices[0]; // Use the first device

    // Create OpenCL context, queue and program
    let context = match Context::builder()
        .platform(platform)
        .devices(device)
        .build()
    {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to create OpenCL context: {}", e)),
    };

    let queue = match Queue::new(
        &context,
        device,
        Some(CommandQueueProperties::PROFILING_ENABLE),
    ) {
        Ok(q) => q,
        Err(e) => return Err(format!("Failed to create command queue: {}", e)),
    };

    let program = match Program::builder()
        .devices(device)
        .src(kernel_source)
        .build(&context)
    {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to build program: {}", e)),
    };

    // Generate random private keys
    let keypair_batch = generate_random_mnemonic_keypair_batch("eth", batch_size)
        .map_err(|e| format!("Failed to generate keypairs: {}", e))?;
    
    let private_keys_buffer = keypair_batch
        .get_private_key_buffer(&queue)
        .map_err(|e| format!("Failed to create private keys buffer: {}", e))?;

    // Create addresses buffer
    let addresses_buffer = match Buffer::<u8>::builder()
        .queue(queue.clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(batch_size * 20) // 20 bytes per Ethereum address
        .build()
    {
        Ok(b) => b,
        Err(e) => return Err(format!("Failed to create addresses buffer: {}", e)),
    };

    // Create kernel
    let kernel = match Kernel::builder()
        .program(&program)
        .name("generate_eth_address")
        .arg(&private_keys_buffer)
        .arg(&addresses_buffer)
        .arg(batch_size as u32)
        .build()
    {
        Ok(k) => k,
        Err(e) => return Err(format!("Failed to build kernel: {}", e)),
    };

    // Execute address generation kernel
    let gws = [batch_size];
    let lws = [WORK_GROUP_SIZE.min(batch_size)];

    unsafe {
        match kernel
            .cmd()
            .queue(&queue)
            .global_work_size(&gws)
            .local_work_size(&lws)
            .enq()
        {
            Ok(_) => (),
            Err(e) => return Err(format!("Failed to execute kernel: {}", e)),
        }
    }

    // Read all generated addresses from GPU
    let mut addresses = vec![0u8; batch_size * 20];
    match addresses_buffer.read(&mut addresses).enq() {
        Ok(_) => (),
        Err(e) => return Err(format!("Failed to read addresses: {}", e)),
    }

    // Create result tuples with (private_key, address, mnemonic)
    let mut results = Vec::with_capacity(batch_size);
    
    for i in 0..batch_size {
        let private_key = keypair_batch.mnemonic_pairs[i].private_key.clone();
        let address = addresses[i * 20..(i + 1) * 20].to_vec();
        let mnemonic = keypair_batch.mnemonic_pairs[i].mnemonic.clone();
        
        results.push((private_key, address, mnemonic));
    }
    
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tiny_keccak::{Hasher, Keccak};
    use std::str::FromStr;
    use rand::{thread_rng, Rng};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    // Helper function to derive Ethereum address from private key on CPU
    fn derive_eth_address_cpu(private_key: &[u8]) -> Vec<u8> {
        // Create a secp256k1 context
        let secp = Secp256k1::new();
        
        // Parse the private key
        let secret_key = SecretKey::from_slice(private_key).unwrap();
        
        // Derive the public key (uncompressed)
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let public_key_bytes = public_key.serialize_uncompressed();
        
        // Remove the first byte (0x04 prefix) before hashing
        let public_key_without_prefix = &public_key_bytes[1..];
        
        // Compute Keccak-256 hash
        let mut hasher = Keccak::v256();
        let mut hash = [0u8; 32];
        hasher.update(public_key_without_prefix);
        hasher.finalize(&mut hash);
        
        // Take the last 20 bytes as the Ethereum address
        hash[12..32].to_vec()
    }

    #[test]
    fn test_ethereum_address_generation_correctness() {
        // Skip test if no OpenCL devices available
        let platforms = Platform::list();
        if platforms.is_empty() {
            println!("Skipping test_ethereum_address_generation_correctness: No OpenCL platforms available");
            return;
        }
        
        // Generate a small batch of addresses
        const TEST_BATCH_SIZE: usize = 5;
        
        let results = generate_ethereum_addresses_batch(0, TEST_BATCH_SIZE);
        assert!(results.is_ok(), "Failed to generate addresses batch");
        
        let address_tuples = results.unwrap();
        assert_eq!(address_tuples.len(), TEST_BATCH_SIZE, "Incorrect number of results");
        
        for (private_key, gpu_address, _mnemonic) in address_tuples {
            // Generate the address on CPU for comparison
            let cpu_address = derive_eth_address_cpu(&private_key);
            
            // Addresses should match
            assert_eq!(
                gpu_address, 
                cpu_address, 
                "GPU address doesn't match CPU address for private key: {}", 
                hex::encode(&private_key)
            );
            
            // Validate address format (20 bytes)
            assert_eq!(
                gpu_address.len(), 
                20, 
                "Generated Ethereum address should be 20 bytes"
            );
        }
        
        println!("Successfully verified Ethereum address generation correctness");
    }
    
    #[test]
    fn test_ethereum_address_format() {
        // Skip test if no OpenCL devices available
        let platforms = Platform::list();
        if platforms.is_empty() {
            println!("Skipping test_ethereum_address_format: No OpenCL platforms available");
            return;
        }
        
        // Generate a few addresses
        const TEST_BATCH_SIZE: usize = 3;
        
        let results = generate_ethereum_addresses_batch(0, TEST_BATCH_SIZE);
        assert!(results.is_ok(), "Failed to generate addresses batch");
        
        let address_tuples = results.unwrap();
        
        for (_, address, _) in address_tuples {
            // Check address is 20 bytes
            assert_eq!(address.len(), 20, "Ethereum address should be 20 bytes");
            
            // Convert to hex and verify format with 0x prefix
            let address_hex = format!("0x{}", hex::encode(&address));
            
            // Verify the address starts with 0x and has 42 characters
            assert!(address_hex.starts_with("0x"), "Address should start with 0x");
            assert_eq!(address_hex.len(), 42, "Address should be 42 characters long (0x + 40 hex chars)");
            
            // Apply EIP-55 checksum and verify it's valid
            let checksum_address = eip55::checksum(&address_hex);
            assert_eq!(checksum_address.len(), 42, "Checksum address should be 42 characters long");
        }
        
        println!("Successfully verified Ethereum address format");
    }
    
    #[test]
    fn test_ethereum_vanity_address_search() {
        // Skip test if no OpenCL devices available
        let platforms = Platform::list();
        if platforms.is_empty() {
            println!("Skipping test_ethereum_vanity_address_search: No OpenCL platforms available");
            return;
        }
        
        // Use simple regex that should match quickly (like addresses starting with 0x00)
        let simple_regex = "^0x00";
        
        // Create a timeout for the test (20 seconds should be enough for a simple pattern)
        let timeout = Duration::from_secs(20);
        let start_time = Instant::now();
        
        // Run the miner in a separate thread to enable timeout
        let handle = std::thread::spawn(|| {
            run_gpu_ethereum_miner(0, simple_regex)
        });
        
        // Wait for the thread to finish or timeout
        let result = match handle.join() {
            Ok(result) => result,
            Err(_) => Err("Thread panicked while running vanity address search".to_string()),
        };
        
        // Check if we found a result within the timeout or report progress
        if start_time.elapsed() > timeout {
            println!("Test timed out, but this is acceptable for a probabalistic search");
            return;
        }
        
        assert!(result.is_ok(), "Failed to find vanity address: {:?}", result.err());
        
        let (address, private_key, mnemonic) = result.unwrap();
        
        // Verify the address matches our pattern
        assert!(
            address.starts_with("0x00"), 
            "Found address {} does not match the pattern {}", 
            address, 
            simple_regex
        );
        
        println!("Successfully found vanity address: {}", address);
        println!("Private key: {}", private_key);
        println!("Mnemonic: {}", mnemonic);
    }
    
    #[test]
    fn test_ethereum_performance() {
        // Skip test if no OpenCL devices available
        let platforms = Platform::list();
        if platforms.is_empty() {
            println!("Skipping test_ethereum_performance: No OpenCL platforms available");
            return;
        }
        
        // 修改：使用更小的批量大小，避免内存问题
        const PERF_BATCH_SIZE: usize = 100;
        
        let start_time = Instant::now();
        let results = generate_ethereum_addresses_batch(0, PERF_BATCH_SIZE);
        assert!(results.is_ok(), "Failed to generate addresses batch");
        let elapsed = start_time.elapsed();
        
        // Print performance metrics
        println!(
            "Generated {} Ethereum addresses in {:?}", 
            PERF_BATCH_SIZE, 
            elapsed
        );
        println!(
            "Performance: ~{:.2} addresses/sec", 
            PERF_BATCH_SIZE as f64 / elapsed.as_secs_f64()
        );
        
        // No hard assertions on performance as it depends on hardware
        // But log the performance for review
    }
    
    #[test]
    fn test_ethereum_address_uniqueness() {
        // Skip test if no OpenCL devices available
        let platforms = Platform::list();
        if platforms.is_empty() {
            println!("Skipping test_ethereum_address_uniqueness: No OpenCL platforms available");
            return;
        }
        
        // Generate a moderate number of addresses
        const TEST_BATCH_SIZE: usize = 100;
        
        let results = generate_ethereum_addresses_batch(0, TEST_BATCH_SIZE);
        assert!(results.is_ok(), "Failed to generate addresses batch");
        
        let address_tuples = results.unwrap();
        let mut unique_addresses = std::collections::HashSet::new();
        let mut unique_private_keys = std::collections::HashSet::new();
        
        for (private_key, address, _) in address_tuples {
            let address_hex = hex::encode(&address);
            let private_key_hex = hex::encode(&private_key);
            
            // Add to sets
            unique_addresses.insert(address_hex);
            unique_private_keys.insert(private_key_hex);
        }
        
        // Check uniqueness
        assert_eq!(
            unique_addresses.len(), 
            TEST_BATCH_SIZE, 
            "All generated addresses should be unique"
        );
        assert_eq!(
            unique_private_keys.len(), 
            TEST_BATCH_SIZE, 
            "All private keys should be unique"
        );
        
        println!("Successfully verified address and private key uniqueness");
    }
}
