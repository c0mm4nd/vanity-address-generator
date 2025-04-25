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
            } else {
                println!(
                    "No match for address {}: {}",
                    regex_str,
                    address_hex
                );
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
