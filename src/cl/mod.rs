use ocl::{Platform, Device, Context, Queue, Program, Kernel, Buffer};
use ocl::enums::DeviceInfo;
use ocl::flags::{MemFlags, CommandQueueProperties};
use std::path::Path;
use std::fs::read_to_string;
use std::time::Duration;
use rand::{Rng, thread_rng};

const WORK_GROUP_SIZE: usize = 256;
const BATCH_SIZE: usize = 1024 * 256; // Process 256K keys in parallel

pub fn list_platforms_and_devices() {
    let platforms = Platform::list();
    println!("Available OpenCL platforms:");
    
    for (i, platform) in platforms.iter().enumerate() {
        let name = platform.name().unwrap_or_else(|_| String::from("Unknown"));
        let version = platform.version().unwrap_or_else(|_| String::from("Unknown"));
        
        println!("Platform {}: {} ({})", i, name, version);
        
        match Device::list_all(platform) {
            Ok(devices) => {
                for (j, device) in devices.iter().enumerate() {
                    // Fix device info retrieval
                    let device_name = match device.info(DeviceInfo::Name) {
                        Ok(name) => name.to_string(),
                        Err(_) => String::from("Unknown")
                    };
                    
                    let device_type = match device.info(DeviceInfo::Type) {
                        Ok(type_info) => format!("{:?}", type_info),
                        Err(_) => String::from("Unknown")
                    };
                    
                    println!("  Device {}.{}: {} ({})", i, j, device_name, device_type);
                }
            },
            Err(e) => println!("  Error listing devices: {}", e)
        }
    }
}

pub fn run_gpu_ethereum_miner(platform_idx: i32, regex_str: &str) -> Result<(String, String), String> {
    // Load kernel source
    let kernel_path = Path::new("src/cl/eth_kernel.cl");
    let kernel_source = match read_to_string(&kernel_path) {
        Ok(source) => source,
        Err(e) => return Err(format!("Failed to read kernel source: {}", e))
    };

    // Get platform and device - fix the error in platform listing
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
        Err(e) => return Err(format!("Failed to list devices for platform: {}", e))
    };

    if devices.is_empty() {
        return Err("No OpenCL devices available on the selected platform".into());
    }

    let device = devices[0]; // Use the first device
    
    // Fix device info retrieval
    let platform_name = platform.name().unwrap_or_else(|_| String::from("Unknown"));
    let device_name = match device.info(DeviceInfo::Name) {
        Ok(name) => name.to_string(),
        Err(_) => String::from("Unknown")
    };
    
    println!("Using platform: {}", platform_name);
    println!("Using device: {}", device_name);

    // Create context, queue and program
    let context = match Context::builder()
        .platform(platform)
        .devices(device)
        .build() {
            Ok(c) => c,
            Err(e) => return Err(format!("Failed to create OpenCL context: {}", e))
        };

    let queue = match Queue::new(&context, device, Some(CommandQueueProperties::PROFILING_ENABLE)) {
        Ok(q) => q,
        Err(e) => return Err(format!("Failed to create command queue: {}", e))
    };

    let program = match Program::builder()
        .devices(device)
        .src(kernel_source)
        .build(&context) {
            Ok(p) => p,
            Err(e) => return Err(format!("Failed to build program: {}", e))
        };

    // Create buffers
    let private_keys_buffer = match Buffer::<u8>::builder()
        .queue(queue.clone())
        .flags(MemFlags::READ_ONLY)
        .len(BATCH_SIZE * 32) // 32 bytes per private key
        .build() {
            Ok(b) => b,
            Err(e) => return Err(format!("Failed to create private keys buffer: {}", e))
        };

    let addresses_buffer = match Buffer::<u8>::builder()
        .queue(queue.clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(BATCH_SIZE * 20) // 20 bytes per Ethereum address
        .build() {
            Ok(b) => b,
            Err(e) => return Err(format!("Failed to create addresses buffer: {}", e))
        };

    let found_flags_buffer = match Buffer::<u32>::builder()
        .queue(queue.clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(BATCH_SIZE)
        .build() {
            Ok(b) => b,
            Err(e) => return Err(format!("Failed to create found flags buffer: {}", e))
        };

    let found_indices_buffer = match Buffer::<u32>::builder()
        .queue(queue.clone())
        .flags(MemFlags::READ_WRITE)
        .len(1)
        .build() {
            Ok(b) => b,
            Err(e) => return Err(format!("Failed to create found indices buffer: {}", e))
        };

    // Initialize found indices to max value
    // Fix array to vec conversion
    let initial_index = vec![u32::MAX];
    match found_indices_buffer.write(&initial_index).enq() {
        Ok(_) => (),
        Err(e) => return Err(format!("Failed to write to found indices buffer: {}", e))
    }

    // Create a buffer for the regex pattern
    let regex_bytes = regex_str.as_bytes();
    let regex_len = regex_bytes.len();

    let regex_buffer = match Buffer::<u8>::builder()
        .queue(queue.clone())
        .flags(MemFlags::READ_ONLY)
        .len(regex_len)
        .copy_host_slice(regex_bytes)
        .build() {
            Ok(b) => b,
            Err(e) => return Err(format!("Failed to create regex buffer: {}", e))
        };

    // Create kernel
    let kernel = match Kernel::builder()
        .program(&program)
        .name("generate_eth_address")
        .arg(&private_keys_buffer)
        .arg(&addresses_buffer)
        .arg(&found_flags_buffer)
        .arg(&found_indices_buffer)
        .arg(&regex_buffer)
        .arg(regex_len as u32)
        .arg(BATCH_SIZE as u32)
        .build() {
            Ok(k) => k,
            Err(e) => return Err(format!("Failed to build kernel: {}", e))
        };

    println!("OpenCL initialization complete. Starting GPU mining...");
    println!("Looking for addresses matching regex: {}", regex_str);

    let mut found_address = String::new();
    let mut found_private_key = String::new();
    
    let mut rng = thread_rng();
    let mut batch_count = 0;
    let mut private_keys = vec![0u8; BATCH_SIZE * 32];
    let mut addresses = vec![0u8; BATCH_SIZE * 20];
    let mut found_flags = vec![0u32; BATCH_SIZE];
    let mut found_index = vec![u32::MAX]; // Fix: using Vec instead of array

    // Mining loop
    loop {
        batch_count += 1;
        
        // Generate random private keys
        for chunk in private_keys.chunks_mut(32) {
            rng.fill(chunk);
        }

        // Upload private keys to GPU
        match private_keys_buffer.write(&private_keys).enq() {
            Ok(_) => (),
            Err(e) => return Err(format!("Failed to write private keys to GPU: {}", e))
        }

        // Reset found index
        match found_indices_buffer.write(&initial_index).enq() {
            Ok(_) => (),
            Err(e) => return Err(format!("Failed to reset found index: {}", e))
        }

        // Execute kernel
        let gws = [BATCH_SIZE];
        let lws = [WORK_GROUP_SIZE];
        
        unsafe {
            match kernel.cmd()
                .queue(&queue)  // Fix: Explicitly specify the queue
                .global_work_size(&gws)
                .local_work_size(&lws)
                .enq() {
                    Ok(_) => (),
                    Err(e) => return Err(format!("Failed to execute kernel: {}", e))
                }
        }

        // Read results
        match found_indices_buffer.read(&mut found_index).enq() {
            Ok(_) => (),
            Err(e) => return Err(format!("Failed to read found index: {}", e))
        }

        // Check if we found a match
        if found_index[0] != u32::MAX {
            // Read address and private key data
            match addresses_buffer.read(&mut addresses).enq() {
                Ok(_) => (),
                Err(e) => return Err(format!("Failed to read addresses: {}", e))
            }

            let found_idx = found_index[0] as usize;
            let address_slice = &addresses[found_idx * 20..(found_idx + 1) * 20];
            let private_key_slice = &private_keys[found_idx * 32..(found_idx + 1) * 32];

            // Convert address and private key to hexadecimal
            found_address = format!("0x{}", hex::encode(address_slice));
            found_private_key = hex::encode(private_key_slice);

            println!("Found matching address after {} batches!", batch_count);
            println!("Address: {}", found_address);
            
            break;
        }

        // Print status every 10 batches
        if batch_count % 10 == 0 {
            println!("Processed {} batches ({} addresses)...", 
                batch_count, batch_count * BATCH_SIZE);
        }

        // Brief pause to avoid hogging the CPU
        std::thread::sleep(Duration::from_millis(1));
    }

    Ok((found_address, found_private_key))
}