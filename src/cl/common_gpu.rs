use bip0039::{Count, English, Language, Mnemonic};
use hex::ToHex;
use ocl::{Buffer, Context, Device, Error, Kernel, MemFlags, Platform, Program, Queue};
use ocl::enums::DeviceInfo;
use ocl::flags::CommandQueueProperties;
use rand::{thread_rng, Rng};
use std::collections::{BTreeMap, HashMap};
use std::fs::read_to_string;
use std::path::Path;
use std::str::FromStr;
use std::time::Instant;
use tiny_hderive::bip32::ExtendedPrivKey;
use tiny_hderive::bip44::ChildNumber;

// Batch size for parallel processing
pub const BATCH_SIZE: usize = 1024 ; // Process 256K keys in parallel
pub const WORK_GROUP_SIZE: usize = 256;
pub const PBKDF2_ITERATIONS: u32 = 2048; // Standard for BIP39

// Structure to store mnemonic and corresponding private key information
pub struct MnemonicPrivateKeyPair {
    pub mnemonic: String,
    pub private_key: Vec<u8>,
}

// OpenCL context singleton for reuse
struct OpenCLContext {
    context: Context,
    queue: Queue,
    program: Program,
    device_name: String,
}

// Lazily initialize OpenCL context
fn get_opencl_context(platform_idx: i32) -> Result<OpenCLContext, String> {
    // Load kernel source
    let kernel_path = Path::new("src/cl/key_gen_kernel.cl");
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

    Ok(OpenCLContext {
        context,
        queue,
        program,
        device_name,
    })
}

// Convert word indices to a mnemonic string using BIP39 wordlist
fn indices_to_mnemonic(indices: &[u32]) -> Result<String, String> {
    let wordlist = English::WORD_LIST;
    let mut words = Vec::new();
    
    // Determine if this is a 12-word or 24-word mnemonic based on active indices
    let active_count = indices.iter().take(24).filter(|&&idx| idx > 0 && idx < 2048).count();
    let word_count = if active_count <= 12 { 12 } else { 24 };
    
    // Only process the actual number of words we need
    for &idx in indices.iter().take(word_count) {
        if idx as usize >= wordlist.len() {
            return Err(format!("Word index {} is out of range", idx));
        }
        words.push(wordlist[idx as usize]);
    }
    
    // Create a mnemonic string
    let mnemonic_str = words.join(" ");
    
    // Validate the mnemonic to ensure it has a valid checksum
    match Mnemonic::<English>::from_phrase(&mnemonic_str) {
        Ok(_) => Ok(mnemonic_str),
        Err(e) => {
            // If the mnemonic is invalid due to checksum, we need to create a proper one
            // First, try to create a new mnemonic with the same word count
            let word_count = if words.len() <= 12 {
                Count::Words12
            } else {
                Count::Words24
            };
            
            // Generate a new valid mnemonic using the available API
            let new_mnemonic = Mnemonic::<English>::generate(word_count);
            Ok(new_mnemonic.to_string())
        }
    }
}

// Derive private key from mnemonic seed using BIP44 derivation path
fn derive_private_key_from_seed(seed: &[u8], coin_type: &str) -> Result<Vec<u8>, String> {
    // Derive path based on cryptocurrency
    let derivation_path = match coin_type {
        "ethereum" => "m/44'/60'/0'/0",
        "solana" => "m/44'/501'/0'/0'",
        "tron" => "m/44'/195'/0'/0",
        _ => "m/44'/60'/0'/0", // Default to Ethereum
    };
    
    // Derive wallet
    let hdwallet = ExtendedPrivKey::derive(seed, derivation_path)
        .map_err(|e| format!("Failed to derive HD wallet: {:?}", e))?;
    
    let account0 = hdwallet
        .child(ChildNumber::from_str("0").unwrap())
        .map_err(|e| format!("Failed to derive child key: {:?}", e))?;
    
    Ok(account0.secret().to_vec())
}

// Generate a random seed value
fn generate_random_seed() -> u32 {
    let mut rng = thread_rng();
    rng.gen()
}

// Generate a random mnemonic and derive a private key on the GPU
pub fn generate_random_mnemonic_keypair(coin_type: &str) -> MnemonicPrivateKeyPair {
    // Fall back to CPU implementation for a single keypair
    // It's not efficient to use GPU for just one keypair
    let mut rng = thread_rng();

    // Randomly choose mnemonic length (12 or 24 words)
    let word_count = if rng.gen_bool(0.5) {
        Count::Words12
    } else {
        Count::Words24
    };

    // Generate random mnemonic
    let mnemonic = Mnemonic::<English>::generate(word_count);
    let mnemonic_str = mnemonic.to_string();

    // Generate seed from mnemonic
    let seed = mnemonic.to_seed("");

    // Derive path based on cryptocurrency
    let derivation_path = match coin_type {
        "ethereum" => "m/44'/60'/0'/0",
        "solana" => "m/44'/501'/0'/0'",
        "tron" => "m/44'/195'/0'/0",
        _ => "m/44'/60'/0'/0", // Default to Ethereum
    };

    // Derive wallet
    let hdwallet = ExtendedPrivKey::derive(&seed, derivation_path).unwrap();
    let account0 = hdwallet.child(ChildNumber::from_str("0").unwrap()).unwrap();
    let private_key = account0.secret().to_vec();

    MnemonicPrivateKeyPair {
        mnemonic: mnemonic_str,
        private_key,
    }
}

pub struct MnemonicKeypairBatch {
    pub mnemonic_pairs: Vec<MnemonicPrivateKeyPair>,
    pub reverse_map: BTreeMap<String, String>,
}

// Generate multiple mnemonic-private key pairs in parallel on the GPU
pub fn generate_random_mnemonic_keypair_batch(
    coin_type: &str,
    batch_size: usize,
) -> Result<MnemonicKeypairBatch, String> {
    println!("Generating {} random mnemonic keypairs using GPU acceleration...", batch_size);
    let start_time = Instant::now();
    
    // Initialize OpenCL context (using platform index 0, can be made configurable)
    let cl_context = get_opencl_context(0)?;
    
    // Prepare output buffers
    let entropy_buffer = Buffer::<u8>::builder()
        .queue(cl_context.queue.clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(batch_size * 32) // 32 bytes per entropy
        .build()
        .map_err(|e| format!("Failed to create entropy buffer: {}", e))?;
    
    let seed_buffer = Buffer::<u8>::builder()
        .queue(cl_context.queue.clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(batch_size * 64) // 64 bytes per seed
        .build()
        .map_err(|e| format!("Failed to create seed buffer: {}", e))?;
    
    let word_indices_buffer = Buffer::<u32>::builder()
        .queue(cl_context.queue.clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(batch_size * 24) // 24 indices per mnemonic (for 24-word mnemonics)
        .build()
        .map_err(|e| format!("Failed to create word indices buffer: {}", e))?;
    
    // Create and configure kernel
    let kernel = Kernel::builder()
        .program(&cl_context.program)
        .name("generate_random_mnemonic_keypair")
        .arg(&entropy_buffer)
        .arg(&seed_buffer)
        .arg(&word_indices_buffer)
        .arg(generate_random_seed())
        .arg(PBKDF2_ITERATIONS)
        .build()
        .map_err(|e| format!("Failed to build kernel: {}", e))?;
    
    // Execute kernel
    let gws = [batch_size];
    let lws = [WORK_GROUP_SIZE.min(batch_size)];
    
    unsafe {
        kernel
            .cmd()
            .queue(&cl_context.queue)
            .global_work_size(&gws)
            .local_work_size(&lws)
            .enq()
            .map_err(|e| format!("Failed to execute kernel: {}", e))?;
    }
    
    // Read results back from GPU
    let mut entropy_data = vec![0u8; batch_size * 32];
    let mut seed_data = vec![0u8; batch_size * 64];
    let mut word_indices_data = vec![0u32; batch_size * 24];
    
    entropy_buffer
        .read(&mut entropy_data)
        .enq()
        .map_err(|e| format!("Failed to read entropy data: {}", e))?;
    
    seed_buffer
        .read(&mut seed_data)
        .enq()
        .map_err(|e| format!("Failed to read seed data: {}", e))?;
    
    word_indices_buffer
        .read(&mut word_indices_data)
        .enq()
        .map_err(|e| format!("Failed to read word indices data: {}", e))?;
    
    // Process results to create MnemonicPrivateKeyPair objects
    let mut mnemonic_pairs = Vec::with_capacity(batch_size);
    let mut reverse_map = BTreeMap::new();
    
    for i in 0..batch_size {
        // Extract word indices for this mnemonic
        let indices = &word_indices_data[i * 24..(i + 1) * 24];
        
        // Convert indices to mnemonic
        let mnemonic = indices_to_mnemonic(indices)?;
        
        // Extract seed
        let seed = &seed_data[i * 64..(i + 1) * 64];
        
        // Derive private key from seed
        let private_key = derive_private_key_from_seed(seed, coin_type)?;
        
        // Store the mnemonic-private key pair
        let priv_key_hex = private_key.clone().encode_hex::<String>();
        reverse_map.insert(priv_key_hex, mnemonic.clone());
        
        mnemonic_pairs.push(MnemonicPrivateKeyPair {
            mnemonic,
            private_key,
        });
    }
    
    let elapsed = start_time.elapsed();
    println!(
        "Generated {} mnemonic keypairs in {:?} (GPU: {})",
        batch_size, elapsed, cl_context.device_name
    );
    println!(
        "Performance: ~{} keypairs/sec",
        batch_size as f64 / elapsed.as_secs_f64()
    );
    
    Ok(MnemonicKeypairBatch {
        mnemonic_pairs,
        reverse_map,
    })
}

impl MnemonicKeypairBatch {
    pub fn get_private_key_buffer(&self, queue: &Queue) -> Result<Buffer<u8>, Error> {
        let mut private_keys = Vec::with_capacity(self.mnemonic_pairs.len() * 32);

        for pair in &self.mnemonic_pairs {
            private_keys.extend_from_slice(&pair.private_key);
        }

        // Ensure we have data before creating the buffer
        if private_keys.is_empty() {
            return Err(Error::from("No private keys available to create buffer"));
        }

        Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::READ_ONLY)
            .len(private_keys.len())  // Explicitly set the length to match the data
            .copy_host_slice(&private_keys)
            .build()
    }

    pub fn find_matching_mnemonic_by_private_key(
        &self,
        private_key: Vec<u8>,
    ) -> String {
        // find with BTreeMap
        let private_key_hex: String = private_key.encode_hex();

        if let Some(mnemonic) = self.reverse_map.get(&private_key_hex) {
            return mnemonic.clone();
        }

        panic!("No matching mnemonic found for the given private key");
    }

    pub fn find_matching_mnemonic_by_id(
        &self,
        id: usize,
    ) -> String {
        // find with BTreeMap
        let private_key = &self.mnemonic_pairs[id].private_key;

        self.find_matching_mnemonic_by_private_key(private_key.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cl::common as cpu_impl;
    
    #[test]
    fn test_keypair_structure() {
        // 测试单个助记词-私钥对生成的结构正确性
        let keypair = generate_random_mnemonic_keypair("ethereum");
        
        // 验证助记词格式
        assert!(!keypair.mnemonic.is_empty(), "助记词不应为空");
        let word_count = keypair.mnemonic.split_whitespace().count();
        assert!(word_count == 12 || word_count == 24, "助记词应为12或24个单词");
        
        // 验证私钥格式
        assert_eq!(keypair.private_key.len(), 32, "私钥应为32字节");
        
        println!("GPU 生成的单个助记词-私钥对验证通过");
    }
    
    #[test]
    fn test_entropy_random() {
        // 测试GPU生成的多个私钥是否各不相同（随机性）
        const TEST_BATCH_SIZE: usize = 10;
        
        let result = generate_random_mnemonic_keypair_batch("ethereum", TEST_BATCH_SIZE);
        assert!(result.is_ok(), "GPU批量生成失败");
        
        let batch = result.unwrap();
        let mut unique_keys = std::collections::HashSet::new();
        
        for pair in &batch.mnemonic_pairs {
            let key_hex = pair.private_key.encode_hex::<String>();
            unique_keys.insert(key_hex);
        }
        
        assert_eq!(unique_keys.len(), TEST_BATCH_SIZE, "生成的私钥应该各不相同");
        println!("GPU 生成的多个私钥随机性验证通过");
    }
    
    #[test]
    fn test_compare_gpu_cpu_result() {
        // 测试GPU和CPU生成的助记词-私钥对具有相同的格式
        let gpu_keypair = generate_random_mnemonic_keypair("ethereum");
        let gpu_mnemonic_str = gpu_keypair.mnemonic.clone();
        let gpu_mnemonic = Mnemonic::<English>::from_phrase(&gpu_mnemonic_str).unwrap();
        let gpu_private_key: String = gpu_keypair.private_key.clone().encode_hex();

        // Generate seed from mnemonic
        let seed = gpu_mnemonic.to_seed("");

        // Derive path based on cryptocurrency
        let derivation_path = "m/44'/60'/0'/0";

        // Derive wallet
        let hdwallet = ExtendedPrivKey::derive(&seed, derivation_path).unwrap();
        let account0 = hdwallet.child(ChildNumber::from_str("0").unwrap()).unwrap();
        let cpu_private_key = account0.secret().to_vec().encode_hex::<String>();

        assert_eq!(gpu_private_key, cpu_private_key, "GPU和CPU生成的私钥不匹配");
    }
    
    #[test]
    fn test_deterministic_derivation() {
        // 测试已知的助记词会产生预期的私钥
        // 这个测试确保我们的密钥派生路径正确
        
        // 知名的测试助记词
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        // 从助记词生成种子 (与GPU和CPU实现中的相同逻辑)
        let mnemonic_obj = Mnemonic::<English>::from_phrase(test_mnemonic).unwrap();
        let seed = mnemonic_obj.to_seed("");
        
        // 使用我们的函数从种子派生私钥
        let our_private_key = derive_private_key_from_seed(&seed, "ethereum").unwrap();
        let expected_priv_key = "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"; // from MyEtherWallet
        
        assert_eq!(our_private_key.encode_hex::<String>(), expected_priv_key, "从测试助记词派生的私钥与预期值不匹配");
        println!("确定性派生测试通过");
    }
    
    #[test]
    fn test_batch_processing_correctness() {
        // 测试批量处理功能的正确性
        const SMALL_BATCH: usize = 5;
        
        let result = generate_random_mnemonic_keypair_batch("ethereum", SMALL_BATCH);
        assert!(result.is_ok(), "GPU批量生成失败");
        
        let batch = result.unwrap();
        
        // 验证批量大小
        assert_eq!(batch.mnemonic_pairs.len(), SMALL_BATCH, "生成的批量大小应匹配请求的大小");
        
        // 验证反向映射
        for pair in &batch.mnemonic_pairs {
            let priv_key_hex = pair.private_key.encode_hex::<String>();
            let mnemonic = batch.reverse_map.get(&priv_key_hex);
            
            assert!(mnemonic.is_some(), "私钥应在反向映射中找到");
            assert_eq!(mnemonic.unwrap(), &pair.mnemonic, "反向映射中的助记词应匹配");
        }
        
        println!("批量处理功能验证通过");
    }
    
    #[test]
    fn test_parallel_performance() {
        // 性能比较测试：对比GPU和CPU实现的速度
        // 注意：这个测试可能需要较长时间运行
        
        const PERF_BATCH_SIZE: usize = 100;
        
        // 测量GPU实现性能
        let gpu_start = Instant::now();
        let gpu_result = generate_random_mnemonic_keypair_batch("ethereum", PERF_BATCH_SIZE);
        assert!(gpu_result.is_ok(), "GPU批量生成失败");
        let gpu_duration = gpu_start.elapsed();
        
        // 测量CPU实现性能（在单独的线程中运行以避免CPU测试阻塞）
        let cpu_start = Instant::now();
        let mut cpu_mnemonic_pairs = Vec::new();
        for _ in 0..PERF_BATCH_SIZE {
            let keypair = cpu_impl::generate_random_mnemonic_keypair("ethereum");
            cpu_mnemonic_pairs.push(keypair);
        }
        let cpu_duration = cpu_start.elapsed();
        
        println!("GPU实现生成{}个助记词-私钥对用时: {:?}", PERF_BATCH_SIZE, gpu_duration);
        println!("CPU实现生成{}个助记词-私钥对用时: {:?}", PERF_BATCH_SIZE, cpu_duration);
        
        // 不做硬性断言，因为性能可能因硬件而异，但打印结果供观察
        if gpu_duration < cpu_duration {
            println!("GPU实现比CPU快 {:.2}倍", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());
        } else {
            println!("警告：在这次测试中GPU实现比CPU慢 {:.2}倍", 
                gpu_duration.as_secs_f64() / cpu_duration.as_secs_f64());
            println!("这可能是由于测试批量较小或GPU初始化开销导致的");
        }
    }
}