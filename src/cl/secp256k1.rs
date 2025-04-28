"""// src/cl/secp256k1.rs
use ocl::{Buffer, Context, Device, Kernel, Platform, Program, Queue};
use ocl::enums::DeviceType;
use ocl::error::Error as OclError;
use std::fs;
use std::path::Path;

// Basic error handling for simplicity
#[derive(Debug)]
pub enum GpuError {
    Ocl(OclError),
    Io(std::io::Error),
    Msg(String),
}

impl From<OclError> for GpuError {
    fn from(err: OclError) -> Self {
        GpuError::Ocl(err)
    }
}

impl From<std::io::Error> for GpuError {
    fn from(err: std::io::Error) -> Self {
        GpuError::Io(err)
    }
}

pub struct Secp256k1GpuContext {
    _platform: Platform, // Keep platform alive
    _device: Device,     // Keep device alive
    context: Context,
    queue: Queue,
    program: Program,
}

impl Secp256k1GpuContext {
    pub fn new(kernel_path: &Path) -> Result<Self, GpuError> {
        let platform = Platform::default();
        // Prefer GPU, fallback to CPU if necessary or handle error
        let device_type = Some(DeviceType::GPU); // Or allow selection/fallback
        let devices = Device::list(platform, device_type)?;
        let device = devices.into_iter().next()
            .ok_or_else(|| GpuError::Msg(format!("No {:?} device found", device_type.unwrap_or(DeviceType::ALL))))?;

        println!("Using OpenCL device: {}", device.name()?);


        let context = Context::builder()
            .platform(platform)
            .devices(device)
            .build()?;

        let queue = Queue::new(&context, device, None)?;

        let kernel_source = fs::read_to_string(kernel_path)?;

        let program = Program::builder()
            .src(kernel_source)
            .devices(device) // Pass the single selected device
            .build(&context)?;

        Ok(Secp256k1GpuContext {
            _platform: platform,
            _device: device,
            context,
            queue,
            program,
        })
    }

    /// Generates public keys from private keys on the GPU.
    ///
    /// # Arguments
    ///
    /// * `private_keys` - A byte slice where each 32-byte chunk represents a private key.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `Vec<u8>` where each 65-byte chunk represents an
    /// uncompressed public key, or a `GpuError`.
    pub fn generate_keys(&self, private_keys: &[u8]) -> Result<Vec<u8>, GpuError> {
        let num_keys = private_keys.len() / 32; // Assuming 32 bytes per private key
        if num_keys == 0 || private_keys.len() % 32 != 0 {
            return Err(GpuError::Msg(format!(
                "Invalid private key data length: {}. Must be a multiple of 32.",
                private_keys.len()
            )));
        }
        println!("Preparing to generate {} keys on GPU...", num_keys);


        // Create input buffer for private keys
        // Using MEM_USE_HOST_PTR might be faster if the driver supports it well,
        // but MEM_COPY_HOST_PTR is generally safer.
        let priv_key_buffer: Buffer<u8> = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY | ocl::flags::MEM_COPY_HOST_PTR)
            .len(private_keys.len())
            .copy_host_slice(private_keys)
            .build()?;
        println!("Private key buffer created ({} bytes).", private_keys.len());


        // Create output buffer for public keys (assuming 65 bytes per uncompressed key)
        let pub_key_len = num_keys * 65;
        let pub_key_buffer: Buffer<u8> = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_WRITE_ONLY) // Kernel only writes
            .len(pub_key_len)
            .build()?;
        println!("Public key buffer created ({} bytes).", pub_key_len);


        // Create the kernel
        let kernel = Kernel::builder()
            .program(&self.program)
            .name("generate_public_keys")
            .queue(self.queue.clone())
            .global_work_size(num_keys) // One work item per key
            // .local_work_size(??) // Optional: Tune for performance
            .arg(&priv_key_buffer)
            .arg(&pub_key_buffer)
            .arg(num_keys as u32) // Pass num_keys as uint
            .build()?;
        println!("Kernel built: generate_public_keys");


        // Execute the kernel
        println!("Enqueuing kernel...");
        unsafe {
            kernel.enq()?;
        }
        println!("Kernel enqueued.");


        // Read results back from the GPU
        let mut public_keys_vec = vec![0u8; pub_key_len];
        println!("Reading results from GPU...");
        // This is a blocking read by default.
        pub_key_buffer.read(&mut public_keys_vec).enq()?;
        println!("Results read back ({} bytes).", public_keys_vec.len());


        Ok(public_keys_vec)
    }
}

// Example usage function (can be called from main.rs or tests)
#[allow(dead_code)] // Allow this function even if not called directly in this file
pub fn run_gpu_key_gen_example() -> Result<(), GpuError> {
    println!("Starting GPU key generation example...");
    let kernel_path = Path::new("src/cl/secp256k1_kernel.cl");
    if !kernel_path.exists() {
        return Err(GpuError::Msg(format!("Kernel file not found: {:?}", kernel_path)));
    }
    println!("Kernel path: {:?}", kernel_path);


    let gpu_context = Secp256k1GpuContext::new(kernel_path)?;
    println!("GPU context created.");


    // Example: Generate 10 private keys (replace with actual random keys)
    let num_example_keys = 10;
    let mut private_keys = Vec::with_capacity(num_example_keys * 32);
    for i in 0..num_example_keys {
        let mut key = [0u8; 32];
        // **WARNING: THESE ARE NOT SECURE PRIVATE KEYS. USE A PROPER CSPRNG.**
        key[31] = i + 1; // Just to make them slightly different
        private_keys.extend_from_slice(&key);
    }
    println!("Generated {} dummy private keys.", num_example_keys);


    println!("Calling generate_keys...");
    let public_keys = gpu_context.generate_keys(&private_keys)?;
    println!("GPU key generation finished.");
    println!("Generated {} public keys ({} bytes total).", public_keys.len() / 65, public_keys.len());


    // Process the public_keys vector...
    // (e.g., print the first few bytes of each key)
    for i in 0..num_example_keys {
         // Ensure we don't panic if the returned data is shorter than expected
        let start = i * 65;
        let end = start + 65;
        if end <= public_keys.len() {
            let key_slice = &public_keys[start..end];
             println!("Public Key {}: {:02x}{:02x}{:02x}{:02x}...",
                i,
                key_slice[0], // Should be 0x04 for uncompressed
                key_slice[1],
                key_slice[2],
                key_slice[3]
            );
        } else {
             eprintln!("Warning: Public key data seems truncated for key index {}", i);
        }
    }


    println!("GPU key generation example finished successfully.");
    Ok(())
}
""