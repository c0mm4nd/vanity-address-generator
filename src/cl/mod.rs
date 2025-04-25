pub mod common;
pub mod common_gpu;
pub mod ethereum;
pub mod solana;
pub mod tron;

use ocl::enums::DeviceInfo;
use ocl::Platform;
use ocl::Device;

pub use common::generate_random_mnemonic_keypair;
// Export GPU accelerated functions
pub use common_gpu::{generate_random_mnemonic_keypair_batch as generate_gpu_mnemonic_keypair_batch};

// Re-export the GPU miner functions for convenience
pub use ethereum::run_gpu_ethereum_miner;
pub use solana::run_gpu_solana_miner;
pub use tron::run_gpu_tron_miner;

// List all available OpenCL platforms and devices
pub fn list_platforms_and_devices() {
    println!("Available OpenCL platforms and devices:");

    let platforms = Platform::list();
    if platforms.is_empty() {
        println!("  No OpenCL platforms found");
        return;
    }

    for (i, platform) in platforms.iter().enumerate() {
        let platform_name = match platform.name() {
            Ok(name) => name,
            Err(_) => String::from("Unknown"),
        };

        println!("Platform {}: {}", i, platform_name);

        let devices = match Device::list_all(platform) {
            Ok(devs) => devs,
            Err(_) => {
                println!("  Failed to list devices for this platform");
                continue;
            }
        };

        if devices.is_empty() {
            println!("  No devices found for this platform");
            continue;
        }

        for (j, device) in devices.iter().enumerate() {
            let device_name = match device.info(DeviceInfo::Name) {
                Ok(name) => name.to_string(),
                Err(_) => String::from("Unknown"),
            };

            let device_type = match device.info(DeviceInfo::Type) {
                Ok(type_info) => format!("{:?}", type_info),
                Err(_) => String::from("Unknown"),
            };

            println!("  Device {}.{}: {} ({})", i, j, device_name, device_type);
        }
    }
}


