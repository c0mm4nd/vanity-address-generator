// Random key generation kernel for vanity address generation
// This kernel focuses on efficient random private key generation

// BIP39 mnemonic generation related constants and structures
#define BIP39_ENTROPY_LEN_128 16  // 128 bits = 16 bytes
#define BIP39_ENTROPY_LEN_256 32  // 256 bits = 32 bytes
#define BIP39_CHECKSUM_BITS_128 4 // 4 bits for 128-bit entropy
#define BIP39_CHECKSUM_BITS_256 8 // 8 bits for 256-bit entropy
#define BIP39_WORD_COUNT_12 12    // Number of words for 128-bit entropy
#define BIP39_WORD_COUNT_24 24    // Number of words for 256-bit entropy

// SHA-256 Constants
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

// Forward declarations for Metal compatibility
void sha256_transform(uint state[8], const uint block[16]);
void sha256(const uchar *data, uint len, uchar digest[32]);
void hmac_sha256(const uchar *key, uint key_len, const uchar *message, uint message_len, uchar output[32]);
void pbkdf2_hmac_sha256(const uchar *password, uint password_len, 
                       const uchar *salt, uint salt_len,
                       uint iterations, uchar *output, uint output_len);
void bip39_append_checksum(uchar *entropy, uint entropy_len, uint *entropy_with_checksum);
uint wang_hash(uint seed);
uint lcg_rand(uint *state);
uint xorshift_rand32(uint state[4]);
uchar xorshift_rand_byte(uint state[4]);

__constant uint k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// SHA-256 helper macros
#define rotr(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define sigma0(x) (rotr(x, 7) ^ rotr(x, 18) ^ ((x) >> 3))
#define sigma1(x) (rotr(x, 17) ^ rotr(x, 19) ^ ((x) >> 10))
#define Sigma0(x) (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))
#define Sigma1(x) (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25))
#define ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

// Wang Hash function - simple non-cryptographic hash for seed transformation
uint wang_hash(uint seed) {
    seed = (seed ^ 61) ^ (seed >> 16);
    seed *= 9;
    seed = seed ^ (seed >> 4);
    seed *= 0x27d4eb2d;
    seed = seed ^ (seed >> 15);
    return seed;
}

// Linear Congruential Generator for simple random number generation
uint lcg_rand(uint *state) {
    const uint a = 1664525;
    const uint c = 1013904223;
    *state = (*state) * a + c;
    return *state;
}

// Improved random number generation using 32-bit Xorshift
// Metal-compatible implementation (no ulong)
void xorshift_init(uint state[4], uint seed) {
    // Initialize with wang_hash for better distribution
    state[0] = wang_hash(seed);
    state[1] = wang_hash(state[0] + seed);
    state[2] = wang_hash(state[1] + seed);
    state[3] = wang_hash(state[2] + seed);
    
    // Ensure states are not all zeros
    if (state[0] == 0 && state[1] == 0 && state[2] == 0 && state[3] == 0) {
        state[0] = 0x853c49e6;
        state[1] = 0x748fea9b;
        state[2] = 0xda3e39cb;
        state[3] = 0x94b95bdb;
    }
    
    // Warm up the generator
    for (int i = 0; i < 16; i++) {
        uint t = state[0] ^ (state[0] << 11);
        state[0] = state[1];
        state[1] = state[2];
        state[2] = state[3];
        state[3] = state[3] ^ (state[3] >> 19) ^ t ^ (t >> 8);
    }
}

// Get next random value from Xorshift
void xorshift_next(uint state[4]) {
    uint t = state[0] ^ (state[0] << 11);
    state[0] = state[1];
    state[1] = state[2];
    state[2] = state[3];
    state[3] = state[3] ^ (state[3] >> 19) ^ t ^ (t >> 8);
}

// Get a random 32-bit unsigned integer
uint xorshift_rand32(uint state[4]) {
    xorshift_next(state);
    return state[3];
}

// Get a random byte (0-255)
uchar xorshift_rand_byte(uint state[4]) {
    return (uchar)(xorshift_rand32(state) & 0xFF);
}

// SHA-256 transform function
void sha256_transform(uint state[8], const uint block[16]) {
    uint a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    // Prepare message schedule
    for (i = 0, j = 0; i < 16; i++) {
        m[i] = block[i];
    }
    
    for (i = 16; i < 64; i++) {
        m[i] = sigma1(m[i - 2]) + m[i - 7] + sigma0(m[i - 15]) + m[i - 16];
    }

    // Initialize working variables
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    // Main loop
    for (i = 0; i < 64; i++) {
        t1 = h + Sigma1(e) + ch(e, f, g) + k[i] + m[i];
        t2 = Sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Add the compressed chunk to the current hash value
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

// SHA-256 hash function
void sha256(const uchar *data, uint len, uchar digest[32]) {
    uint state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    uint block[16];
    uint i, j;
    uint bytesProcessed = 0;
    
    // Process full blocks
    while (bytesProcessed + 64 <= len) {
        for (i = 0, j = 0; i < 16; i++, j += 4) {
            block[i] = ((uint)data[bytesProcessed + j] << 24) |
                      ((uint)data[bytesProcessed + j + 1] << 16) |
                      ((uint)data[bytesProcessed + j + 2] << 8) |
                      ((uint)data[bytesProcessed + j + 3]);
        }
        
        sha256_transform(state, block);
        bytesProcessed += 64;
    }
    
    // Final block with padding
    for (i = 0; i < 16; i++) {
        block[i] = 0;
    }
    
    // Copy remaining bytes
    for (i = 0; bytesProcessed < len; i++, bytesProcessed++) {
        block[i / 4] |= (uint)data[bytesProcessed] << (24 - (i % 4) * 8);
    }
    
    // Append 1 bit
    block[i / 4] |= 0x80 << (24 - (i % 4) * 8);
    
    // If there isn't enough space for the length, process this block and prepare another one
    if (i >= 56) {
        sha256_transform(state, block);
        for (i = 0; i < 16; i++) {
            block[i] = 0;
        }
    }
    
    // Append length in bits
    uint bitlen = len * 8;
    block[15] = bitlen;
    
    // Process the final block
    sha256_transform(state, block);
    
    // Output digest
    for (i = 0; i < 8; i++) {
        digest[i * 4] = (uchar)((state[i] >> 24) & 0xFF);
        digest[i * 4 + 1] = (uchar)((state[i] >> 16) & 0xFF);
        digest[i * 4 + 2] = (uchar)((state[i] >> 8) & 0xFF);
        digest[i * 4 + 3] = (uchar)(state[i] & 0xFF);
    }
}

// HMAC-SHA256 implementation
void hmac_sha256(const uchar *key, uint key_len, const uchar *message, uint message_len, uchar output[32]) {
    uchar k[64] = {0};
    uchar inner_padding[64];
    uchar outer_padding[64];
    
    // Prepare the key
    if (key_len > 64) {
        sha256(key, key_len, k);
        key_len = 32;
    } else {
        for (uint i = 0; i < key_len; i++) {
            k[i] = key[i];
        }
    }
    
    // Create paddings
    for (uint i = 0; i < 64; i++) {
        inner_padding[i] = 0x36 ^ k[i];
        outer_padding[i] = 0x5c ^ k[i];
    }
    
    // Inner hash
    uchar inner_hash[32];
    uchar temp[64 + 1024]; // Assuming message_len is less than 1024
    
    for (uint i = 0; i < 64; i++) {
        temp[i] = inner_padding[i];
    }
    
    for (uint i = 0; i < message_len; i++) {
        temp[64 + i] = message[i];
    }
    
    sha256(temp, 64 + message_len, inner_hash);
    
    // Outer hash
    for (uint i = 0; i < 64; i++) {
        temp[i] = outer_padding[i];
    }
    
    for (uint i = 0; i < 32; i++) {
        temp[64 + i] = inner_hash[i];
    }
    
    sha256(temp, 64 + 32, output);
}

// PBKDF2-HMAC-SHA256 implementation (simplified for this purpose)
void pbkdf2_hmac_sha256(const uchar *password, uint password_len, 
                       const uchar *salt, uint salt_len,
                       uint iterations, uchar *output, uint output_len) {
    uchar u[32];
    uchar temp[128]; // Assuming salt_len + 4 is less than 128
    uint block_count = (output_len + 31) / 32;
    
    for (uint i = 1; i <= block_count; i++) {
        // Create salt || INT_32_BE(i)
        for (uint j = 0; j < salt_len; j++) {
            temp[j] = salt[j];
        }
        
        // Append block index in big-endian format
        temp[salt_len] = (uchar)((i >> 24) & 0xFF);
        temp[salt_len + 1] = (uchar)((i >> 16) & 0xFF);
        temp[salt_len + 2] = (uchar)((i >> 8) & 0xFF);
        temp[salt_len + 3] = (uchar)(i & 0xFF);
        
        // First iteration
        hmac_sha256(password, password_len, temp, salt_len + 4, u);
        
        for (uint j = 0; j < 32; j++) {
            output[(i - 1) * 32 + j] = u[j];
        }
        
        // Remaining iterations
        for (uint j = 1; j < iterations; j++) {
            hmac_sha256(password, password_len, u, 32, u);
            
            for (uint k = 0; k < 32 && (i - 1) * 32 + k < output_len; k++) {
                output[(i - 1) * 32 + k] ^= u[k];
            }
        }
    }
}

// Calculate BIP39 checksum and append to the entropy
void bip39_append_checksum(uchar *entropy, uint entropy_len, uint *entropy_with_checksum) {
    uchar hash[32];
    sha256(entropy, entropy_len, hash);
    
    // The checksum is the first (entropy_len / 32) bits of the hash
    uint checksum_byte = hash[0];
    uint checksum_bits = entropy_len / 4; // Number of checksum bits
    
    // Prepare entropy with checksum
    uint bytes_to_copy = (entropy_len + (checksum_bits + 7) / 8 + 3) / 4;
    for (uint i = 0; i < bytes_to_copy; i++) {
        entropy_with_checksum[i] = 0;
    }
    
    // Copy entropy bytes
    for (uint i = 0; i < entropy_len; i++) {
        uint byte_index = i / 4;
        uint bit_position = 24 - (i % 4) * 8;
        entropy_with_checksum[byte_index] |= ((uint)entropy[i]) << bit_position;
    }
    
    // Append checksum
    uint last_byte_index = entropy_len / 4;
    uint last_bit_position = 24 - (entropy_len % 4) * 8;
    entropy_with_checksum[last_byte_index] |= (checksum_byte >> (8 - checksum_bits)) << (last_bit_position - checksum_bits);
}

// Main kernel function to generate random mnemonic keypair
__kernel void generate_random_mnemonic_keypair(
    __global uchar *entropy_output,        // Output buffer for entropy (32 bytes per entropy)
    __global uchar *seed_output,           // Output buffer for seed (64 bytes per seed)
    __global uint *word_indices_output,    // Output buffer for word indices (24 indices per mnemonic)
    uint seed_value,                       // Random seed value
    uint num_iterations                    // Number of iterations for PBKDF2
) {
    uint id = get_global_id(0);
    
    // Initialize xorshift RNG state with unique seed per thread
    uint rng_state[4];
    xorshift_init(rng_state, seed_value + id + get_global_id(1) * 0x100000 + get_global_id(2) * 0x10000000);
    
    // Generate random entropy (256 bits = 32 bytes) using the improved RNG
    __private uchar entropy[32];
    for (uint i = 0; i < 32; i++) {
        entropy[i] = xorshift_rand_byte(rng_state);
    }
    
    // Additional entropy mixing for better randomness
    for (uint i = 0; i < 16; i++) {
        uint idx1 = xorshift_rand32(rng_state) % 32;
        uint idx2 = xorshift_rand32(rng_state) % 32;
        uchar tmp = entropy[idx1];
        entropy[idx1] = entropy[idx2];
        entropy[idx2] = tmp;
    }
    
    // Copy entropy to output buffer
    for (uint i = 0; i < 32; i++) {
        entropy_output[id * 32 + i] = entropy[i];
    }
    
    // Calculate entropy with checksum
    uint entropy_with_checksum[9]; // 8 words (256 bits) + 1 word for checksum
    bip39_append_checksum(entropy, 32, entropy_with_checksum);
    
    // Extract word indices (11 bits per word)
    __private uint word_indices[24];
    for (uint i = 0; i < 24; i++) {
        uint start_bit = i * 11;
        uint start_byte = start_bit / 32;
        uint start_bit_in_byte = start_bit % 32;
        
        if (start_bit_in_byte <= 21) {
            // Word fits in a single 32-bit word
            word_indices[i] = (entropy_with_checksum[start_byte] >> (21 - start_bit_in_byte)) & 0x7FF;
        } else {
            // Word spans two 32-bit words
            uint bits_from_first = 32 - start_bit_in_byte;
            uint bits_from_second = 11 - bits_from_first;
            
            word_indices[i] = ((entropy_with_checksum[start_byte] & ((1 << bits_from_first) - 1)) << bits_from_second) |
                             ((entropy_with_checksum[start_byte + 1] >> (32 - bits_from_second)) & ((1 << bits_from_second) - 1));
        }
    }
    
    // Copy word indices to output buffer
    for (uint i = 0; i < 24; i++) {
        word_indices_output[id * 24 + i] = word_indices[i];
    }
    
    // Generate seed using PBKDF2-HMAC-SHA256 (simplified)
    // In a real implementation, the mnemonic phrase would be converted to a string
    // and used as the password, and "mnemonic" + passphrase would be the salt
    // Here we'll use the raw entropy as the password and a fixed salt
    const uchar salt[8] = {'m','n','e','m','o','n','i','c'};
    __private uchar seed[64];
    
    pbkdf2_hmac_sha256(entropy, 32, salt, 8, num_iterations, seed, 64);
    
    // Copy seed to output buffer
    for (uint i = 0; i < 64; i++) {
        seed_output[id * 64 + i] = seed[i];
    }
}

// Batch kernel function to generate multiple random mnemonic keypairs
__kernel void generate_random_mnemonic_keypair_batch(
    __global uchar *entropy_output,        // Output buffer for entropy (batch_size * 32 bytes)
    __global uchar *seed_output,           // Output buffer for seed (batch_size * 64 bytes)
    __global uint *word_indices_output,    // Output buffer for word indices (batch_size * 24 indices)
    uint seed_value,                       // Starting seed value
    uint batch_size,                       // Number of keypairs to generate per work item
    uint num_iterations                    // Number of iterations for PBKDF2
) {
    uint global_id = get_global_id(0);
    uint base_id = global_id * batch_size;
    
    // Initialize xorshift RNG state with unique seed per thread and work group
    uint rng_state[4];
    xorshift_init(rng_state, seed_value + global_id + get_global_id(1) * 0x100000 + get_global_id(2) * 0x10000000);
    
    for (uint batch_idx = 0; batch_idx < batch_size; batch_idx++) {
        uint id = base_id + batch_idx;
        
        // Further vary randomness for each item in batch
        rng_state[0] ^= batch_idx * 0x1234567;
        rng_state[3] ^= ~(batch_idx * 0x89ABCDEF);
        
        // Generate random entropy (256 bits = 32 bytes) using improved RNG
        __private uchar entropy[32];
        for (uint i = 0; i < 32; i++) {
            entropy[i] = xorshift_rand_byte(rng_state);
        }
        
        // Additional entropy mixing for better randomness
        for (uint i = 0; i < 16; i++) {
            uint idx1 = xorshift_rand32(rng_state) % 32;
            uint idx2 = xorshift_rand32(rng_state) % 32;
            uchar tmp = entropy[idx1];
            entropy[idx1] = entropy[idx2];
            entropy[idx2] = tmp;
        }
        
        // Copy entropy to output buffer
        for (uint i = 0; i < 32; i++) {
            entropy_output[id * 32 + i] = entropy[i];
        }
        
        // Calculate entropy with checksum
        uint entropy_with_checksum[9]; // 8 words (256 bits) + 1 word for checksum
        bip39_append_checksum(entropy, 32, entropy_with_checksum);
        
        // Extract word indices (11 bits per word)
        __private uint word_indices[24];
        for (uint i = 0; i < 24; i++) {
            uint start_bit = i * 11;
            uint start_byte = start_bit / 32;
            uint start_bit_in_byte = start_bit % 32;
            
            if (start_bit_in_byte <= 21) {
                // Word fits in a single 32-bit word
                word_indices[i] = (entropy_with_checksum[start_byte] >> (21 - start_bit_in_byte)) & 0x7FF;
            } else {
                // Word spans two 32-bit words
                uint bits_from_first = 32 - start_bit_in_byte;
                uint bits_from_second = 11 - bits_from_first;
                
                word_indices[i] = ((entropy_with_checksum[start_byte] & ((1 << bits_from_first) - 1)) << bits_from_second) |
                                 ((entropy_with_checksum[start_byte + 1] >> (32 - bits_from_second)) & ((1 << bits_from_second) - 1));
            }
        }
        
        // Copy word indices to output buffer
        for (uint i = 0; i < 24; i++) {
            word_indices_output[id * 24 + i] = word_indices[i];
        }
        
        // Generate seed using PBKDF2-HMAC-SHA256
        const uchar salt[8] = {'m','n','e','m','o','n','i','c'};
        __private uchar seed[64];
        
        pbkdf2_hmac_sha256(entropy, 32, salt, 8, num_iterations, seed, 64);
        
        // Copy seed to output buffer
        for (uint i = 0; i < 64; i++) {
            seed_output[id * 64 + i] = seed[i];
        }
    }
}
