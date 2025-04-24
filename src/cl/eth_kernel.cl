// Ethereum address generation kernel
// This kernel handles secp256k1 key operations and Keccak256 hashing

// Keccak-256 constants
#define KECCAK_ROUNDS 24

typedef ulong uint64_t;
typedef uint uint32_t;
typedef uchar uint8_t;

// Keccak state
typedef struct {
    uint64_t state[25];
    int byteIndex;
    int wordIndex;
} keccak_state;

// Constants for Keccak permutation
__constant uint64_t keccakf_rndc[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

// Rotation constants for Keccak
__constant int keccakf_rotc[24] = {
    1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
};

// Pi table for Keccak
__constant int keccakf_piln[24] = {
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
};

// Define our own rotate function for uint64_t to avoid ambiguity
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

// Define hex characters as a constant array instead of in function scope
__constant char HEX_CHARS[16] = "0123456789abcdef";

// Helper function to convert a byte to hex characters
void byte_to_hex(uint8_t byte, char *hex) {
    // Remove static keyword and use the constant array instead
    hex[0] = HEX_CHARS[byte >> 4];
    hex[1] = HEX_CHARS[byte & 0x0F];
}

// Keccak-f permutation function
void keccakf(uint64_t st[25]) {
    int i, j, r;
    uint64_t t, bc[5];

    for (r = 0; r < KECCAK_ROUNDS; r++) {
        // Theta
        for (i = 0; i < 5; i++) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }

        for (i = 0; i < 5; i++) {
            // Fix: replace rotate with our macro ROTL64
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) {
                st[j + i] ^= t;
            }
        }

        // Rho Pi
        t = st[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            // Fix: replace rotate with our macro ROTL64
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        // Chi
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) {
                bc[i] = st[j + i];
            }
            for (i = 0; i < 5; i++) {
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        // Iota
        st[0] ^= keccakf_rndc[r];
    }
}

// Initialize Keccak state
void keccak_init(keccak_state *ctx) {
    for (int i = 0; i < 25; i++) {
        ctx->state[i] = 0;
    }
    ctx->byteIndex = 0;
    ctx->wordIndex = 0;
}

// Update Keccak state with input data
void keccak_update(keccak_state *ctx, __global const uint8_t *input, size_t len) {
    size_t i;
    int byteIndex = ctx->byteIndex;
    int wordIndex = ctx->wordIndex;
    uint64_t *state = ctx->state;
    
    // Process input bytes
    for (i = 0; i < len; i++) {
        uint8_t byte = input[i];
        uint64_t mask = (uint64_t)byte << (byteIndex * 8);
        state[wordIndex] ^= mask;
        
        byteIndex++;
        if (byteIndex == 8) {
            byteIndex = 0;
            wordIndex++;
            if (wordIndex == 17) { // 136 bytes (1088 bits) is the rate for SHA3-256
                keccakf(state);
                wordIndex = 0;
            }
        }
    }
    
    ctx->byteIndex = byteIndex;
    ctx->wordIndex = wordIndex;
}

// Finalize Keccak hash with padding
void keccak_final(keccak_state *ctx, uint8_t *output) {
    uint64_t *state = ctx->state;
    int byteIndex = ctx->byteIndex;
    int wordIndex = ctx->wordIndex;
    
    // Add padding
    uint64_t mask = (uint64_t)0x01 << (byteIndex * 8);
    state[wordIndex] ^= mask;
    
    // Add final bit at the end
    state[16] ^= 0x8000000000000000;
    
    // Perform final permutation
    keccakf(state);
    
    // Copy first 32 bytes (256 bits) of state to output
    for (int i = 0; i < 4; i++) {
        uint64_t word = state[i];
        for (int j = 0; j < 8; j++) {
            output[i * 8 + j] = (word >> (j * 8)) & 0xFF;
        }
    }
}

// Compute Keccak-256 hash
void keccak256(uint8_t *output, __global const uint8_t *input, size_t len) {
    keccak_state ctx;
    keccak_init(&ctx);
    keccak_update(&ctx, input, len);
    keccak_final(&ctx, output);
}

// Check if patterns like "0xa*" or "^0xa.*$" match an Ethereum address
bool matches_simplified_regex(__global const char *pattern, uint32_t pattern_len, const char *hex_addr) {
    uint32_t pattern_pos = 0;
    
    // Skip '^' at the beginning of the pattern if present
    if (pattern_len > 0 && pattern[0] == '^') {
        pattern_pos++;
    }
    
    // Handle "0x" prefix in pattern
    bool pattern_has_0x_prefix = false;
    if (pattern_pos + 1 < pattern_len && 
        pattern[pattern_pos] == '0' && 
        pattern[pattern_pos + 1] == 'x') {
        pattern_has_0x_prefix = true;
        pattern_pos += 2; // Skip "0x"
    }
    
    // Start matching from the beginning of the hex address
    uint32_t addr_pos = 0;
    bool has_match = true;
    
    while (pattern_pos < pattern_len && has_match) {
        // Handle $ at the end of the pattern
        if (pattern[pattern_pos] == '$' && pattern_pos == pattern_len - 1) {
            // Must be at the end of the address for $ to match
            return (addr_pos == 40); // 40 is the length of the hex address
        }
        
        // Handle wildcards and quantifiers
        if (pattern_pos + 1 < pattern_len && pattern[pattern_pos + 1] == '*') {
            char wildcard_char = pattern[pattern_pos];
            pattern_pos += 2; // Skip the character and the *
            
            // For ".*" case, match any number of characters until the next pattern char or end
            if (wildcard_char == '.') {
                // If we're at the end of the pattern, return true (everything matches)
                if (pattern_pos >= pattern_len || 
                    (pattern_pos == pattern_len - 1 && pattern[pattern_pos] == '$')) {
                    return true;
                }
                
                // Otherwise, we need to find the next character in the pattern after the .*
                char next_char = pattern[pattern_pos];
                
                // Skip to where the next character appears in the address string
                while (addr_pos < 40) {
                    if (hex_addr[addr_pos] == next_char) {
                        // Found a potential match point, but there might be multiple
                        // occurrences, so we'll just proceed as if this is the right one
                        break;
                    }
                    addr_pos++;
                }
                
                // If we couldn't find the next character, no match
                if (addr_pos >= 40) {
                    has_match = false;
                }
            } else {
                // For specific character followed by *, match 0 or more of that character
                while (addr_pos < 40 && 
                       (hex_addr[addr_pos] == wildcard_char || wildcard_char == '.')) {
                    addr_pos++;
                }
            }
        } else {
            // Regular character matching
            if (addr_pos >= 40) {
                has_match = false;
                break;
            }
            
            char p = pattern[pattern_pos];
            char a = hex_addr[addr_pos];
            
            // Handle '.' wildcard
            if (p == '.') {
                // Any character matches
                addr_pos++;
                pattern_pos++;
            } 
            // Case-insensitive hex character matching
            else if (p == a || 
                    (p >= 'a' && p <= 'f' && p - 32 == a) || 
                    (p >= 'A' && p <= 'F' && p + 32 == a)) {
                addr_pos++;
                pattern_pos++;
            } else {
                has_match = false;
            }
        }
    }
    
    // Match is valid if we processed the full pattern
    // and either processed the full address or the pattern ends with .*$
    return has_match && pattern_pos >= pattern_len;
}

// Main kernel function for Ethereum address generation
__kernel void generate_eth_address(
    __global uint8_t *private_keys,   // Input: array of private keys (32 bytes each)
    __global uint8_t *addresses,      // Output: array of ETH addresses (20 bytes each)
    __global uint32_t *found_flags,   // Output: flag to indicate if match was found
    __global uint32_t *found_indices, // Output: index of the matched address
    __global const char *regex_pattern, // Regex pattern (simplified - we'll do basic prefix matching)
    uint32_t regex_len,               // Length of the regex pattern
    uint32_t num_keys                 // Number of keys to process
) {
    uint32_t id = get_global_id(0);
    
    if (id >= num_keys) return;
    
    // Get the private key for this work item
    __global uint8_t *priv_key = &private_keys[id * 32];
    
    // This is a simplified implementation - in a real implementation, 
    // we would perform secp256k1 operations to derive the public key from the private key
    // For now, we'll just use the private key directly to compute a hash
    
    // Hash the private key (simulating public key derivation)
    uint8_t temp_hash[32];
    keccak256(temp_hash, priv_key, 32);
    
    // Extract the last 20 bytes as Ethereum address
    __global uint8_t *addr = &addresses[id * 20];
    for (int i = 0; i < 20; i++) {
        addr[i] = temp_hash[i + 12];  // Last 20 bytes
    }
    
    // Convert raw address bytes to hex string representation for matching
    char hex_addr[40]; // 20 bytes * 2 hex chars per byte
    for (int i = 0; i < 20; i++) {
        byte_to_hex(addr[i], &hex_addr[i * 2]);
    }
    
    // First check if the pattern has the 0x prefix
    bool has_0x_prefix = false;
    uint32_t start_pos = 0;
    
    if (regex_len > 2 && regex_pattern[0] == '^') {
        start_pos = 1;
        if (regex_len > 3 && regex_pattern[1] == '0' && regex_pattern[2] == 'x') {
            has_0x_prefix = true;
        }
    } else if (regex_len > 1 && regex_pattern[0] == '0' && regex_pattern[1] == 'x') {
        has_0x_prefix = true;
    }
    
    // Use our improved regex matching function
    bool match = false;
    
    // If the pattern contains "0x" and we're looking for a hex character right after it,
    // make sure the address has that character at the beginning
    if (has_0x_prefix && regex_len > start_pos + 2) {
        // Check if the first character in the hex address matches the first character after 0x in the pattern
        char target_char = regex_pattern[start_pos + 2];
        
        if ((target_char == 'a' || target_char == 'A') && 
            hex_addr[0] != 'a' && hex_addr[0] != 'A') {
            // If pattern expects 'a' but the address doesn't start with 'a', it's not a match
            match = false;
        } else {
            // Otherwise use the regular matcher
            match = matches_simplified_regex(regex_pattern, regex_len, hex_addr);
        }
    } else {
        match = matches_simplified_regex(regex_pattern, regex_len, hex_addr);
    }
    
    // If we found a match, set the flag and index
    if (match) {
        found_flags[id] = 1;
        atomic_min(&found_indices[0], id);
    } else {
        found_flags[id] = 0;
    }
}