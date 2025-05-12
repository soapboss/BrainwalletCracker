/* 
 * RIPEMD-160 Hash to/from Bitcoin P2PKH Address Converter
 * For educational purposes only
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <openssl/sha.h>

// Base58 character set used for Bitcoin addresses
static const char base58_chars[] = 
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Convert a hex string to bytes
// Returns 0 on success, non-zero on error
int hex_to_bytes(const char *hex_str, unsigned char *out_bytes, size_t out_size) {
    size_t hex_len = strlen(hex_str);
    size_t byte_len = hex_len / 2;
    
    if (hex_len % 2 != 0 || byte_len > out_size) {
        return -1;  // Invalid hex string or buffer too small
    }
    
    for (size_t i = 0; i < byte_len; i++) {
        char high = hex_str[i*2];
        char low = hex_str[i*2+1];
        
        int high_val = -1, low_val = -1;
        
        if (high >= '0' && high <= '9') high_val = high - '0';
        else if (high >= 'a' && high <= 'f') high_val = high - 'a' + 10;
        else if (high >= 'A' && high <= 'F') high_val = high - 'A' + 10;
        
        if (low >= '0' && low <= '9') low_val = low - '0';
        else if (low >= 'a' && low <= 'f') low_val = low - 'a' + 10;
        else if (low >= 'A' && low <= 'F') low_val = low - 'A' + 10;
        
        if (high_val < 0 || low_val < 0) {
            return -1;  // Invalid hex character
        }
        
        out_bytes[i] = (high_val << 4) | low_val;
    }
    
    return 0;
}

// Convert bytes to a hex string
void bytes_to_hex(const unsigned char *bytes, size_t bytes_len, char *out_hex) {
    static const char hex_chars[] = "0123456789abcdef";
    
    for (size_t i = 0; i < bytes_len; i++) {
        out_hex[i*2] = hex_chars[(bytes[i] >> 4) & 0xF];
        out_hex[i*2+1] = hex_chars[bytes[i] & 0xF];
    }
    
    out_hex[bytes_len*2] = '\0';
}

// Base58 encoding
size_t base58_encode(const unsigned char *data, size_t data_len, char *out_str, size_t out_str_size) {
    // Count leading zeros
    size_t zeros = 0;
    while (zeros < data_len && data[zeros] == 0) {
        zeros++;
    }
    
    // Allocate temporary buffer for base58 conversion
    // Worst case: base58 takes log(256)/log(58) ~= 1.38 times as much space as binary
    size_t b58_len = data_len * 138 / 100 + 1;
    unsigned char *b58 = malloc(b58_len);
    if (!b58) return 0;
    
    memset(b58, 0, b58_len);
    
    // Process input data and convert to base58
    for (size_t i = zeros; i < data_len; i++) {
        unsigned int carry = data[i];
        for (size_t j = 0; j < b58_len; j++) {
            carry += b58[j] * 256;
            b58[j] = carry % 58;
            carry /= 58;
        }
    }
    
    // Determine actual output length and check buffer size
    size_t out_len = 0;
    size_t i = b58_len;
    while (i--) {
        if (b58[i] > 0 || out_len > 0) {
            if (out_len < out_str_size - 1)
                out_str[out_len++] = base58_chars[b58[i]];
        }
    }
    
    // Add leading '1' characters for each leading zero byte
    for (size_t i = 0; i < zeros && out_len < out_str_size - 1; i++) {
        // Move existing characters to make room for the '1'
        memmove(out_str + 1, out_str, out_len);
        out_str[0] = '1';
        out_len++;
    }
    
    out_str[out_len] = '\0';
    
    free(b58);
    return out_len;
}

// Base58 decoding
int base58_decode(const char *str, unsigned char *out_data, size_t out_data_size) {
    // Count leading '1's
    size_t zeros = 0;
    while (str[zeros] == '1') {
        zeros++;
    }
    
    // Allocate buffer for the result
    size_t str_len = strlen(str);
    size_t out_len = str_len * 733 / 1000 + 1; // Approximate maximum size
    unsigned char *tmp = malloc(out_len);
    if (!tmp) return -1;
    
    memset(tmp, 0, out_len);
    
    // Process the Base58 string
    for (size_t i = zeros; i < str_len; i++) {
        const char *p = strchr(base58_chars, str[i]);
        if (!p) {
            free(tmp);
            return -1; // Invalid character
        }
        
        int val = p - base58_chars;
        
        // Multiply by 58 and add val
        for (size_t j = 0; j < out_len; j++) {
            int carry = tmp[j] * 58 + val;
            tmp[j] = carry;
            val = carry >> 8;
        }
    }
    
    // Copy the result to output buffer, with leading zeros
    if (zeros + out_len > out_data_size) {
        free(tmp);
        return -1; // Output buffer too small
    }
    
    memset(out_data, 0, zeros);
    
    // Find the highest non-zero byte
    size_t real_len = out_len;
    while (real_len > 0 && tmp[real_len - 1] == 0) {
        real_len--;
    }
    
    // Copy in reverse order
    for (size_t i = 0; i < real_len; i++) {
        out_data[zeros + i] = tmp[real_len - 1 - i];
    }
    
    free(tmp);
    return zeros + real_len;
}

// Base58Check encoding (includes version byte and checksum)
size_t base58check_encode(unsigned char version, const unsigned char *data, size_t data_len, 
                          char *out_str, size_t out_str_size) {
    // Prepare data with version and checksum
    unsigned char *buffer = malloc(data_len + 5);  // version + data + 4-byte checksum
    if (!buffer) return 0;
    
    buffer[0] = version;
    memcpy(buffer + 1, data, data_len);
    
    // Calculate double SHA-256 checksum
    unsigned char checksum[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, buffer, data_len + 1);
    SHA256_Final(checksum, &sha256);
    
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, checksum, SHA256_DIGEST_LENGTH);
    SHA256_Final(checksum, &sha256);
    
    // Add checksum to the end of buffer
    memcpy(buffer + data_len + 1, checksum, 4);
    
    // Encode with Base58
    size_t result = base58_encode(buffer, data_len + 5, out_str, out_str_size);
    
    free(buffer);
    return result;
}

// Base58Check decoding (validates checksum)
int base58check_decode(const char *str, unsigned char *out_data, size_t out_data_size, 
                      unsigned char *out_version) {
    // Temporary buffer for decoded data (version + data + 4-byte checksum)
    unsigned char buffer[100];
    int len = base58_decode(str, buffer, sizeof(buffer));
    
    if (len < 5) {
        return -1; // Too short to have version + data + checksum
    }
    
    // Verify checksum (last 4 bytes)
    unsigned char checksum[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, buffer, len - 4);
    SHA256_Final(checksum, &sha256);
    
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, checksum, SHA256_DIGEST_LENGTH);
    SHA256_Final(checksum, &sha256);
    
    // Check if the checksums match
    if (memcmp(checksum, buffer + len - 4, 4) != 0) {
        return -1; // Invalid checksum
    }
    
    // Set the version byte and copy the data
    *out_version = buffer[0];
    
    if (len - 5 > out_data_size) {
        return -1; // Output buffer too small
    }
    
    memcpy(out_data, buffer + 1, len - 5);
    
    return len - 5; // Return length of data (without version and checksum)
}

// Convert RIPEMD-160 hash to P2PKH address
void hash160_to_p2pkh(const char *hex_hash, char *out_address) {
    unsigned char hash160[20];
    
    // Convert hex string to binary
    if (hex_to_bytes(hex_hash, hash160, sizeof(hash160)) != 0) {
        strcpy(out_address, "Error: Invalid RIPEMD-160 hash");
        return;
    }
    
    // Apply Base58Check encoding with version byte 0x00 (for P2PKH)
    base58check_encode(0x00, hash160, 20, out_address, 40);
}

// Convert P2PKH address to RIPEMD-160 hash
void p2pkh_to_hash160(const char *address, char *out_hex_hash) {
    unsigned char hash160[20];
    unsigned char version;
    
    // Decode Base58Check address
    int len = base58check_decode(address, hash160, sizeof(hash160), &version);
    
    if (len != 20 || version != 0x00) {
        strcpy(out_hex_hash, "Error: Invalid P2PKH address");
        return;
    }
    
    // Convert binary to hex string
    bytes_to_hex(hash160, 20, out_hex_hash);
}

// Show help information
void usage(char *name) {
    printf("Usage: %s [options]\n", name);
    printf("Options:\n");
    printf("  -p            Convert RIPEMD-160 hash to P2PKH address\n");
    printf("  -r            Convert P2PKH address to RIPEMD-160 hash\n");
    printf("  -f <file>     Input file (one entry per line)\n");
    printf("  -s <string>   Input string (hash or address to convert)\n");
    printf("  -o <file>     Output file (default: stdout)\n");
    printf("  -h            Show this help message\n");
    printf("\nExample:\n");
    printf("  %s -p -s 7c3f9c4ea689d13b81d03eac86f04c7c657f2c49\n", name);
    printf("  %s -r -s 1J7mdg5rbQyUHENYdx39WVWK7fsLpEoXZy\n", name);
    exit(0);
}

int main(int argc, char **argv) {
    int opt;
    int mode = 0;  // 0: undefined, 1: hash to address, 2: address to hash
    char *input_file = NULL;
    char *input_string = NULL;
    char *output_file = NULL;
    
    while ((opt = getopt(argc, argv, "prf:s:o:h")) != -1) {
        switch (opt) {
            case 'p':
                mode = 1;  // hash to address
                break;
            case 'r':
                mode = 2;  // address to hash
                break;
            case 'f':
                input_file = optarg;
                break;
            case 's':
                input_string = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'h':
                usage(argv[0]);
                break;
            default:
                usage(argv[0]);
        }
    }
    
    if (mode == 0) {
        printf("Error: Must specify conversion mode (-p or -r)\n");
        usage(argv[0]);
    }
    
    if (input_file == NULL && input_string == NULL) {
        printf("Error: Must provide input file (-f) or input string (-s)\n");
        usage(argv[0]);
    }
    
    // Open output file if specified, or use stdout
    FILE *out_fp = stdout;
    if (output_file != NULL) {
        out_fp = fopen(output_file, "w");
        if (out_fp == NULL) {
            perror("Error opening output file");
            exit(1);
        }
    }
    
    // Process input string if provided
    if (input_string != NULL) {
        char result[100] = {0};
        
        if (mode == 1) {  // hash to address
            hash160_to_p2pkh(input_string, result);
        } else {  // address to hash
            p2pkh_to_hash160(input_string, result);
        }
        
        fprintf(out_fp, "%s\n", result);
    }
    
    // Process input file if provided
    if (input_file != NULL) {
        FILE *in_fp = fopen(input_file, "r");
        if (in_fp == NULL) {
            perror("Error opening input file");
            exit(1);
        }
        
        char line[1024];
        while (fgets(line, sizeof(line), in_fp) != NULL) {
            // Remove newline character if present
            size_t len = strlen(line);
            if (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) {
                line[--len] = '\0';
            }
            if (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) {
                line[--len] = '\0';
            }
            
            // Skip empty lines
            if (len == 0) {
                continue;
            }
            
            char result[100] = {0};
            
            if (mode == 1) {  // hash to address
                hash160_to_p2pkh(line, result);
            } else {  // address to hash
                p2pkh_to_hash160(line, result);
            }
            
            fprintf(out_fp, "%s\n", result);
        }
        
        fclose(in_fp);
    }
    
    // Close output file if it was opened
    if (output_file != NULL) {
        fclose(out_fp);
    }
    
    return 0;
} 