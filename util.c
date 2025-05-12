/* 
 * Bitcoin Wallet Address Generator - Utility functions
 * A simplified implementation of brainflayer
 * For educational purposes only
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/sha.h>

#include "util.h"

// Hex character to value lookup
static int hex_char_to_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Convert a hex string to bytes
int hex_to_bytes(const char *hex_str, unsigned char *out_bytes, size_t out_size) {
    size_t hex_len = strlen(hex_str);
    size_t byte_len = hex_len / 2;
    
    if (hex_len % 2 != 0 || byte_len > out_size) {
        return -1;  // Invalid hex string or buffer too small
    }
    
    for (size_t i = 0; i < byte_len; i++) {
        int high = hex_char_to_value(hex_str[i*2]);
        int low = hex_char_to_value(hex_str[i*2+1]);
        
        if (high < 0 || low < 0) {
            return -1;  // Invalid hex character
        }
        
        out_bytes[i] = (high << 4) | low;
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

// Base58 character set used for Bitcoin addresses
static const char base58_chars[] = 
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

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