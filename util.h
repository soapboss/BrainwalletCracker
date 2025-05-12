/* 
 * Bitcoin Wallet Address Generator - Utility functions
 * A simplified implementation of brainflayer
 * For educational purposes only
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <stdlib.h>

// Convert a hex string to bytes
// Returns 0 on success, non-zero on error
int hex_to_bytes(const char *hex_str, unsigned char *out_bytes, size_t out_size);

// Convert bytes to a hex string (null-terminated)
// The out_hex buffer must be at least 2*bytes_len+1 in size
void bytes_to_hex(const unsigned char *bytes, size_t bytes_len, char *out_hex);

// Base58 encoding for Bitcoin addresses
// Returns the length of the resulting string
size_t base58_encode(const unsigned char *data, size_t data_len, char *out_str, size_t out_str_size);

// Base58Check encoding for Bitcoin addresses (includes version byte and checksum)
// Returns the length of the resulting string
size_t base58check_encode(unsigned char version, const unsigned char *data, size_t data_len, 
                        char *out_str, size_t out_str_size);

#endif /* UTIL_H */ 