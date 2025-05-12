/* 
 * Bitcoin Wallet Address Generator - Crypto operations
 * A simplified implementation of brainflayer
 * For educational purposes only
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stdlib.h>

// Opaque context structure to hold crypto resources
typedef struct {
    void *secp256k1_ctx;
    void *ec_table;
} crypto_context;

// Initialize crypto context
int crypto_init(crypto_context *ctx);

// Clean up crypto context
void crypto_cleanup(crypto_context *ctx);

// Private key generation methods
int generate_privkey_sha256(crypto_context *ctx, const char *passphrase, size_t passphrase_len, 
                           unsigned char *out_privkey);

int generate_privkey_keccak(crypto_context *ctx, const char *passphrase, size_t passphrase_len, 
                           unsigned char *out_privkey);

int generate_privkey_warpwallet(crypto_context *ctx, const char *passphrase, size_t passphrase_len, 
                               const char *salt, size_t salt_len, unsigned char *out_privkey);

int generate_privkey_brainwalletio(crypto_context *ctx, const char *passphrase, size_t passphrase_len, 
                                  const char *salt, size_t salt_len, unsigned char *out_privkey);

int generate_privkey_brainv2(crypto_context *ctx, const char *passphrase, size_t passphrase_len, 
                            const char *salt, size_t salt_len, unsigned char *out_privkey);

// Public key and address generation
int generate_pubkey(crypto_context *ctx, const unsigned char *privkey, 
                   unsigned char *out_pubkey, int compressed);

int generate_bitcoin_address(crypto_context *ctx, const unsigned char *pubkey, 
                            int compressed, char *out_address);

int generate_ethereum_address(crypto_context *ctx, const unsigned char *pubkey, 
                             char *out_address);

#endif /* CRYPTO_H */ 