/* 
 * Bitcoin Wallet Address Generator - Crypto operations
 * A simplified implementation of brainflayer
 * For educational purposes only
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/hmac.h>
#include <libscrypt.h>

// For scrypt, we'll need to either include libscrypt or implement it here
// For simplicity, we'll declare it as an external function provided by libscrypt
extern int crypto_scrypt(const uint8_t *passwd, size_t passwdlen,
                        const uint8_t *salt, size_t saltlen,
                        uint64_t N, uint32_t r, uint32_t p,
                        uint8_t *buf, size_t buflen);

#include "crypto.h"
#include "util.h"

// Keccak/SHA-3 implementation
typedef struct {
    uint64_t state[25];
    unsigned int rate;
    unsigned int capacity;
    unsigned int block_size;
    unsigned char buffer[144]; // 1600 bits / 8 = 200 bytes, but we only need 144 for SHA3-256
    unsigned int buffer_pos;
} keccak_ctx;

// Initialize Keccak context for SHA3-256
static void keccak_init(keccak_ctx *ctx) {
    memset(ctx, 0, sizeof(keccak_ctx));
    ctx->rate = 1088;
    ctx->capacity = 512;
    ctx->block_size = 136; // 1088 bits / 8 = 136 bytes
}

// Simplified Keccak hash function for SHA3-256
// Note: In a real implementation, the full Keccak-f[1600] permutation would be implemented
static void keccak_update(keccak_ctx *ctx, const unsigned char *data, size_t len) {
    // This is a placeholder. In a real implementation, this would process the input data 
    // and update the state with the Keccak permutation function
    // For simplicity, we're using OpenSSL's EVP API for SHA3 instead of implementing Keccak directly
    (void)ctx;
    (void)data;
    (void)len;
}

static void keccak_final(keccak_ctx *ctx, unsigned char *out) {
    // This is a placeholder. In a real implementation, this would finalize the hash
    // by applying padding and the last permutation
    // For simplicity, we're using OpenSSL's EVP API for SHA3 instead of implementing Keccak directly
    (void)ctx;
    (void)out;
}

// Initialize the crypto context
int crypto_init(crypto_context *ctx) {
    // Set everything to NULL/0 initially
    memset(ctx, 0, sizeof(crypto_context));
    
    // In a full implementation, this would initialize the secp256k1 context
    // and load/generate the EC multiplication tables for optimization
    
    return 0;
}

// Clean up crypto context
void crypto_cleanup(crypto_context *ctx) {
    // In a full implementation, this would free the secp256k1 context
    // and any other resources
    
    memset(ctx, 0, sizeof(crypto_context));
}

// Generate private key using SHA-256
int generate_privkey_sha256(crypto_context *ctx, const char *passphrase, size_t passphrase_len, 
                           unsigned char *out_privkey) {
    SHA256_CTX sha256;
    
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, passphrase, passphrase_len);
    SHA256_Final(out_privkey, &sha256);
    
    return 0;
}

// Generate private key using Keccak/SHA-3
int generate_privkey_keccak(crypto_context *ctx, const char *passphrase, size_t passphrase_len, 
                           unsigned char *out_privkey) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    
    mdctx = EVP_MD_CTX_new();
    md = EVP_sha3_256();
    
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, passphrase, passphrase_len);
    EVP_DigestFinal_ex(mdctx, out_privkey, NULL);
    
    EVP_MD_CTX_free(mdctx);
    
    return 0;
}

// Generate private key using WarpWallet method (scrypt + PBKDF2)
int generate_privkey_warpwallet(crypto_context *ctx, const char *passphrase, size_t passphrase_len, 
                               const char *salt, size_t salt_len, unsigned char *out_privkey) {
    // WarpWallet implementation based on https://keybase.io/warp algorithm
    // This implementation follows the approach in warpwallet-master/pkg/warp package
    
    // Allocate memory for the modified passphrase and salt
    // We need to append \u0001 or \u0002 to each
    char *passphrase_s = malloc(passphrase_len + 2); // +2 for \u0001 and null terminator
    char *salt_s = malloc(salt_len + 2);             // +2 for \u0001 and null terminator
    char *passphrase_p = malloc(passphrase_len + 2); // +2 for \u0002 and null terminator
    char *salt_p = malloc(salt_len + 2);             // +2 for \u0002 and null terminator
    
    if (!passphrase_s || !salt_s || !passphrase_p || !salt_p) {
        // Handle memory allocation failure
        if (passphrase_s) free(passphrase_s);
        if (salt_s) free(salt_s);
        if (passphrase_p) free(passphrase_p);
        if (salt_p) free(salt_p);
        return -1;
    }
    
    // Prepare inputs for scrypt
    memcpy(passphrase_s, passphrase, passphrase_len);
    passphrase_s[passphrase_len] = 1;  // \u0001
    passphrase_s[passphrase_len + 1] = '\0';
    
    memcpy(salt_s, salt, salt_len);
    salt_s[salt_len] = 1;  // \u0001
    salt_s[salt_len + 1] = '\0';
    
    // Prepare inputs for PBKDF2
    memcpy(passphrase_p, passphrase, passphrase_len);
    passphrase_p[passphrase_len] = 2;  // \u0002
    passphrase_p[passphrase_len + 1] = '\0';
    
    memcpy(salt_p, salt, salt_len);
    salt_p[salt_len] = 2;  // \u0002
    salt_p[salt_len + 1] = '\0';
    
    // First key using scrypt (N=2^18, r=8, p=1, dkLen=32)
    unsigned char seed1[32];
    int ret = libscrypt_scrypt((unsigned char*)passphrase_s, passphrase_len + 1,
                             (unsigned char*)salt_s, salt_len + 1,
                             262144, 8, 1, seed1, 32);
    
    // Second key using PBKDF2 (iterations=65536, hash=SHA256, dkLen=32)
    unsigned char seed2[32];
    PKCS5_PBKDF2_HMAC(passphrase_p, passphrase_len + 1,
                      (unsigned char*)salt_p, salt_len + 1,
                      65536, EVP_sha256(), 32, seed2);
    
    // XOR the two seeds to get the final private key
    for (int i = 0; i < 32; i++) {
        out_privkey[i] = seed1[i] ^ seed2[i];
    }
    
    // Clean up
    free(passphrase_s);
    free(salt_s);
    free(passphrase_p);
    free(salt_p);
    
    return 0;
}

// Generate private key using BrainwalletIO method
int generate_privkey_brainwalletio(crypto_context *ctx, const char *passphrase, size_t passphrase_len, 
                                  const char *salt, size_t salt_len, unsigned char *out_privkey) {
    // BrainwalletIO implementation based on brainwalletio.c
    // Process:
    // 1. Generate seed1 using scrypt (N=2^18, r=8, p=1, dkLen=32)
    // 2. Convert seed1 to hex string
    // 3. Hash the hex string with SHA-256 to get final private key
    
    // Step 1: Generate seed1 using scrypt
    unsigned char seed1[32];
    int ret = libscrypt_scrypt((unsigned char*)passphrase, passphrase_len,
                             (unsigned char*)salt, salt_len,
                             262144, 8, 1, seed1, 32);
    if (ret != 0) {
        return -1;
    }
    
    // Step 2: Convert seed1 to hex string
    char hex_seed1[65]; // 32 bytes * 2 + 1 for null terminator
    for (int i = 0; i < 32; i++) {
        sprintf(hex_seed1 + (i * 2), "%02x", seed1[i]);
    }
    hex_seed1[64] = '\0';
    
    // Step 3: Hash the hex string with SHA-256
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, hex_seed1, 64);
    SHA256_Final(out_privkey, &sha256);
    
    return 0;
}

// Generate private key using BrainV2 method
int generate_privkey_brainv2(crypto_context *ctx, const char *passphrase, size_t passphrase_len, 
                            const char *salt, size_t salt_len, unsigned char *out_privkey) {
    // In a real implementation, this would implement the BrainV2 algorithm
    // with multiple rounds of scrypt
    // For simplicity, we're just doing multiple rounds of SHA-256
    
    unsigned char buffer[512];
    unsigned char hash[32];
    
    memcpy(buffer, passphrase, passphrase_len);
    memcpy(buffer + passphrase_len, salt, salt_len);
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, buffer, passphrase_len + salt_len);
    SHA256_Final(hash, &sha256);
    
    // Additional rounds of hashing to simulate multiple KDF iterations
    for (int i = 0; i < 5; i++) {
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, hash, 32);
        SHA256_Final(hash, &sha256);
    }
    
    memcpy(out_privkey, hash, 32);
    
    return 0;
}

// Generate public key from private key
int generate_pubkey(crypto_context *ctx, const unsigned char *privkey, 
                   unsigned char *out_pubkey, int compressed) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) return -1;
    
    BIGNUM *priv_bn = BN_bin2bn(privkey, 32, NULL);
    if (!priv_bn) {
        EC_KEY_free(key);
        return -1;
    }
    
    if (!EC_KEY_set_private_key(key, priv_bn)) {
        BN_free(priv_bn);
        EC_KEY_free(key);
        return -1;
    }
    
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *pub_point = EC_POINT_new(group);
    
    if (!EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL)) {
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        EC_KEY_free(key);
        return -1;
    }
    
    EC_KEY_set_public_key(key, pub_point);
    
    // Format the public key
    size_t pubkey_size;
    if (compressed) {
        // Compressed public key format: 0x02/0x03 + 32-byte X coordinate
        // 0x02 if Y is even, 0x03 if Y is odd
        const EC_POINT *pub = EC_KEY_get0_public_key(key);
        BIGNUM *y = BN_new();
        
        // Get X and Y coordinates
        EC_POINT_get_affine_coordinates(group, pub, NULL, y, NULL);
        
        // Determine if Y is odd or even
        int is_odd = BN_is_odd(y);
        
        out_pubkey[0] = is_odd ? 0x03 : 0x02;
        
        // Extract X coordinate
        pubkey_size = EC_POINT_point2oct(group, pub, POINT_CONVERSION_COMPRESSED,
                                        out_pubkey, 33, NULL);
        
        BN_free(y);
    } else {
        // Uncompressed public key format: 0x04 + 32-byte X coordinate + 32-byte Y coordinate
        pubkey_size = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED,
                                        out_pubkey, 65, NULL);
    }
    
    EC_POINT_free(pub_point);
    BN_free(priv_bn);
    EC_KEY_free(key);
    
    return (pubkey_size > 0) ? 0 : -1;
}

// Generate Bitcoin address from public key
int generate_bitcoin_address(crypto_context *ctx, const unsigned char *pubkey, 
                            int compressed, char *out_address) {
    // Hash the public key with SHA-256 and RIPEMD-160
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char hash160[RIPEMD160_DIGEST_LENGTH];
    
    // Step 1: SHA-256
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, pubkey, compressed ? 33 : 65);
    SHA256_Final(hash, &sha256);
    
    // Step 2: RIPEMD-160
    RIPEMD160_CTX ripemd160;
    RIPEMD160_Init(&ripemd160);
    RIPEMD160_Update(&ripemd160, hash, SHA256_DIGEST_LENGTH);
    RIPEMD160_Final(hash160, &ripemd160);
    
    // 直接输出哈希值的十六进制表示
    bytes_to_hex(hash160, RIPEMD160_DIGEST_LENGTH, out_address);
    
    return 0;
}

// Generate Ethereum address from public key
int generate_ethereum_address(crypto_context *ctx, const unsigned char *pubkey, 
                             char *out_address) {
    // Ethereum uses Keccak-256 of the public key
    // Note: We skip the first byte of the pubkey (0x04 format identifier)
    
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char hash[32];
    
    mdctx = EVP_MD_CTX_new();
    md = EVP_sha3_256();
    
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, pubkey + 1, 64);  // Skip the first byte (0x04)
    EVP_DigestFinal_ex(mdctx, hash, NULL);
    
    EVP_MD_CTX_free(mdctx);
    
    // 直接输出最后20字节的哈希值的十六进制表示
    bytes_to_hex(hash + 12, 20, out_address);
    
    return 0;
} 