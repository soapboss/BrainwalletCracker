/* 
 * Bitcoin Wallet Address Generator
 * A simplified implementation of brainflayer
 * For educational purposes only
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>

#include "crypto.h"
#include "util.h"

void usage(char *name) {
    printf("Usage: %s [options]\n", name);
    printf("Options:\n");
    printf("  -a <method>  Address generation method:\n");
    printf("               1: SHA-256 (classic brainwallet)\n");
    printf("               2: Keccak/SHA-3\n");
    printf("               3: WarpWallet (scrypt + PBKDF2)\n");
    printf("               4: BrainwalletIO\n");
    printf("               5: BrainV2\n");
    printf("               6: Raw private key (hex input)\n");
    printf("  -t <type>    Output address type:\n");
    printf("               1: Bitcoin uncompressed\n");
    printf("               2: Bitcoin compressed\n");
    printf("               3: Ethereum\n");
    printf("  -p <phrase>  Passphrase (for brainwallet methods)\n");
    printf("  -k <key>     Private key in hex (for raw key method)\n");
    printf("  -s <salt>    Salt value (for methods that support it)\n");
    printf("  -h           Show this help message\n");
    exit(0);
}

int main(int argc, char **argv) {
    int opt;
    int method = 0;  // Default: none
    int type = 0;    // Default: none
    char *passphrase = NULL;
    char *privatekey = NULL;
    char *salt = NULL;
    
    while ((opt = getopt(argc, argv, "a:t:p:k:s:h")) != -1) {
        switch (opt) {
            case 'a':
                method = atoi(optarg);
                break;
            case 't':
                type = atoi(optarg);
                break;
            case 'p':
                passphrase = optarg;
                break;
            case 'k':
                privatekey = optarg;
                break;
            case 's':
                salt = optarg;
                break;
            case 'h':
                usage(argv[0]);
                break;
            default:
                usage(argv[0]);
        }
    }
    
    if (method == 0 || type == 0) {
        printf("Error: Method (-a) and output type (-t) must be specified\n");
        usage(argv[0]);
    }
    
    if ((method != 6 && passphrase == NULL) || 
        (method == 6 && privatekey == NULL)) {
        printf("Error: Must provide either passphrase (-p) or private key (-k)\n");
        usage(argv[0]);
    }
    
    // Initialize crypto context
    crypto_context ctx;
    crypto_init(&ctx);
    
    // Generate private key based on selected method
    unsigned char privkey[32] = {0};
    
    switch (method) {
        case 1: // SHA-256
            generate_privkey_sha256(&ctx, passphrase, strlen(passphrase), privkey);
            break;
        case 2: // Keccak/SHA-3
            generate_privkey_keccak(&ctx, passphrase, strlen(passphrase), privkey);
            break;
        case 3: // WarpWallet
            if (salt == NULL) {
                printf("Error: WarpWallet requires a salt value (-s)\n");
                exit(1);
            }
            generate_privkey_warpwallet(&ctx, passphrase, strlen(passphrase), 
                                        salt, strlen(salt), privkey);
            break;
        case 4: // BrainwalletIO
            if (salt == NULL) {
                printf("Error: BrainwalletIO requires a salt value (-s)\n");
                exit(1);
            }
            generate_privkey_brainwalletio(&ctx, passphrase, strlen(passphrase), 
                                          salt, strlen(salt), privkey);
            break;
        case 5: // BrainV2
            if (salt == NULL) {
                printf("Error: BrainV2 requires a salt value (-s)\n");
                exit(1);
            }
            generate_privkey_brainv2(&ctx, passphrase, strlen(passphrase), 
                                     salt, strlen(salt), privkey);
            break;
        case 6: // Raw private key
            if (hex_to_bytes(privatekey, privkey, 32) != 0) {
                printf("Error: Invalid private key format\n");
                exit(1);
            }
            break;
        default:
            printf("Error: Invalid method\n");
            usage(argv[0]);
    }
    
    // Display private key
    char privkey_hex[65];
    bytes_to_hex(privkey, 32, privkey_hex);
    printf("Private Key: %s\n", privkey_hex);
    
    // Generate public key and address
    unsigned char pubkey[65];
    char hash_hex[41] = {0};
    
    switch (type) {
        case 1: // Bitcoin uncompressed
            generate_pubkey(&ctx, privkey, pubkey, 0);
            generate_bitcoin_address(&ctx, pubkey, 0, hash_hex);
            printf("Bitcoin Public Key Hash (uncompressed): %s\n", hash_hex);
            break;
        case 2: // Bitcoin compressed
            generate_pubkey(&ctx, privkey, pubkey, 1);
            generate_bitcoin_address(&ctx, pubkey, 1, hash_hex);
            printf("Bitcoin Public Key Hash (compressed): %s\n", hash_hex);
            break;
        case 3: // Ethereum
            generate_pubkey(&ctx, privkey, pubkey, 0);
            generate_ethereum_address(&ctx, pubkey, hash_hex);
            printf("Ethereum Address Hash: %s\n", hash_hex);
            break;
        default:
            printf("Error: Invalid output type\n");
            usage(argv[0]);
    }
    
    // Clean up
    crypto_cleanup(&ctx);
    
    return 0;
} 