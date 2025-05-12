# Bitcoin Wallet Address Generator

A command-line tool for generating Bitcoin and Ethereum addresses from various input types. This project is a simplified implementation of the [brainflayer](https://github.com/ryancdotorg/brainflayer) tool, focusing on educational purposes to help users understand the principles of cryptocurrency address generation.

## Features

1. **Multiple Key Derivation Methods**:
   - SHA-256 hash (classic brainwallet)
   - Keccak/SHA-3 hash
   - WarpWallet algorithm (simplified implementation)
   - BrainwalletIO algorithm (simplified implementation)
   - BrainV2 algorithm (simplified implementation)
   - Raw private key input

2. **Address Types**:
   - Bitcoin uncompressed (P2PKH)
   - Bitcoin compressed (P2PKH)
   - Ethereum

## Installation

### Prerequisites

- GCC or another C compiler
- OpenSSL development libraries

### Build Instructions

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install build-essential libssl-dev libscrypt-dev

# Build the project
cd linux
make
```

## Usage

```bash
./btc_wallet_gen [options]
```

### Options

- `-a <method>` : Address generation method
  - `1`: SHA-256 (classic brainwallet)
  - `2`: Keccak/SHA-3
  - `3`: WarpWallet (scrypt + PBKDF2)
  - `4`: BrainwalletIO
  - `5`: BrainV2
  - `6`: Raw private key (hex input)
- `-t <type>` : Output address type
  - `1`: Bitcoin uncompressed
  - `2`: Bitcoin compressed
  - `3`: Ethereum
- `-p <phrase>` : Passphrase (for brainwallet methods)
- `-k <key>` : Private key in hex (for raw key method)
- `-s <salt>` : Salt value (for methods that support it)
- `-h` : Show help message

### Examples

Generate a Bitcoin address from a passphrase using SHA-256:
```bash
./btc_wallet_gen -a 1 -t 2 -p "my secret passphrase" 
```

Generate an Ethereum address from a raw private key:
```bash
./btc_wallet_gen -a 6 -t 1 -k "a0dc65ffca799873cbea0ac274015b9526505dae8f3abe89e6c7c128476a6e31"
```

Generate a Bitcoin compressed address using WarpWallet:
```bash
./btc_wallet_gen -a 3 -t 1 -p "123456" -s "123456@qq.com"
```

## Security Warning

**IMPORTANT**: This tool is intended for educational purposes only. "Brainwallet" methods are vulnerable to dictionary attacks and brute force cracking. Do not use this tool to generate wallets for storing actual cryptocurrency assets.

## Limitations

This implementation is simplified for educational purposes:
- The WarpWallet, BrainwalletIO, and BrainV2 implementations are simplified approximations
- Some cryptographic functions are using basic implementations instead of the full algorithms
- Error handling is minimal
- Performance optimizations present in the original brainflayer are not included

## License

This project is provided for educational purposes only. Use at your own risk. 