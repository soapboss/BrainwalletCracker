# Bitcoin BrainwalletIO Brainwallet Checker

This is a specialized high-speed multi-threaded implementation for checking BrainwalletIO brainwallet addresses. This corresponds to the original brainflayer's `-a 4 -t 1` mode.

## Features

- Multi-threaded BrainwalletIO key generation for high performance
- Import passwords from a file
- Support for passphrases with optional salts
- Check generated addresses against a target list
- Generate uncompressed Bitcoin addresses
- Save found matches with their corresponding private keys
- Configurable thread count via YAML configuration

## What is BrainwalletIO?

BrainwalletIO is a deterministic bitcoin address generator that uses a two-step process to create private keys:
1. First, it generates a seed using scrypt (N=2^18, r=8, p=1) with the passphrase and salt
2. Then it converts this seed to a hex string and hashes it with SHA-256 to produce the final private key

This method provides better security than simple SHA-256 brainwallets, as the scrypt algorithm is designed to be computationally intensive, which helps mitigate brute force attacks.

## Building

### Prerequisites

- C++11 compatible compiler (g++ or clang++)
- OpenSSL development libraries
- libscrypt development libraries
- yaml-cpp library

### Installation

```bash
# Install dependencies on Ubuntu/Debian
sudo apt-get install build-essential libssl-dev libscrypt-dev libyaml-cpp-dev

# Build the program
make
```

## Usage

```bash
# Basic usage
./brainflayer_brainwalletio -f passphrases.txt

# With a default salt for all passphrases
./brainflayer_brainwalletio -f passphrases.txt -s "mysalt@example.com"

# With custom address and output files
./brainflayer_brainwalletio -f passphrases.txt -a address.hash -o found.hash

# Show help
./brainflayer_brainwalletio -h
```

### Parameters

- `-f <file>`: File containing passphrases to check (one per line, required)
- `-a <file>`: File containing target hash160 addresses (default: address.hash)
- `-o <file>`: Output file for matches (default: found.hash)
- `-s <salt>`: Default salt to use when not specified in input file
- `-h`: Show help message

### Input Format

Your passphrase file can include optional salts for each passphrase using the format:
```
passphrase1
passphrase2,salt2
passphrase3
passphrase4,salt4
```

If a salt is not specified for a passphrase, the default salt (from command line or config) will be used.

## Configuration

You can adjust the settings by editing the `config.yaml` file:

```yaml
# Number of threads to use (0 = use all available CPU cores)
threads: 8

# Default salt to use when no salt is provided in input file or command line
default_salt: ""
```

## File Formats

### Input Files

- `passphrases.txt`: Plain text file with one entry per line (format: "passphrase" or "passphrase,salt")
- `address.hash`: Plain text file with one hash160 (40 hex characters) per line

### Output File

- `found.hash`: CSV file with format: `passphrase,salt,private_key_hex,hash160_hex`

## Performance Tips

1. BrainwalletIO is computationally intensive due to scrypt
2. Use a smaller batch size to prevent memory pressure
3. Adjust thread count based on your CPU cores and memory availability
4. Consider processing fewer passphrases at a time with multiple runs 