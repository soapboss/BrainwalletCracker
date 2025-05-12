#!/bin/bash

# Number of passphrases to generate for the benchmark
# Using a smaller number due to WarpWallet's computational intensity
NUM_PASSPHRASES=1000

# Create a benchmark passphrases file
echo "Creating benchmark passphrase file with $NUM_PASSPHRASES passphrases..."
rm -f benchmark_passphrases.txt

for i in $(seq 1 $NUM_PASSPHRASES); do
    # Add some with salts, some without
    if [ $((i % 3)) -eq 0 ]; then
        echo "password$i,salt$i@example.com" >> benchmark_passphrases.txt
    else
        echo "password$i" >> benchmark_passphrases.txt
    fi
    
    if [ $((i % 100)) -eq 0 ]; then
        echo "Generated $i passphrases..."
    fi
done

# Create a benchmark address file with a single impossible-to-match address
echo "Creating benchmark address file..."
echo "0000000000000000000000000000000000000000" > benchmark_address.hash

# Run the benchmark with default threads
echo "Running benchmark with default threads..."
time ./brainflayer_warpwallet -f benchmark_passphrases.txt -a benchmark_address.hash -o benchmark_found.hash -s "benchmark@example.com"

# Clean up
echo "Benchmark completed. Cleaning up..."
rm -f benchmark_passphrases.txt benchmark_address.hash benchmark_found.hash

echo "Note: WarpWallet is computationally intensive. Adjust config.yaml and batch sizes for optimal performance on your system." 