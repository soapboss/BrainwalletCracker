#!/bin/bash

# Create a small test passphrases file
echo "Creating test passphrase file..."
cat > test_passphrases.txt << EOF
correct,battery
passphrase,salt
test,123@qq.com
123456,abc@example.com
EOF

# Create a test address file with known BrainwalletIO hash160 for "passphrase" with salt "salt"
# This hash160 corresponds to the uncompressed Bitcoin address generated from BrainwalletIO with passphrase "passphrase" and salt "salt"
echo "Creating test address file..."
echo "930322dc5cfcb3ec785a500f06da46d45149b568" > test_address.hash

# Run the program
echo "Running brainflayer_brainwalletio..."
./brainflayer_brainwalletio -f test_passphrases.txt -a test_address.hash -o test_found.hash

# Check if we found a match
if [ -s test_found.hash ]; then
    echo "Success! Match found in test_found.hash:"
    cat test_found.hash
else
    echo "No match found. Something might be wrong with the implementation."
fi

echo "Test completed." 