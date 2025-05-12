#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <unordered_set>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <yaml-cpp/yaml.h>
#include <libscrypt.h>

// Hash160 is 20 bytes (RIPEMD160 output)
#define HASH160_LENGTH 20

// WarpWallet parameters
#define SCRYPT_N 262144  // 2^18
#define SCRYPT_R 8
#define SCRYPT_P 1
#define PBKDF2_ITERATIONS 65536

// Class for Bitcoin cryptography operations
class BitcoinCrypto {
private:
    // Convert bytes to hex string
    static std::string bytesToHex(const unsigned char* data, size_t len) {
        std::string result;
        result.reserve(len * 2);
        
        static const char hex[] = "0123456789abcdef";
        for (size_t i = 0; i < len; ++i) {
            unsigned char byte = data[i];
            result.push_back(hex[byte >> 4]);
            result.push_back(hex[byte & 0xF]);
        }
        
        return result;
    }

public:
    // Generate private key using WarpWallet algorithm (scrypt + PBKDF2)
    static std::vector<unsigned char> generatePrivKeyWarpwallet(const std::string& passphrase, const std::string& salt) {
        std::vector<unsigned char> privkey(32); // 32 bytes for private key
        
        // WarpWallet uses a combination of scrypt and PBKDF2
        // We need to append special bytes to passphrase and salt
        
        // For scrypt: append \u0001 to both passphrase and salt
        std::vector<unsigned char> passphraseScrypt(passphrase.begin(), passphrase.end());
        passphraseScrypt.push_back(1);  // \u0001
        
        std::vector<unsigned char> saltScrypt(salt.begin(), salt.end());
        saltScrypt.push_back(1);  // \u0001
        
        // For PBKDF2: append \u0002 to both passphrase and salt
        std::vector<unsigned char> passphrasePbkdf(passphrase.begin(), passphrase.end());
        passphrasePbkdf.push_back(2);  // \u0002
        
        std::vector<unsigned char> saltPbkdf(salt.begin(), salt.end());
        saltPbkdf.push_back(2);  // \u0002
        
        // Step 1: Generate first key with scrypt
        unsigned char seed1[32];
        int ret = libscrypt_scrypt(
            passphraseScrypt.data(), passphraseScrypt.size(),
            saltScrypt.data(), saltScrypt.size(),
            SCRYPT_N, SCRYPT_R, SCRYPT_P,
            seed1, 32
        );
        
        if (ret != 0) {
            std::cerr << "Error in scrypt computation" << std::endl;
            return privkey; // Return zeros on error
        }
        
        // Step 2: Generate second key with PBKDF2-HMAC-SHA256
        unsigned char seed2[32];
        PKCS5_PBKDF2_HMAC(
            reinterpret_cast<const char*>(passphrasePbkdf.data()), passphrasePbkdf.size(),
            saltPbkdf.data(), saltPbkdf.size(),
            PBKDF2_ITERATIONS,
            EVP_sha256(),
            32, seed2
        );
        
        // Step 3: XOR the two seeds to get the final private key
        for (int i = 0; i < 32; i++) {
            privkey[i] = seed1[i] ^ seed2[i];
        }
        
        return privkey;
    }
    
    // Generate uncompressed public key from private key
    static std::vector<unsigned char> generatePubKey(const std::vector<unsigned char>& privkey) {
        std::vector<unsigned char> pubkey(65); // Uncompressed public key is 65 bytes
        
        EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (!key) return {};
        
        BIGNUM* priv_bn = BN_bin2bn(privkey.data(), privkey.size(), NULL);
        if (!priv_bn) {
            EC_KEY_free(key);
            return {};
        }
        
        if (!EC_KEY_set_private_key(key, priv_bn)) {
            BN_free(priv_bn);
            EC_KEY_free(key);
            return {};
        }
        
        const EC_GROUP* group = EC_KEY_get0_group(key);
        EC_POINT* pub_point = EC_POINT_new(group);
        
        if (!EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL)) {
            EC_POINT_free(pub_point);
            BN_free(priv_bn);
            EC_KEY_free(key);
            return {};
        }
        
        EC_KEY_set_public_key(key, pub_point);
        
        // Format as uncompressed public key
        size_t pubkey_size = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED,
                                             pubkey.data(), pubkey.size(), NULL);
        
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        EC_KEY_free(key);
        
        if (pubkey_size != 65) {
            return {};
        }
        
        return pubkey;
    }
    
    // Generate Bitcoin hash160 from public key
    static std::vector<unsigned char> generateHash160(const std::vector<unsigned char>& pubkey) {
        // Hash the public key with SHA-256 and RIPEMD-160
        unsigned char hash[SHA256_DIGEST_LENGTH];
        std::vector<unsigned char> hash160(RIPEMD160_DIGEST_LENGTH);
        
        // Step 1: SHA-256
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, pubkey.data(), pubkey.size());
        SHA256_Final(hash, &sha256);
        
        // Step 2: RIPEMD-160
        RIPEMD160_CTX ripemd160;
        RIPEMD160_Init(&ripemd160);
        RIPEMD160_Update(&ripemd160, hash, SHA256_DIGEST_LENGTH);
        RIPEMD160_Final(hash160.data(), &ripemd160);
        
        return hash160;
    }
    
    // Convert hash160 to hex string
    static std::string hash160ToHex(const std::vector<unsigned char>& hash160) {
        return bytesToHex(hash160.data(), hash160.size());
    }
    
    // Convert privkey to hex string
    static std::string privKeyToHex(const std::vector<unsigned char>& privkey) {
        return bytesToHex(privkey.data(), privkey.size());
    }
};

// Load target addresses from file
std::unordered_set<std::string> loadAddresses(const std::string& filename) {
    std::unordered_set<std::string> addresses;
    std::ifstream file(filename);
    std::string line;
    
    while (std::getline(file, line)) {
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        
        if (!line.empty()) {
            addresses.insert(line);
        }
    }
    
    return addresses;
}

// Load configuration from config.yaml
struct Config {
    int numThreads;
    std::string defaultSalt;
};

Config loadConfig() {
    Config config;
    config.defaultSalt = ""; // Default empty salt
    
    try {
        YAML::Node yaml = YAML::LoadFile("config.yaml");
        config.numThreads = yaml["threads"].as<int>();
        if (yaml["default_salt"]) {
            config.defaultSalt = yaml["default_salt"].as<std::string>();
        }
    } catch (...) {
        // Default configuration if file can't be loaded
        config.numThreads = std::thread::hardware_concurrency();
    }
    
    // Ensure at least one thread
    if (config.numThreads < 1) {
        config.numThreads = 1;
    }
    
    return config;
}

// Parse input line for passphrase and salt
// Format can be: "passphrase" or "passphrase,salt"
std::pair<std::string, std::string> parseInputLine(const std::string& line, const std::string& defaultSalt) {
    std::string passphrase = line;
    std::string salt = defaultSalt;
    
    // Check if line contains a comma (passphrase,salt format)
    size_t commaPos = line.find(',');
    if (commaPos != std::string::npos) {
        passphrase = line.substr(0, commaPos);
        salt = line.substr(commaPos + 1);
    }
    
    return {passphrase, salt};
}

// Shared resources
std::mutex foundMutex;
std::mutex consoleMutex;
std::atomic<size_t> processedPassphrases(0);
std::atomic<size_t> foundMatches(0);

// Process a batch of passphrases
void processBatch(
    const std::vector<std::string>& inputLines, 
    const std::unordered_set<std::string>& targetAddresses,
    const std::string& outputFile,
    size_t threadId,
    const std::string& defaultSalt
) {
    std::ofstream outFile;
    
    for (const auto& line : inputLines) {
        // Parse the input line to get passphrase and salt
        auto [passphrase, salt] = parseInputLine(line, defaultSalt);
        
        // Generate private key using WarpWallet
        auto privKey = BitcoinCrypto::generatePrivKeyWarpwallet(passphrase, salt);
        
        // Generate public key (uncompressed)
        auto pubKey = BitcoinCrypto::generatePubKey(privKey);
        if (pubKey.empty()) continue;
        
        // Generate hash160
        auto hash160 = BitcoinCrypto::generateHash160(pubKey);
        
        // Check if hash160 is in target list
        std::string hash160Hex = BitcoinCrypto::hash160ToHex(hash160);
        
        if (targetAddresses.find(hash160Hex) != targetAddresses.end()) {
            // Found a match!
            std::string privKeyHex = BitcoinCrypto::privKeyToHex(privKey);
            
            std::lock_guard<std::mutex> lock(foundMutex);
            if (!outFile.is_open()) {
                outFile.open(outputFile, std::ios::app);
            }
            
            outFile << passphrase << "," << salt << "," << privKeyHex << "," << hash160Hex << std::endl;
            outFile.flush();
            
            foundMatches++;
            
            std::lock_guard<std::mutex> consoleLock(consoleMutex);
            std::cout << "Thread " << threadId << " found match: " << passphrase 
                      << " (salt: " << salt << ") -> " << hash160Hex << std::endl;
        }
        
        processedPassphrases++;
    }
}

int main(int argc, char* argv[]) {
    std::string passphraseFile;
    std::string addressFile = "address.hash";
    std::string outputFile = "found.hash";
    std::string cmdSalt;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-f" && i + 1 < argc) {
            passphraseFile = argv[++i];
        } else if (arg == "-a" && i + 1 < argc) {
            addressFile = argv[++i];
        } else if (arg == "-o" && i + 1 < argc) {
            outputFile = argv[++i];
        } else if (arg == "-s" && i + 1 < argc) {
            cmdSalt = argv[++i];
        } else if (arg == "-h") {
            std::cout << "Usage: " << argv[0] << " -f <password_file> [-a <address_file>] [-o <output_file>] [-s <default_salt>]" << std::endl;
            std::cout << "  Each line in password_file can be 'passphrase' or 'passphrase,salt'" << std::endl;
            return 0;
        }
    }
    
    if (passphraseFile.empty()) {
        std::cerr << "Error: Passphrase file is required (-f)" << std::endl;
        std::cerr << "Usage: " << argv[0] << " -f <password_file> [-a <address_file>] [-o <output_file>] [-s <default_salt>]" << std::endl;
        return 1;
    }
    
    // Load configuration
    Config config = loadConfig();
    std::cout << "Using " << config.numThreads << " threads" << std::endl;
    
    // Command-line salt overrides config
    std::string defaultSalt = cmdSalt.empty() ? config.defaultSalt : cmdSalt;
    if (!defaultSalt.empty()) {
        std::cout << "Using default salt: " << defaultSalt << std::endl;
    }
    
    // Load target addresses
    std::cout << "Loading addresses from " << addressFile << "..." << std::endl;
    auto targetAddresses = loadAddresses(addressFile);
    std::cout << "Loaded " << targetAddresses.size() << " addresses" << std::endl;
    
    if (targetAddresses.empty()) {
        std::cerr << "Warning: No addresses loaded from " << addressFile << std::endl;
        return 1;
    }
    
    // Load passphrases
    std::cout << "Loading passphrases from " << passphraseFile << "..." << std::endl;
    std::ifstream passphraseFileStream(passphraseFile);
    if (!passphraseFileStream) {
        std::cerr << "Error: Could not open passphrase file: " << passphraseFile << std::endl;
        return 1;
    }
    
    // Create empty output file
    std::ofstream(outputFile).close();
    
    // Process passphrases in batches using multiple threads
    const size_t batchSize = 100; // Smaller batch size due to more intensive computation
    std::vector<std::string> inputBatch;
    inputBatch.reserve(batchSize);
    
    std::vector<std::thread> threads;
    std::string line;
    
    auto startTime = std::chrono::steady_clock::now();
    size_t totalInputs = 0;
    
    // Read input lines and distribute to threads
    while (std::getline(passphraseFileStream, line)) {
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        
        if (!line.empty()) {
            inputBatch.push_back(line);
            totalInputs++;
            
            if (inputBatch.size() >= batchSize) {
                // Launch a thread to process this batch
                if (threads.size() >= config.numThreads) {
                    // Wait for a thread to finish before creating a new one
                    threads[0].join();
                    threads.erase(threads.begin());
                }
                
                threads.emplace_back(processBatch, inputBatch, std::ref(targetAddresses), 
                                    outputFile, threads.size(), defaultSalt);
                
                inputBatch.clear();
                inputBatch.reserve(batchSize);
            }
        }
    }
    
    // Process any remaining inputs
    if (!inputBatch.empty()) {
        threads.emplace_back(processBatch, inputBatch, std::ref(targetAddresses), 
                            outputFile, threads.size(), defaultSalt);
    }
    
    // Wait for all threads to finish
    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
    
    std::cout << "Processed " << totalInputs << " inputs in " << duration.count() << " seconds" << std::endl;
    std::cout << "Found " << foundMatches << " matches" << std::endl;
    
    if (foundMatches > 0) {
        std::cout << "Matches saved to " << outputFile << std::endl;
    }
    
    return 0;
} 