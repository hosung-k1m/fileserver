#pragma once
#include <vector>
#include <cstdint>

// a simple DH key exchange using smaller prime number but same idea
class DH {
private:
    
    static constexpr uint64_t P = 0x7FFFFFFF; // large enough but simple prime
    static constexpr uint64_t G = 2; // generator of 2
    
    uint64_t privateKey;
    uint64_t publicKey;
    
    static uint64_t mod_exp(uint64_t base, uint64_t exponent, uint64_t modulus);
    
    static uint64_t simple_rand();

public:
    DH();
    
    uint64_t generatePublicKey();
    
    uint64_t get_publicKey() const { return publicKey; }
    
    uint64_t computeSharedSecret(uint64_t other_publicKey) const;
    
    static std::vector<uint8_t> uint64ToBytes(uint64_t value);
    static uint64_t bytesToUint64(const std::vector<uint8_t>& bytes);
}; 