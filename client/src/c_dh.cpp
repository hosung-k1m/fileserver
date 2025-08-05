#include "c_dh.h"
#include "c_kex.h"
#include <random>
#include <iostream>
#include <cstring>
#include <arpa/inet.h>


DH::DH() : privateKey(0), publicKey(0) {
    // random private key
    privateKey = simple_rand();
}

uint64_t DH::simple_rand() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis(1, P - 2);
    return dis(gen);
}

// simplified calculation of base ^ secret % mod
uint64_t DH::mod_exp(uint64_t base, uint64_t exponent, uint64_t modulus) {
    if (modulus == 1) return 0;
    
    uint64_t result = 1;
    base = base % modulus;
    
    while (exponent > 0) {
        if (exponent & 1) {
            result = (result * base) % modulus;
        }
        exponent = exponent >> 1;
        base = (base * base) % modulus;
    }
    
    return result;
}

uint64_t DH::generatePublicKey() {
    publicKey = mod_exp(G, privateKey, P);
    return publicKey;
}

// clientPrivate ^ secret % mod
uint64_t DH::computeSharedSecret(uint64_t other_publicKey) const {
    return mod_exp(other_publicKey, privateKey, P);
}

std::vector<uint8_t> DH::uint64ToBytes(uint64_t value) {
    std::vector<uint8_t> bytes(8);
    for (int i = 0; i < 8; i++) {
        bytes[7 - i] = (value >> (i * 8)) & 0xFF;
    }
    return bytes;
}

uint64_t DH::bytesToUint64(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 8) return 0;
    
    uint64_t value = 0;
    for (int i = 0; i < 8; i++) {
        value = (value << 8) | bytes[i];
    }
    return value;
}

bool handleKexDhReply(const std::vector<uint8_t>& reply, const DH& dh, uint64_t& sharedSecret) {
    if (reply.empty() || reply[0] != 31) {
        std::cerr << "Invalid KEXDH_REPLY message type" << std::endl;
        return false;
    }
    
    size_t offset = 1;
    
    if (offset + 4 > reply.size()) return false;
    uint32_t hostKeyLength = ntohl(*(uint32_t*)(reply.data() + offset));
    offset += 4 + hostKeyLength;
    
    // read server public key
    if (offset + 4 > reply.size()) return false;
    uint32_t serverPublicLength = ntohl(*(uint32_t*)(reply.data() + offset));
    offset += 4;
    
    if (offset + serverPublicLength > reply.size()) return false;
    std::vector<uint8_t> serverPublicBytes(reply.begin() + offset, reply.begin() + offset + serverPublicLength);
    uint64_t serverPublicKey = DH::bytesToUint64(serverPublicBytes);
    
    // compute shared secret
    sharedSecret = dh.computeSharedSecret(serverPublicKey);
    
    std::cout << "Computed shared secret: " << std::hex << sharedSecret << std::dec << std::endl;
    
    return true;
} 