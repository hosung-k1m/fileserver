#pragma once

#include <vector>
#include <cstdint>
#include <string>

/**
 * simplified symetric encryption system using XOR for IV and the ley from DH shared secret
 * MAC integrity checks
 */

class SimpleCrypto {
    private:
        std::vector<uint8_t> key_;
        std::vector<uint8_t> iv_;
        uint32_t sequence_number_;
        
        static std::vector<uint8_t> deriveKey(uint64_t sharedSecret, const std::string& purpose);
        
        std::vector<uint8_t> xorEncrypt(const std::vector<uint8_t>& data);
        std::vector<uint8_t> xorDecrypt(const std::vector<uint8_t>& data);
        
        static std::vector<uint8_t> simpleHash(const std::vector<uint8_t>& data);
        
        void updateIV();

    public:
        SimpleCrypto(uint64_t sharedSecret, bool is_client);
        
        std::vector<uint8_t> encryptPacket(const std::vector<uint8_t>& rawPacket);
        
        bool decryptPacket(const std::vector<uint8_t>& encryptedPacket, std::vector<uint8_t>& rawPacketOut);
}; 