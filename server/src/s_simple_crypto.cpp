#include "../include/s_simple_crypto.h"
#include <iostream>
#include <cstring>
#include <algorithm>

SimpleCrypto::SimpleCrypto(uint64_t sharedSecret, bool is_client) {

    sequence_number_ = 0;
    
    // derive the encryption key from the DH and constant string
    std::string direction = is_client ? "client_to_server" : "server_to_client";
    key_ = deriveKey(sharedSecret, direction);
    
    // IV (initialization vector) from shared secret
    iv_ = deriveKey(sharedSecret, "iv_" + direction);
    
    // make IV 16 bytes
    if (iv_.size() > 16){
        iv_.resize(16);
    } 
    if (iv_.size() < 16) {
        iv_.resize(16, 0);
    }

    // std::cout << "Initialized SimpleCrypto with DH key (size: " << key_.size() << " bytes)" << std::endl;
}

std::vector<uint8_t> SimpleCrypto::deriveKey(uint64_t sharedSecret, const std::string& purpose) {
    // hash shared secret with purpose string
    std::vector<uint8_t> input;
    
    // shared secret bytes in Little Endian format
    for (int i = 0; i < 8; i++) {
        input.push_back((sharedSecret >> (i * 8)) & 0xFF);
    }
    
    // purpose string ASCII values
    input.insert(input.end(), purpose.begin(), purpose.end());
    
    // simple hash, XOR all bytes with position and then mod 32
    std::vector<uint8_t> hash(32, 0);
    for (size_t i = 0; i < input.size(); i++) {
        hash[i % 32] ^= input[i] ^ (i & 0xFF);
    }
    
    return hash;
}

std::vector<uint8_t> SimpleCrypto::simpleHash(const std::vector<uint8_t>& data) {
    // hash function, XOR with position and rotate
    std::vector<uint8_t> hash(16, 0);
    
    for (size_t i = 0; i < data.size(); i++) {
        uint8_t byte = data[i];
        uint8_t pos = i & 0xFF;
        
        // rotate and XOR
        for (int j = 0; j < 16; j++) {
            hash[j] ^= byte ^ pos ^ ((i + j) & 0xFF);
            byte = (byte << 1) | (byte >> 7); // rotate left
        }
    }
    
    return hash;
}

void SimpleCrypto::updateIV() {
    //IV update using sequence number
    for (size_t i = 0; i < iv_.size(); i++) {
        iv_[i] ^= (sequence_number_ >> (i % 4 * 8)) & 0xFF;
    }
}

std::vector<uint8_t> SimpleCrypto::xorEncrypt(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> encrypted(data.size());
    
    for (size_t i = 0; i < data.size(); i++) {
        // XOR with key, IV, and position
        uint8_t key_byte = key_[i % key_.size()];
        uint8_t iv_byte = iv_[i % iv_.size()];
        uint8_t pos_byte = (i + sequence_number_) & 0xFF;
        
        encrypted[i] = data[i] ^ key_byte ^ iv_byte ^ pos_byte;
    }
    
    return encrypted;
}

std::vector<uint8_t> SimpleCrypto::xorDecrypt(const std::vector<uint8_t>& data) {
    // encryption is symmetric
    return xorEncrypt(data);
}

std::vector<uint8_t> SimpleCrypto::encryptPacket(const std::vector<uint8_t>& rawPacket) {
    // update IV for this sequence
    updateIV();
    
    // encrypt the packet
    std::vector<uint8_t> encrypted = xorEncrypt(rawPacket);
    
    // create MAC --> hash(sequenceNumber || encrypted_data)
    std::vector<uint8_t> macInput;
    macInput.push_back((sequence_number_ >> 24) & 0xFF);
    macInput.push_back((sequence_number_ >> 16) & 0xFF);
    macInput.push_back((sequence_number_ >> 8) & 0xFF);
    macInput.push_back(sequence_number_ & 0xFF);
    macInput.insert(macInput.end(), encrypted.begin(), encrypted.end());
    
    std::vector<uint8_t> mac = simpleHash(macInput);
    
    // combine encrypted data and MAC
    std::vector<uint8_t> result;
    result.insert(result.end(), encrypted.begin(), encrypted.end());
    result.insert(result.end(), mac.begin(), mac.end());
    
    sequence_number_++;
    
    return result;
}

bool SimpleCrypto::decryptPacket(const std::vector<uint8_t>& encryptedPacket, std::vector<uint8_t>& rawPacketOut) {
    if (encryptedPacket.size() < 16) {
        std::cerr << "Packet too short for MAC" << std::endl;
        return false;
    }
    
    // seperate encrypted data and MAC
    size_t data_size = encryptedPacket.size() - 16;
    std::vector<uint8_t> encrypted_data(encryptedPacket.begin(), encryptedPacket.begin() + data_size);
    std::vector<uint8_t> recievedMac(encryptedPacket.begin() + data_size, encryptedPacket.end());
    
    // verify MAC
    std::vector<uint8_t> macInput;
    macInput.push_back((sequence_number_ >> 24) & 0xFF);
    macInput.push_back((sequence_number_ >> 16) & 0xFF);
    macInput.push_back((sequence_number_ >> 8) & 0xFF);
    macInput.push_back(sequence_number_ & 0xFF);
    macInput.insert(macInput.end(), encrypted_data.begin(), encrypted_data.end());
    
    std::vector<uint8_t> computedMac = simpleHash(macInput);
    
    if (recievedMac != computedMac) {
        std::cerr << "MAC verification failed" << std::endl;
        return false;
    }
    
    // std::cout << "MAC verification passed! Sequence number: " << sequence_number_ << std::endl;
    
    updateIV();
    
    rawPacketOut = xorDecrypt(encrypted_data);
    
    sequence_number_++;
    
    return true;
} 