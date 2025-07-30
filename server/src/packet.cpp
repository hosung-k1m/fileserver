#include "../include/packet.h"
#include <cstdlib>
#include <iostream>
#include <openssl/rand.h> // For secure random bytes

/*
FORMAT NEEDED:
packet length
padding length
payload
padding
*/

std::vector<uint8_t> wrapPacket(const std::vector<uint8_t>& payload) {
    size_t blockSize = 8;
    size_t payloadLen = payload.size();
    size_t minPad = 4;

    // According to RFC 4253:
    // packet_length = padding_length + payload_length + 1
    // Total transmitted = 4 + packet_length
    // We need (4 + packet_length) % blockSize == 0
    
    size_t totalNoPad = 4 + 1 + payloadLen; // length field + padding_length byte + payload
    size_t paddingLen = blockSize - (totalNoPad % blockSize);

    if (paddingLen < minPad) {
        paddingLen += blockSize;
    }

    size_t packetLength = 1 + payloadLen + paddingLen; // padding_length byte + payload + padding
    std::vector<uint8_t> packet;
    packet.reserve(4 + packetLength);

    // Packet length
    packet.push_back((packetLength >> 24) & 0xFF);
    packet.push_back((packetLength >> 16) & 0xFF);
    packet.push_back((packetLength >> 8) & 0xFF);
    packet.push_back((packetLength & 0xFF));

    // Padding length
    packet.push_back(static_cast<uint8_t>(paddingLen));

    // Payload
    packet.insert(packet.end(), payload.begin(), payload.end());

    // Random padding
    std::vector<uint8_t> padding(paddingLen);
    RAND_bytes(padding.data(), paddingLen); // Secure random bytes
    packet.insert(packet.end(), padding.begin(), padding.end());

    return packet;
}

std::vector<uint8_t> unwrapPacket(const std::vector<uint8_t>& packet) {
    if (packet.size() < 6) {
        std::cerr << "Packet too short: " << packet.size() << " bytes\n";
        return {}; // Invalid packet
    }

    // Extract packet length (first 4 bytes)
    uint32_t packetLength = (packet[0] << 24) | (packet[1] << 16) | (packet[2] << 8) | packet[3];
    
    // Extract padding length (5th byte)
    uint8_t paddingLength = packet[4];
    
    // Calculate payload length
    size_t payloadLength = packetLength - paddingLength - 1; // -1 for padding length byte
    
    // std::cerr << "Packet length: " << packetLength << ", padding length: " << (int)paddingLength 
    //           << ", payload length: " << payloadLength << ", total packet size: " << packet.size() << "\n";
    
    // Extract payload (starts at byte 5, length is payloadLength)
    if (packet.size() < 5 + payloadLength) {
        std::cerr << "Packet too short for payload\n";
        return {}; // Packet too short
    }
    
    return std::vector<uint8_t>(packet.begin() + 5, packet.begin() + 5 + payloadLength);
}