#pragma once
#include <vector>
#include <string>
#include <cstdint>

namespace ITPProtocol {
    constexpr uint32_t MAX_PAYLOAD_SIZE = 65536;
    constexpr uint32_t HEADER_SIZE = 16;

    enum class ITPMessageType : uint8_t {
        CONNECT = 1,
        DISCONNECT = 2,
    };

    struct ITPHeader {
        uint8_t messageType;
        uint32_t payloadLength;
        uint32_t sequenceNumber;
        uint32_t checksum;
        
        ITPHeader(uint8_t type = 0, uint32_t length = 0, uint32_t seq = 0, uint32_t checksum_val = 0){
            messageType = type;
            payloadLength = length;
            sequenceNumber = seq;
            checksum = checksum_val;
        }
    };

    std::vector<uint8_t> serializeHeader(const ITPHeader& header);
    bool deserializeHeader(const std::vector<uint8_t>& data, ITPHeader& header);

    bool sendMessage(int socket_fd, uint8_t messageType, const std::vector<uint8_t>& payload, uint32_t sequenceNumber);
    bool receiveMessage(int socket_fd, ITPHeader& header, std::vector<uint8_t>& payload);

    uint32_t calculateChecksum(const std::vector<uint8_t>& data);
    bool validateChecksum(const std::vector<uint8_t>& data, uint32_t expected_checksum);
} 