#pragma once

#include <vector>
#include <string>
#include <cstdint>

class SimpleCrypto;

namespace FTPProtocol {

    enum class FTPMessageType : uint8_t {
        FILE_START = 1,
        FILE_DATA = 2,
        FILE_END = 3,
        FILE_ERROR = 4,
        DISCONNECT = 5
    };

    constexpr uint32_t MAX_CHUNK_SIZE = 8192;
    constexpr uint32_t MAX_FILENAME_LENGTH = 255;

    // file tranfer struct header
    struct FTPHeader {
        uint8_t messageType;
        uint32_t payloadLength;
        uint32_t sequenceNumber;
        
        FTPHeader(uint8_t type = 0, uint32_t length = 0, uint32_t seq = 0){
            messageType = type;
            payloadLength = length;
            sequenceNumber = seq;
        }
    };

    // file start message struct
    struct FileStartMessage {
        uint32_t filenameLength;
        uint64_t fileSize;
        uint32_t chunkSize;
        
        FileStartMessage(uint32_t name_len = 0, uint64_t size = 0, uint32_t chunk = MAX_CHUNK_SIZE){
            filenameLength = name_len;
            fileSize = size;
            chunkSize = chunk;
        }
    };

    // file data message struct
    struct FileDataMessage {
        uint32_t chunkNumber;
        uint32_t dataLength;
        
        FileDataMessage(uint32_t chunk = 0, uint32_t length = 0){
            chunkNumber = chunk;
            dataLength = length;
        }
    };



    std::vector<uint8_t> serializeHeader(const FTPHeader& header);
    bool deserializeHeader(const std::vector<uint8_t>& data, FTPHeader& header);

    bool parseFileStartMessage(const std::vector<uint8_t>& data, std::string& filename, uint64_t& fileSize, uint32_t& chunkSize);
    bool parseFileDataMessage(const std::vector<uint8_t>& data, uint32_t& chunkNumber, std::vector<uint8_t>& file_data);

    bool sendEncryptedMessage(int socket_fd, uint8_t messageType, const std::vector<uint8_t>& payload, uint32_t sequenceNumber, SimpleCrypto& crypto);
    bool receiveEncryptedMessage(int socket_fd, FTPHeader& header, std::vector<uint8_t>& payload, SimpleCrypto& crypto);
}