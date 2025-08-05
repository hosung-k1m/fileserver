#include "../include/c_file_transfer_protocol.h"
#include "c_simple_crypto.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

namespace FTPProtocol {

    std::vector<uint8_t> serializeHeader(const FTPHeader& header) {
        std::vector<uint8_t> data(sizeof(FTPHeader));
        
        // convert to Big Endian network byte order
        uint32_t payloadLength = htonl(header.payloadLength);
        uint32_t sequenceNumber = htonl(header.sequenceNumber);
        
        // copy the data from the header to vector
        data[0] = header.messageType;
        memcpy(data.data() + 1, &payloadLength, sizeof(uint32_t));
        memcpy(data.data() + 5, &sequenceNumber, sizeof(uint32_t));
        
        return data;
    }

    bool deserializeHeader(const std::vector<uint8_t>& data, FTPHeader& header) {
        if (data.size() < sizeof(FTPHeader)) {
            return false;
        }
        
        // copy data from vector to a FTPHeader
        header.messageType = data[0];
        memcpy(&header.payloadLength, data.data() + 1, sizeof(uint32_t));
        memcpy(&header.sequenceNumber, data.data() + 5, sizeof(uint32_t));
        
        // convert form Big Endian
        header.payloadLength = ntohl(header.payloadLength);
        header.sequenceNumber = ntohl(header.sequenceNumber);
        
        return true;
    }

    std::vector<uint8_t> createFileStartMessage(const std::string& filename, uint64_t fileSize) {
        FileStartMessage msg(filename.length(), fileSize, MAX_CHUNK_SIZE);
        
        // Big Endian
        uint32_t filenameLength = htonl(msg.filenameLength);
        uint64_t fileSizeNet = htobe64(msg.fileSize); 
        uint32_t chunkSize = htonl(msg.chunkSize);
        
        std::vector<uint8_t> data(sizeof(FileStartMessage) + filename.length());
        
        // copy header
        memcpy(data.data(), &filenameLength, sizeof(uint32_t));
        memcpy(data.data() + 4, &fileSizeNet, sizeof(uint64_t));
        memcpy(data.data() + 12, &chunkSize, sizeof(uint32_t));
        
        // copy filename
        memcpy(data.data() + sizeof(FileStartMessage), filename.data(), filename.length());
        
        return data;
    }

    std::vector<uint8_t> createFileDataMessage(uint32_t chunkNumber, const std::vector<uint8_t>& data) {
        FileDataMessage msg(chunkNumber, data.size());
        
        // Big Endian
        uint32_t chunkNumberNet = htonl(msg.chunkNumber);
        uint32_t dataLengthNet = htonl(msg.dataLength);
        
        std::vector<uint8_t> result(sizeof(FileDataMessage) + data.size());
        
        // copy header
        memcpy(result.data(), &chunkNumberNet, sizeof(uint32_t));
        memcpy(result.data() + 4, &dataLengthNet, sizeof(uint32_t));
        
        // copy data
        memcpy(result.data() + sizeof(FileDataMessage), data.data(), data.size());
        
        return result;
    }

    std::vector<uint8_t> createFileEndMessage() {
        return std::vector<uint8_t>(); // empty message
    }
    
    bool sendEncryptedMessage(int socket_fd, uint8_t messageType, const std::vector<uint8_t>& payload, uint32_t sequenceNumber, SimpleCrypto& crypto) {
        FTPHeader header(messageType, payload.size(), sequenceNumber);

        std::vector<uint8_t> headerData = serializeHeader(header);
        
        // simple encryption of the header
        std::vector<uint8_t> encryptedHeader = crypto.encryptPacket(headerData);
        
        // send encrypted header size
        uint32_t headerSize = htonl(encryptedHeader.size());
        ssize_t sent = send(socket_fd, &headerSize, sizeof(headerSize), 0);
        if (sent != sizeof(headerSize)) {
            return false;
        }
        
        // send encrypted header data
        sent = send(socket_fd, encryptedHeader.data(), encryptedHeader.size(), 0);
        if (sent != (ssize_t)encryptedHeader.size()) {
            std::cerr << "Server: Failed to send encrypted header, sent " << sent << " bytes" << std::endl;
            return false;
        }
        
        // send encrypted payload
        if (!payload.empty()) {
            std::vector<uint8_t> encryptedPayload = crypto.encryptPacket(payload);
            
            // payload size
            uint32_t payloadSize = htonl(encryptedPayload.size());
            sent = send(socket_fd, &payloadSize, sizeof(payloadSize), 0);
            if (sent != sizeof(payloadSize)) {
                return false;
            }
            
            // encryped payload send
            sent = send(socket_fd, encryptedPayload.data(), encryptedPayload.size(), 0);
            if (sent != (ssize_t)encryptedPayload.size()) {
                return false;
            }
        }
        
        return true;
    }

    bool receiveEncryptedMessage(int socket_fd, FTPHeader& header, std::vector<uint8_t>& payload, SimpleCrypto& crypto) {
        // recieve the size of the encryped message
        std::cout << "Lisening for encrypted message..." << std::endl;

        uint32_t encryptedSize;
        ssize_t received = recv(socket_fd, &encryptedSize, sizeof(encryptedSize), MSG_WAITALL);
        if (received != sizeof(encryptedSize)) {
            std::cerr << "Failed to receive encrypted size, got " << received << " bytes" << std::endl;
            return false;
        }
        encryptedSize = ntohl(encryptedSize);
        
        // receive the encrypted header
        std::vector<uint8_t> encryptedHeaderData(encryptedSize);
        received = recv(socket_fd, encryptedHeaderData.data(), encryptedHeaderData.size(), MSG_WAITALL);
        if (received != (ssize_t)encryptedHeaderData.size()) {
            std::cerr << "Failed to receive encrypted header, got " << received << " bytes, expected " << encryptedHeaderData.size() << std::endl;
            return false;
        }
        
        // decrypt header
        std::vector<uint8_t> headerData;
        if (!crypto.decryptPacket(encryptedHeaderData, headerData)) {
            std::cerr << "Failed to decrypt header" << std::endl;
            return false;
        }
        
        // parse header
        if (!deserializeHeader(headerData, header)) {
            std::cerr << "Failed to deserialize header" << std::endl;
            return false;
        }
        
        // receive encrupted payload
        if (header.payloadLength > 0) {
            // receive payload size
            uint32_t payloadEncryptedSize;
            received = recv(socket_fd, &payloadEncryptedSize, sizeof(payloadEncryptedSize), MSG_WAITALL);
            if (received != sizeof(payloadEncryptedSize)) {
                std::cerr << "Failed to receive payload encrypted size, got " << received << " bytes" << std::endl;
                return false;
            }
            payloadEncryptedSize = ntohl(payloadEncryptedSize);
            
            // receive encrypted payload
            std::vector<uint8_t> encryptedPayload(payloadEncryptedSize);
            received = recv(socket_fd, encryptedPayload.data(), encryptedPayload.size(), MSG_WAITALL);
            if (received != (ssize_t)encryptedPayload.size()) {
                std::cerr << "Failed to receive encrypted payload, got " << received << " bytes, expected " << encryptedPayload.size() << std::endl;
                return false;
            }
            
            // decrypt payload
            if (!crypto.decryptPacket(encryptedPayload, payload)) {
                std::cerr << "Failed to decrypt payload" << std::endl;
                return false;
            }
            // std::cout << "Decrypted payload size: " << payload.size() << " bytes" << std::endl;
            
        } else {
            payload.clear();
        }
        
        return true;
    }

}