#include "../include/s_file_transfer_protocol.h"
#include "s_simple_crypto.h"
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

    bool parseFileStartMessage(const std::vector<uint8_t>& data, std::string& filename, uint64_t& fileSize, uint32_t& chunkSize) {
        // std::cout << "parseFileStartMessage - data size = " << data.size() << ", FileStartMessage size = " << sizeof(FileStartMessage) << std::endl;
        
        // std::cout << "Server: First 16 bytes: ";
        // for (int i = 0; i < std::min(16, (int)data.size()); i++) {
        //     printf("%02x ", data[i]);
        // }
        // std::cout << std::endl;
        
        if (data.size() < sizeof(FileStartMessage)) {
            std::cerr << "parseFileStartMessage: data too small" << std::endl;
            return false;
        }
        
        uint32_t filenameLength;
        uint64_t fileSizeNet;
        uint32_t chunk_size_net;
        
        memcpy(&filenameLength, data.data(), sizeof(uint32_t));
        memcpy(&fileSizeNet, data.data() + 4, sizeof(uint64_t));
        memcpy(&chunk_size_net, data.data() + 12, sizeof(uint32_t));
        
        // std::cout << "parseFileStartMessage: raw values - filenameLength=" << filenameLength 
        //         << ", fileSizeNet=" << fileSizeNet 
        //         << ", chunk_size_net=" << chunk_size_net << std::endl;
        

        // convert from Big Endian
        filenameLength = ntohl(filenameLength);
        fileSize = be64toh(fileSizeNet);
        chunkSize = ntohl(chunk_size_net);
        

        // std::cout << "parseFileStartMessage: converted values - filenameLength=" << filenameLength 
        //         << ", fileSize=" << fileSize 
        //         << ", chunkSize=" << chunkSize << std::endl;
        
        if (data.size() < sizeof(FileStartMessage) + filenameLength) {
            std::cerr << "parseFileStartMessage: data too small for filename" << std::endl;
            return false;
        }
        
        filename.assign(data.begin() + sizeof(FileStartMessage), data.begin() + sizeof(FileStartMessage) + filenameLength);
        
        return true;
    }

    bool parseFileDataMessage(const std::vector<uint8_t>& data, uint32_t& chunkNumber, std::vector<uint8_t>& file_data) {
        if (data.size() < sizeof(FileDataMessage)) {
            return false;
        }
        
        FileDataMessage msg;
        memcpy(&msg, data.data(), sizeof(FileDataMessage));
        
        uint32_t chunkNumberNet = ntohl(msg.chunkNumber);
        uint32_t dataLengthNet = ntohl(msg.dataLength);
        
        if (data.size() < sizeof(FileDataMessage) + dataLengthNet) {
            return false;
        }
        
        chunkNumber = chunkNumberNet;
        file_data.assign(data.begin() + sizeof(FileDataMessage), data.begin() + sizeof(FileDataMessage) + dataLengthNet);
        
        return true;
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