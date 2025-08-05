#include "../include/s_internet_traffic_protocol.h"
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>

namespace ITPProtocol {

    // serialize for sending over intnernet
    std::vector<uint8_t> serializeHeader(const ITPHeader& header) {
        std::vector<uint8_t> data(HEADER_SIZE);
        
        // convert to Big Endian network byte order
        uint32_t payloadLength = htonl(header.payloadLength);
        uint32_t sequenceNumber = htonl(header.sequenceNumber);
        uint32_t checksum = htonl(header.checksum);
        
        // copy data safely to Data
        data[0] = header.messageType;
        memcpy(data.data() + 1, &payloadLength, sizeof(uint32_t));
        memcpy(data.data() + 5, &sequenceNumber, sizeof(uint32_t));
        memcpy(data.data() + 9, &checksum, sizeof(uint32_t));
        
        return data;
    }

    // from internet to header format
    bool deserializeHeader(const std::vector<uint8_t>& data, ITPHeader& header) {
        if (data.size() < HEADER_SIZE) {
            return false;
        }
        
        // Copy from data to header
        header.messageType = data[0];
        memcpy(&header.payloadLength, data.data() + 1, sizeof(uint32_t));
        memcpy(&header.sequenceNumber, data.data() + 5, sizeof(uint32_t));
        memcpy(&header.checksum, data.data() + 9, sizeof(uint32_t));
        
        // convert to Big Endian network byte order
        header.payloadLength = ntohl(header.payloadLength);
        header.sequenceNumber = ntohl(header.sequenceNumber); // order of messages
        header.checksum = ntohl(header.checksum);
        
        return true;
    }

    bool sendMessage(int socket_fd, uint8_t messageType, const std::vector<uint8_t>& payload, uint32_t sequenceNumber) {
        // checksum
        uint32_t checksum = calculateChecksum(payload);
        
        // create header struct
        ITPHeader header(messageType, payload.size(), sequenceNumber, checksum);
        std::vector<uint8_t> headerData = serializeHeader(header);
        
        // send header so client knows what to expect
        ssize_t sent = send(socket_fd, headerData.data(), headerData.size(), 0);
        if (sent != (ssize_t)headerData.size()) {
            std::cerr << "Failed to send header: " << sent << " != " << headerData.size() << std::endl;
            return false;
        }
        
        // send payload after sending header
        if (!payload.empty()) {
            sent = send(socket_fd, payload.data(), payload.size(), 0);
            if (sent != (ssize_t)payload.size()) {
                std::cerr << "Failed to send payload: " << sent << " != " << payload.size() << std::endl;
                return false;
            }
        }
        
        return true;
    }

    bool receiveMessage(int socket_fd, ITPHeader& header, std::vector<uint8_t>& payload) {
        // receive header serailized
        std::vector<uint8_t> headerData(HEADER_SIZE);
        ssize_t received = recv(socket_fd, headerData.data(), headerData.size(), MSG_WAITALL);
        if (received != (ssize_t)headerData.size()) {
            std::cerr << "Failed to receive header: " << received << " != " << headerData.size() << std::endl;
            return false;
        }
        
        // parse header to struct
        if (!deserializeHeader(headerData, header)) {
            std::cerr << "Failed to deserialize header" << std::endl;
            return false;
        }
        
        // make sure payload size is valid
        if (header.payloadLength > MAX_PAYLOAD_SIZE) {
            std::cerr << "Payload too large: " << header.payloadLength << " > " << MAX_PAYLOAD_SIZE << std::endl;
            return false;
        }
        
        // recieve payload
        if (header.payloadLength > 0) {
            payload.resize(header.payloadLength);
            received = recv(socket_fd, payload.data(), payload.size(), MSG_WAITALL);
            if (received != (ssize_t)payload.size()) {
                std::cerr << "Failed to receive payload: " << received << " != " << payload.size() << std::endl;
                return false;
            }
            
            // check the checksum for data integrity
            if (!validateChecksum(payload, header.checksum)) {
                std::cerr << "Checksum validation failed" << std::endl;
                return false;
            }
        } else {
            payload.clear();
        }
        
        return true;
    }


    // simplified rolling hash DJB2 Hash function
    uint32_t calculateChecksum(const std::vector<uint8_t>& data) {
        uint32_t checksum = 0;
        for (uint8_t byte : data) {
            checksum = ((checksum << 5) + checksum) + byte;
        }
        return checksum;
    }

    // verify the checksum from header is the checksum of payload. To verify payload integrity
    bool validateChecksum(const std::vector<uint8_t>& data, uint32_t expected_checksum) {
        uint32_t calculated_checksum = calculateChecksum(data);

        if (calculated_checksum == expected_checksum) {
            return true;
        }
        else {
            return false;
        }
    }

}