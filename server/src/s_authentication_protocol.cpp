#include "../include/s_authentication_protocol.h"
#include "../include/s_internet_traffic_protocol.h"
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <map>

namespace AuthProtocol {

    bool parseAuthMessage(const std::vector<uint8_t>& data, std::string& username, std::string& password) {
        if (data.size() < sizeof(AuthMessage)) {
            return false;
        }
        
        // read data from struct
        uint32_t usernameLength, passwordLength;
        memcpy(&usernameLength, data.data(), sizeof(uint32_t));
        memcpy(&passwordLength, data.data() + 4, sizeof(uint32_t));
        
        // convert from Big Endian
        usernameLength = ntohl(usernameLength);
        passwordLength = ntohl(passwordLength);
        
        // check length
        if (usernameLength > MAX_USERNAME_LENGTH || passwordLength > MAX_PASSWORD_LENGTH) {
            return false;
        }
        
        if (data.size() < sizeof(AuthMessage) + usernameLength + passwordLength) {
            return false;
        }
        
        // convert bytes to string
        username = std::string(data.begin() + sizeof(AuthMessage), 
                            data.begin() + sizeof(AuthMessage) + usernameLength);
        password = std::string(data.begin() + sizeof(AuthMessage) + usernameLength,
                            data.begin() + sizeof(AuthMessage) + usernameLength + passwordLength);
        
        return true;
    }

    bool validateCredentials(const std::string& username, const std::string& password, 
                        const std::map<std::string, std::string>& users) {
        auto it = users.find(username);
        // doe not exist
        if (it == users.end()) {
            return false;
        }

        if (it->second == password) {
            return true;
        }
        else {
            return false;
        }
    }

    bool sendAuthResponse(int socket_fd, bool success) {
        uint8_t messageType;
        if (success) {
            messageType = static_cast<uint8_t>(AuthMessageType::AUTH_SUCCESS);
        } else {
            messageType = static_cast<uint8_t>(AuthMessageType::AUTH_FAILURE);
        }
        return ITPProtocol::sendMessage(socket_fd, messageType, {}, 0);
    }

    // check if request is of type auth request and get payload
    bool receiveAuthRequest(int socket_fd, std::string& username, std::string& password) {
        ITPProtocol::ITPHeader header;
        std::vector<uint8_t> payload;
        
        if (!ITPProtocol::receiveMessage(socket_fd, header, payload)) {
            return false;
        }
        
        if (static_cast<AuthMessageType>(header.messageType) != AuthMessageType::AUTH_REQUEST) {
            return false;
        }
        
        return parseAuthMessage(payload, username, password);
    }

}