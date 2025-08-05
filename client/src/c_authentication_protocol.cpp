#include "../include/c_authentication_protocol.h"
#include "../include/c_internet_traffic_protocol.h"
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>

namespace AuthProtocol {

    std::vector<uint8_t> createAuthMessage(const std::string& username, const std::string& password) {
        AuthMessage msg(username.length(), password.length());
        
        // convert to Big Endina network order
        uint32_t usernameLength = htonl(msg.usernameLength);
        uint32_t passwordLength = htonl(msg.passwordLength);
        
        std::vector<uint8_t> data(sizeof(AuthMessage) + username.length() + password.length());
        
        // copy headers
        memcpy(data.data(), &usernameLength, sizeof(uint32_t));
        memcpy(data.data() + 4, &passwordLength, sizeof(uint32_t));
        
        // copy username
        memcpy(data.data() + sizeof(AuthMessage), username.data(), username.length());
        
        // copy password
        memcpy(data.data() + sizeof(AuthMessage) + username.length(), password.data(), password.length());
        
        return data;
    }

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

    bool sendAuthRequest(int socket_fd, const std::string& username, const std::string& password) {
        std::vector<uint8_t> authPayload = createAuthMessage(username, password);
        return ITPProtocol::sendMessage(socket_fd, static_cast<uint8_t>(AuthMessageType::AUTH_REQUEST), authPayload, 0);
    }

    bool receiveAuthResponse(int socket_fd, bool& success) {
        ITPProtocol::ITPHeader header;
        std::vector<uint8_t> payload;
        
        if (!ITPProtocol::receiveMessage(socket_fd, header, payload)) {
            return false;
        }
        
        // check if authentication was sucessful
        AuthMessageType messageType = static_cast<AuthMessageType>(header.messageType);
        if (messageType == AuthMessageType::AUTH_SUCCESS) {
            success = true;
            return true;
        } else if (messageType == AuthMessageType::AUTH_FAILURE) {
            success = false;
            return true;
        }
        
        return false;
    }

}