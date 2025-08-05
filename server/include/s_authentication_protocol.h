#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <map>

namespace AuthProtocol {
    // max lengths for strings
    constexpr uint32_t MAX_USERNAME_LENGTH = 256;
    constexpr uint32_t MAX_PASSWORD_LENGTH = 256;

    // auth message codes
    enum class AuthMessageType : uint8_t {
        AUTH_REQUEST = 10,
        AUTH_SUCCESS = 11,
        AUTH_FAILURE = 12
    };

    // auth message structure
    struct AuthMessage {
        uint32_t usernameLength;
        uint32_t passwordLength;
        
        AuthMessage(uint32_t user_len = 0, uint32_t pass_len = 0){
            usernameLength = user_len;
            passwordLength = pass_len;
        }
    };

    bool parseAuthMessage(const std::vector<uint8_t>& data, std::string& username, std::string& password);

    bool validateCredentials(const std::string& username, const std::string& password, 
                        const std::map<std::string, std::string>& users);

    bool sendAuthResponse(int socket_fd, bool success);
    bool receiveAuthRequest(int socket_fd, std::string& username, std::string& password);
}