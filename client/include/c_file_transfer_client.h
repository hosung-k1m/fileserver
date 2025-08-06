#pragma once

#include <string>
#include <vector>
#include "c_ssh_socket.h"

class SimpleCrypto;

class FileTransferClient {
    private:
        std::string hostname_;
        int port_;
        SSHSocket ssh_;
        SimpleCrypto* sendCrypto_;
        SimpleCrypto* recvCrypto_; 

    public:
        FileTransferClient(const std::string& hostname, int port = 2222);
        ~FileTransferClient();
        
        bool connect();
        bool authenticate(const std::string& username, const std::string& password);
        bool sendFile(const std::string& filePath);
        void disconnect();

    private:
        bool handleVersionExchange();
        bool handleKexinitExchange();
        bool handleKeyExchange();
        bool handleAuthentication(const std::string& username, const std::string& password);
};