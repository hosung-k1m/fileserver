#pragma once
#include <string>

class SSHSocket {
    public:
        SSHSocket(const std::string& hostname, int port);
        ~SSHSocket();
    
        bool connectToServer();
        bool exchangeVersionStrings(std::string& serverVersion);
        void closeConnection();
        int getSocketFd() const { return socketfd_; }
    
    private:
        std::string hostname_;
        int port_;
        int socketfd_;
    };