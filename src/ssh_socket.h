#pragma once
#include <string>

class SSHSocket {
    public:
        SSHSocket(const std::string& hostname, int port);
        ~SSHSocket();

        bool connectToServer();
        void exchangeVersionStrings();
        void closeConnection();

    private:
        std::string hostname_;
        int port_;
        int socketfd_;
};