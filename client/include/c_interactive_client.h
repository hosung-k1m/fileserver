#pragma once

#include <string>
#include <vector>
#include "c_file_transfer_client.h"

class InteractiveClient {
    private:
        std::string hostname_;
        int port_;
        std::string username_;
        std::string password_;
        FileTransferClient* client_;
        bool connected_;
        bool authenticated_;

    public:
        InteractiveClient();
        ~InteractiveClient();
        
        void run();
        
    private:
        bool getConnectionDetails();
        bool connectToServer();
        bool authenticate();
        void showMainMenu();
        void uploadSingleFile();
        void uploadMultipleFiles();
        void browseAndSelectFile();
        void reconnect();
};