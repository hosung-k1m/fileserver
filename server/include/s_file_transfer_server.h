#pragma once

#include <string>
#include <vector>
#include <map>
#include <atomic>
#include <thread>
#include "s_kex.h"

// Forward declaration
class SimpleCrypto;

class FileTransferServer {
private:
    int serverSocket_;
    int port_;
    std::string uploadDir_;
    std::atomic<bool> running_;
    
    // for user authentication
    // TODO: CHANGE THIS TO SOMETHING BETTER
    // Current is map<username, password>
    std::map<std::string, std::string> users_;

    SimpleCrypto* sendCrypto_;
    SimpleCrypto* recvCrypto_;

public:
    // defauly values --> port = 2222, uploadDir = ./uploads
    FileTransferServer(int port = 2222, const std::string& uploadDir = "./uploads");

    ~FileTransferServer();
    
    bool start();
    void run();
    void stop();

private:
    void handleClient(int clientSocket);
    bool handleVersionExchange(int clientSocket);
    bool handleKexinitExchange(int clientSocket, KexMatch& matchedKex);
    bool handleKeyExchange(int clientSocket);
    std::vector<uint8_t> generateServerKexdhReply(const std::vector<uint8_t>& clientKexdhPayload);
    bool handleAuthentication(int clientSocket, std::string& username);
    void handleFileTransfer(int clientSocket, const std::string& username);
};