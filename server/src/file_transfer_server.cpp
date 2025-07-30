#include "file_transfer_server.h"
#include "kex_init.h"
#include "simple_dh.h"
#include "packet.h"
#include "simple_crypto.h"
#include "file_transfer_protocol.h"

#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <map>
#include <atomic>
#include <thread>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

FileTransferServer::FileTransferServer(int port, const std::string& uploadDir) {
    port_ = port;
    uploadDir_ = uploadDir;
    running_ = false;

    // TODO: make this better :/
    // create users for login
    // user: hosung
    // pw: kim 
    users_["hosung"] = "kim";
}

// on destruction
FileTransferServer::~FileTransferServer() {
    stop();
}

bool FileTransferServer::start() {
    // use IPv4 and TCP
    serverSocket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket_ < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return false;
    }
    
    // let rebinding to the port
    int opt = 1; // enable
    setsockopt(serverSocket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // struct sockaddr_in {
	// __uint8_t       sin_len;
	// sa_family_t     sin_family;
	// in_port_t       sin_port; 
	// struct  in_addr sin_addr;
	// char            sin_zero[8];
    // }
    struct sockaddr_in serverAddr;
    // memset bc its C
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET; // since IPv4
    serverAddr.sin_addr.s_addr = INADDR_ANY; // accept connections from any IP, ingress
    serverAddr.sin_port = htons(port_); // server port in Big Endian
    
    
    if (bind(serverSocket_, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Failed to bind socket" << std::endl;
        close(serverSocket_);
        return false;
    }
    
    if (listen(serverSocket_, 2) < 0) {
        std::cerr << "Failed to listen on socket" << std::endl;
        close(serverSocket_);
        return false;
    }
    
    running_ = true;
    std::cout << "KimCloud server started on port " << port_ << std::endl;
    std::cout << "Upload directory set to: " << uploadDir_ << std::endl;

    return true;
}

void FileTransferServer::run() {
    while (running_) {
        struct sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        
        // Wait for client to connect
        std::cout << "Waiting to accept new connection..." << std::endl;
        int clientSocket = accept(serverSocket_, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket < 0) {
            if (running_) {
                std::cerr << "Failed to accept connection" << std::endl;
            }
            continue;
        }
        
        // get ip of connection
        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
        std::cout << " !!! New connection from " << clientIP << ":" << ntohs(clientAddr.sin_port) << " !!!" << std::endl;
        
        // Handle each client in a separate thread
        std::thread clientThread(&FileTransferServer::handleClient, this, clientSocket);
        clientThread.detach();
    }
}

void FileTransferServer::stop() {
    running_ = false;
    // close listening socket
    if (serverSocket_ >= 0) {
        close(serverSocket_);
    }
}

void FileTransferServer::handleClient(int clientSocket) {
    try {
        
        // first step --> version exchange
        if (!handleVersionExchange(clientSocket)) {
            std::cerr << "Version exchange failed :(" << std::endl;
            close(clientSocket);
            return;
        }
        
        // second step --> KEXINIT exchange
        if (!handleKexinitExchange(clientSocket)) {
            std::cerr << "Key exchange failed :(" << std::endl;
            close(clientSocket);
            return;
        }

        // third step --> DH key exchange
        if (!handleKeyExchange(clientSocket)) {
            std::cerr << "Key exchange failed :(" << std::endl;
            close(clientSocket);
            return;
        }
        
        
        std::string username;
        if (!handleAuthentication(clientSocket, username)) {
            std::cerr << "Authentication failed" << std::endl;
            close(clientSocket);
            return;
        }
        
        std::cout << "User " << username << " authenticated successfully" << std::endl;
        
        handleFileTransfer(clientSocket, username);
        
    } catch (const std::exception& e) {
        std::cerr << "Exception in client handler: " << e.what() << std::endl;
    }
    
    std::cout << "Client connection closed" << std::endl;
    close(clientSocket);
}

bool FileTransferServer::handleVersionExchange(int clientSocket) {
    // Send server version
    std::string serverVersion = "KimCloud_Protocol_v1\r\n";
    std::cout << "1. Starting Version String Exchange" << std::endl;
    send(clientSocket, serverVersion.c_str(), serverVersion.length(), 0);
    
    // Receive client version
    char buffer[1024];
    ssize_t bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (bytesRead <= 0) {
        return false;
    }
    buffer[bytesRead] = '\0';
    std::string clientVersion(buffer);

    if (clientVersion != serverVersion) {
        std::cout << "Server version of: " << serverVersion << "\nDoes not match client version of: " << clientVersion << std::endl;
        return false;
    }

    std::cout << "Client version: " << clientVersion << std::endl;
    std::cout << "Server version matches: " << serverVersion << std::endl;
    std::cout << "End of Version String Exchange" << std::endl;
    
    return true;
}

bool FileTransferServer::handleKexinitExchange(int clientSocket) {
    
    std::cout << "2. Starting KEXINIT Payload exchange" << std::endl;
    
    // read socket to buffer
    uint8_t kexBuf[2048] = {0};
    ssize_t kexLen = recv(clientSocket, kexBuf, sizeof(kexBuf), 0);
    if (kexLen <= 0) {
        std::cerr << "Failed to receive client KEXINIT" << std::endl;
        return false;
    }
    std::vector<uint8_t> clientKexPacket(kexBuf, kexBuf + kexLen);
    std::cout << "Received client KEXINIT (" << kexLen << " bytes)" << std::endl;
    
    // Send server KEXINIT
    std::vector<uint8_t> serverKexPayload = buildKexInitPayload();

    // load the KexInformation struct
    KexInformation serverKexInfo = parseKexPayload(serverKexPayload);
    // load the client KexInformation struct
    std::vector<uint8_t> clientKexUnwrapped = unwrapPacket(clientKexPacket);
    KexInformation clientKexInfo = parseKexPayload(clientKexUnwrapped);

    std::vector<uint8_t> serverKexPacket = wrapPacket(serverKexPayload);
    send(clientSocket, serverKexPacket.data(), serverKexPacket.size(), 0);
    std::cout << "Sent server KEXINIT (304 bytes)" << std::endl;
    
    std::cout << "Server Kex Info" << std::endl;
    printKexInformation(serverKexInfo);

    std::cout << "Client Kex Info" << std::endl;
    printKexInformation(clientKexInfo);


    // TODO: negotiation on what to use
    // unwrap the client responce and then parse

    return true;
}
