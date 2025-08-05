#include "s_file_transfer_server.h"
#include "s_kex.h"
#include "s_dh.h"
#include "s_packet.h"
#include "s_simple_crypto.h"
#include "s_file_transfer_protocol.h"
#include "s_authentication_protocol.h"

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
    sendCrypto_ = nullptr;
    recvCrypto_ = nullptr;

    // TODO: make this better :/
    // create users for login
    // user: hosung
    // pw: kim 
    users_["hosung"] = "kim";
    users_["admin"] = "password";
}

// on destruction
FileTransferServer::~FileTransferServer() {
    if (sendCrypto_) {
        delete sendCrypto_;
        sendCrypto_ = nullptr;
    }
    if (recvCrypto_) {
        delete recvCrypto_;
        recvCrypto_ = nullptr;
    }
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
        KexMatch MatchedKex;
        if (!handleKexinitExchange(clientSocket, MatchedKex)) {
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
        
        // fourth step --> authentication
        std::string username;
        if (!handleAuthentication(clientSocket, username)) {
            std::cerr << "Authentication failed" << std::endl;
            close(clientSocket);
            return;
        }
        
        std::cout << "User " << username << " authenticated successfully" << std::endl;
        
        // fifth step --> file transfer
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

bool FileTransferServer::handleKexinitExchange(int clientSocket, KexMatch& matchedKex) {
    
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
            std::vector<uint8_t> serverKexPayload = buildKexPayload();

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

    if (!(kexFirstMatch(matchedKex, serverKexInfo, clientKexInfo))) {
        std::cout << "KexFirstMatch failed" << std::endl;
        return false;
    }
    std::cout << "=============================" << std::endl;
    printMatchKex(matchedKex);

    return true;
}

bool FileTransferServer::handleKeyExchange(int clientSocket) {

    // step 3 DH Key Exchange
    std::cout << "3. Starting DH Key exchange" << std::endl;

    // recieve dh from client
    uint8_t buffer[4096];
    ssize_t bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesRead <= 0) {
        std::cerr << "Failed to receive client KEXDH_INIT" << std::endl;
        return false;
    }
    std::cout << "Received client KEXDH_INIT (" << bytesRead << " bytes)" << std::endl;
    
    std::vector<uint8_t> clientKexdhPacket(buffer, buffer + bytesRead);
    std::vector<uint8_t> clientKexdhPayload = unwrapPacket(clientKexdhPacket);
    
    // generate server DH
    std::vector<uint8_t> serverKexdhReply = generateServerKexdhReply(clientKexdhPayload);
    std::vector<uint8_t> serverKexdhPacket = wrapPacket(serverKexdhReply);
    
    // add KEXDH_REPLY
    std::vector<uint8_t> res;
    res.insert(res.end(), serverKexdhPacket.begin(), serverKexdhPacket.end());
    
    // add NEWKEYS to start encryption
    std::vector<uint8_t> newkeysMsg = {21}; // NEWKEYS CODE
    std::vector<uint8_t> newkeysPacket = wrapPacket(newkeysMsg);
    res.insert(res.end(), newkeysPacket.begin(), newkeysPacket.end());
    
    send(clientSocket, res.data(), res.size(), 0);
    std::cout << "Sent KEXDH_REPLY + NEWKEYS (" << res.size() << " bytes)" << std::endl;
    
    // Receive client NEWKEYS
    uint8_t newkeysBuf[1024];
    ssize_t newkeysLen = recv(clientSocket, newkeysBuf, sizeof(newkeysBuf), 0);
    if (newkeysLen <= 0) {
        std::cerr << "Failed to receive client NEWKEYS" << std::endl;
        return false;
    }
    std::cout << "Received client NEWKEYS (" << newkeysLen << " bytes)" << std::endl;
    
    std::cout << "Key exchange completed successfully" << std::endl;
    return true;
}

std::vector<uint8_t> FileTransferServer::generateServerKexdhReply(const std::vector<uint8_t>& clientKexdhPayload) {
    /**
     * messgae_id --> 30
     * client public (e) --> mpint value
     */

    // read client kex_dh must start with message_id = 30
    if (clientKexdhPayload.empty() || clientKexdhPayload[0] != 30) {
        std::cerr << "Invalid KEXDH_INIT message" << std::endl;
        return std::vector<uint8_t>();
    }
    
    // Extract client's public key
    size_t offset = 1;
    if (offset + 4 > clientKexdhPayload.size()) {
        std::cerr << "Invalid KEXDH_INIT packet size :(" << std::endl;
        return std::vector<uint8_t>();
    }
    
    uint32_t clientPublicLength = read32BigEndian(clientKexdhPayload, offset);
    
    if (offset + clientPublicLength > clientKexdhPayload.size()) {
        std::cerr << "Invalid client public key length" << std::endl;
        return std::vector<uint8_t>();
    }
    
    std::vector<uint8_t> clientPublicBytes(clientKexdhPayload.begin() + offset, clientKexdhPayload.begin() + offset + clientPublicLength);
    uint64_t clientPublicKey = DH::bytesToUint64(clientPublicBytes);
    
    std::cout << "Client public key length: " << clientPublicLength << std::endl;
    std::cout << "Client public key bytes: ";
    for (auto b : clientPublicBytes) {
        std::cout << std::hex << (int)b << " ";
    }
    std::cout << std::dec << std::endl;
    std::cout << "Client public key value: " << std::hex << clientPublicKey << std::dec << std::endl;
    
    // create the server DH
    DH serverDH;
    uint64_t serverPublicKey = serverDH.generatePublicKey();
    std::cout << "Server public key: " << std::hex << serverPublicKey << std::dec << std::endl;
    
    // compute the shared secret
    uint64_t sharedSecret = serverDH.computeSharedSecret(clientPublicKey);
    std::cout << "Server computed shared secret: " << std::hex << sharedSecret << std::dec << std::endl;
    
    // Create cypto objects for both directions
    sendCrypto_ = new SimpleCrypto(sharedSecret, false); // server_to_client for sending
    recvCrypto_ = new SimpleCrypto(sharedSecret, true);  // client_to_server for receiving
    
    /* KEXDH reply format
        ssh_msh_kexdh_reply --> 31
        server public host key
        server public host key
        signiture using server private key

    */
    std::vector<uint8_t> reply;

    reply.push_back(31); 
    
    // add a hard coded host key --> hosung-kim
    // TODO: make real soon?
    std::vector<uint8_t> hostKey = {0x00, 0x00, 0x00, 0x0A, 0x68, 0x6F, 0x73, 0x75, 0x6E, 0x67, 0x2D, 0x6B, 0x69, 0x6D};
    reply.insert(reply.end(), hostKey.begin(), hostKey.end());
    
    // add the public key
    auto serverPublicBytes = DH::uint64ToBytes(serverPublicKey);
    // convert to big endian and insert public key
    uint32_t serverPublicLength = htonl(serverPublicBytes.size());
    reply.insert(reply.end(), (uint8_t*)&serverPublicLength, (uint8_t*)&serverPublicLength + 4);
    // insert public key
    reply.insert(reply.end(), serverPublicBytes.begin(), serverPublicBytes.end());
    
    // add a fake signiture --> hosung-kim
    // TODO: make real soon?
    std::vector<uint8_t> signature = {0x00, 0x00, 0x00, 0x0A, 0x68, 0x6F, 0x73, 0x75, 0x6E, 0x67, 0x2D, 0x6B, 0x69, 0x6D};
    reply.insert(reply.end(), signature.begin(), signature.end());
    
    return reply;
}

bool FileTransferServer::handleAuthentication(int clientSocket, std::string& username) {
    std::string auth_username, auth_password;
    
    if (!AuthProtocol::receiveAuthRequest(clientSocket, auth_username, auth_password)) {
        std::cerr << "Failed to receive authentication request" << std::endl;
        return false;
    }
    
    // check credentials
    bool auth_success = AuthProtocol::validateCredentials(auth_username, auth_password, users_);
    
    if (!auth_success) {
        std::cout << "Authentication failed for user: " << auth_username << std::endl;
        AuthProtocol::sendAuthResponse(clientSocket, false);
        return false;
    }
    
    std::cout << "User " << auth_username << " authenticated successfully" << std::endl;
    
    // send sucess auth responce
    AuthProtocol::sendAuthResponse(clientSocket, true);
    
    username = auth_username; // set username pointer
    return true;
}

/**
 * Order of file transfer messages:
 *
 * FILE_START from client
 * FILE_START to client
 * 
 * FILE_DATA from client
 * FILE_DATA to client
 * 
 * FILE_END from client
 * FILE_DATA to client empy message
 */

void FileTransferServer::handleFileTransfer(int clientSocket, const std::string& username) {
    std::cout << "Starting file transfer session for user: " << username << std::endl;
    
    uint32_t sequenceNumber = 0;
    
    while (true) {
        FTPProtocol::FTPHeader header;
        std::vector<uint8_t> payload;
        
        if (!FTPProtocol::receiveEncryptedMessage(clientSocket, header, payload, *recvCrypto_)) {
            std::cerr << "Failed to receive message" << std::endl;
            break;
        }
        
        sequenceNumber++;
        
        // FILE_START or FILE_END
        switch (static_cast<FTPProtocol::FTPMessageType>(header.messageType)) {
            case FTPProtocol::FTPMessageType::FILE_START: {
                std::string filename;
                uint64_t fileSize;
                uint32_t chunkSize;
                
                // std::cout << "Parsing file start message, payload size: " << payload.size() << " bytes" << std::endl;
                if (FTPProtocol::parseFileStartMessage(payload, filename, fileSize, chunkSize)) {
                    std::cout << "Receiving file: " << filename << " (" << fileSize << " bytes)" << std::endl;
                    
                    // create file path in upload directory with username in front of file name
                    std::string filePath = uploadDir_ + "/" + username + "_" + filename;
                    
                    // open file with writing perms
                    int fileFd = open(filePath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if (fileFd < 0) {
                        std::cerr << "Failed to create file: " << filePath << std::endl;
                        FTPProtocol::sendEncryptedMessage(clientSocket, static_cast<uint8_t>(FTPProtocol::FTPMessageType::FILE_END), {}, sequenceNumber, *sendCrypto_);
                        continue;
                    }
                    
                    // send success response
                    FTPProtocol::sendEncryptedMessage(clientSocket, static_cast<uint8_t>(FTPProtocol::FTPMessageType::FILE_START), {}, sequenceNumber, *sendCrypto_);
                    std::cout << "Sent encrypted FILE_START response to client" << std::endl;
                    
                    size_t bytesReceived = 0;
                    uint32_t expected_chunk = 0;
                    std::map<uint32_t, std::vector<uint8_t>> chunkBuffer; // buffer for out of order chunks mapping of chunk number : chunk data
                    
                    while (bytesReceived < fileSize) {
                        FTPProtocol::FTPHeader dataHeader;
                        std::vector<uint8_t> dataPayload;
                        
                        if (!FTPProtocol::receiveEncryptedMessage(clientSocket, dataHeader, dataPayload, *recvCrypto_)) {
                            std::cerr << "Failed to receive file data" << std::endl;
                            close(fileFd);
                            return;
                        }
                        
                        if (static_cast<FTPProtocol::FTPMessageType>(dataHeader.messageType) == FTPProtocol::FTPMessageType::FILE_DATA) {
                            uint32_t chunkNumber;
                            if (FTPProtocol::parseFileDataMessage(dataPayload, chunkNumber, dataPayload)) {
                                
                                // send chunk received to client
                                FTPProtocol::sendEncryptedMessage(clientSocket, static_cast<uint8_t>(FTPProtocol::FTPMessageType::FILE_DATA), {}, dataHeader.sequenceNumber, *sendCrypto_);
                                
                                if (chunkNumber == expected_chunk) {
                                    // write the expected chunk that is in right order
                                    ssize_t bytesWritten = write(fileFd, dataPayload.data(), dataPayload.size());
                                    if (bytesWritten < 0) {
                                        std::cerr << "Failed to write to file" << std::endl;
                                        close(fileFd);
                                        return;
                                    }
                                    bytesReceived += bytesWritten;
                                    expected_chunk++;
                                    
                                    // check if there are chunks to write now from the buffer
                                    while (chunkBuffer.find(expected_chunk) != chunkBuffer.end()) {
                                        std::vector<uint8_t>& bufferedChunk = chunkBuffer[expected_chunk];
                                        ssize_t bytesWritten = write(fileFd, bufferedChunk.data(), bufferedChunk.size());
                                        if (bytesWritten < 0) {
                                            std::cerr << "Failed to write buffered chunk to file" << std::endl;
                                            close(fileFd);
                                            return;
                                        }
                                        bytesReceived += bytesWritten;
                                        chunkBuffer.erase(expected_chunk);
                                        expected_chunk++;
                                    }
                                    
                                    std::cout << "Progress: " << (bytesReceived * 100 / fileSize) << "% (" << bytesReceived << "/" << fileSize << " bytes)" << std::endl;
                                } else if (chunkNumber > expected_chunk) {
                                    // store the out of order chunks
                                    chunkBuffer[chunkNumber] = dataPayload;
                                    std::cout << "Out of order chunk in buffer!  " << chunkNumber << " (Expected: " << expected_chunk << ")" << std::endl;
                                } else {
                                    // duplicate chunks
                                    std::cout << "Ignoring old duplicate chunk:  " << chunkNumber << " (expected: " << expected_chunk << ")" << std::endl;
                                }
                            }
                        } else if (static_cast<FTPProtocol::FTPMessageType>(dataHeader.messageType) == FTPProtocol::FTPMessageType::FILE_END) {
                            break;
                        }
                    }
                    
                    close(fileFd);
                    std::cout << "File received successfully: " << filePath << std::endl;
                    
                    // file success message to client
                    FTPProtocol::sendEncryptedMessage(clientSocket, static_cast<uint8_t>(FTPProtocol::FTPMessageType::FILE_DATA), {}, sequenceNumber, *sendCrypto_);
                } else {
                    std::cerr << "Failed to parse file start message" << std::endl;
                }
                break;
            }
            case FTPProtocol::FTPMessageType::FILE_END:
                std::cout << "Client sent FILE_END message" << std::endl;
                // send to FILE_DATA to client
                FTPProtocol::sendEncryptedMessage(clientSocket, static_cast<uint8_t>(FTPProtocol::FTPMessageType::FILE_DATA), {}, sequenceNumber, *sendCrypto_);
                
                break;

            case FTPProtocol::FTPMessageType::DISCONNECT:
                std::cout << "Client requested disconnect" << std::endl;

                return;

            default:
                std::cerr << "Unknown message type: " << static_cast<int>(header.messageType) << std::endl;
                break;
        }
    }
} 