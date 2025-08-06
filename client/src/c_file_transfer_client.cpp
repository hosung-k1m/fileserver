#include "c_file_transfer_client.h"
#include "c_kex.h"
#include "c_dh.h"
#include "c_packet.h"
#include "c_simple_crypto.h"
#include "c_file_transfer_protocol.h"
#include "c_authentication_protocol.h"

#include <iostream>
#include <fstream>
#include <filesystem>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>

// construct
FileTransferClient::FileTransferClient(const std::string& hostname, int port) 
    : hostname_(hostname), port_(port), ssh_(hostname, port), sendCrypto_(nullptr), recvCrypto_(nullptr) {
}

// destroy
FileTransferClient::~FileTransferClient() {
    if (sendCrypto_) {
        delete sendCrypto_;
        sendCrypto_ = nullptr;
    }
    if (recvCrypto_) {
        delete recvCrypto_;
        recvCrypto_ = nullptr;
    }
}

bool FileTransferClient::connect() {
    if (!ssh_.connectToServer()) {
        std::cerr << "Failed to connect to server " << hostname_ << ":" << port_ << std::endl;
        return false;
    }
    
    if (!handleVersionExchange()) {
        std::cerr << "Version exchange failed" << std::endl;
        return false;
    }
    
    return true;
}

bool FileTransferClient::authenticate(const std::string& username, const std::string& password) {
    // first step KEXINIT exchange
    if (!handleKexinitExchange()) {
        std::cerr << "KEXINIT exchange failed" << std::endl;
        return false;
    }
    
    // second step key exchange
    if (!handleKeyExchange()) {
        std::cerr << "Key exchange failed" << std::endl;
        return false;
    }
    
    // third step user authentication
    if (!handleAuthentication(username, password)) {
        std::cerr << "Authentication failed" << std::endl;
        return false;
    }
    
    return true;
}

bool FileTransferClient::sendFile(const std::string& filePath) {
    // check file exist
    if (!std::filesystem::exists(filePath)) {
        std::cerr << "File does not exist: " << filePath << std::endl;
        return false;
    }
    
    // open files
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return false;
    }
    
    // get file size
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // get filename
    std::string filename = std::filesystem::path(filePath).filename().string();
    
    std::cout << "Sending file: " << filename << " (" << fileSize << " bytes)" << std::endl;
    
    uint32_t sequenceNumber = 0;
    
    // send FILE_START
    auto fileStartPayload = FTPProtocol::createFileStartMessage(filename, fileSize);
    if (!FTPProtocol::sendEncryptedMessage(ssh_.getSocketFd(), static_cast<uint8_t>(FTPProtocol::FTPMessageType::FILE_START), fileStartPayload, sequenceNumber, *sendCrypto_)) {
        std::cerr << "Failed to send file start message" << std::endl;
        return false;
    }
    sequenceNumber++;
    
    // wait for server FILE_START
    FTPProtocol::FTPHeader header;
    std::vector<uint8_t> payload;
    std::cout << "Waiting for server response..." << std::endl;
    if (!FTPProtocol::receiveEncryptedMessage(ssh_.getSocketFd(), header, payload, *recvCrypto_)) {
        std::cerr << "Failed to receive server response" << std::endl;
        return false;
    }
    
    if (static_cast<FTPProtocol::FTPMessageType>(header.messageType) != FTPProtocol::FTPMessageType::FILE_START) {
        std::cerr << "Server rejected file transfer" << std::endl;
        return false;
    }
    
    // send file data in chunks if too large
    std::vector<uint8_t> buffer(FTPProtocol::MAX_CHUNK_SIZE);
    uint32_t chunkNumber = 0;
    size_t totalSent = 0;
    
    // loop through all the bytes in the file
    while (totalSent < fileSize) {
        // read max number bytes into buffer
        file.read((char*)buffer.data(), buffer.size());
        size_t bytesRead = file.gcount();
        
        if (bytesRead == 0) {
            break;
        }
        
        // resize buffer to read bytes
        std::vector<uint8_t> chunkData(buffer.begin(), buffer.begin() + bytesRead);
        
        // create and send FileMEssage struct
        auto fileDataPayload = FTPProtocol::createFileDataMessage(chunkNumber, chunkData);
        if (!FTPProtocol::sendEncryptedMessage(ssh_.getSocketFd(), static_cast<uint8_t>(FTPProtocol::FTPMessageType::FILE_DATA), fileDataPayload, sequenceNumber, *sendCrypto_)) {
            std::cerr << "Failed to send file data chunk " << chunkNumber << std::endl;
            return false;
        }
        sequenceNumber++;
        
        // update progress
        totalSent += bytesRead;
        chunkNumber++;
        
        // logging
        if (fileSize > 0) {
            int progress = (totalSent * 100) / fileSize;
            std::cout << "\rProgress: " << progress << "% (" << totalSent << "/" << fileSize << " bytes)" << std::flush;
        }
    }
    
    std::cout << std::endl;
    
    // send FILE_END
    auto fileEndPayload = FTPProtocol::createFileEndMessage();
    if (!FTPProtocol::sendEncryptedMessage(ssh_.getSocketFd(), static_cast<uint8_t>(FTPProtocol::FTPMessageType::FILE_END), fileEndPayload, sequenceNumber, *sendCrypto_)) {
        std::cerr << "Failed to send file end message" << std::endl;
        return false;
    }
    sequenceNumber++;
    
    // wait for server responce
    if (!FTPProtocol::receiveEncryptedMessage(ssh_.getSocketFd(), header, payload, *recvCrypto_)) {
        std::cerr << "Failed to receive final server response" << std::endl;
        return false;
    }
    
    std::cout << "Received final server response: message type " << (int)header.messageType << std::endl;
    
    // syncronization is hard accept any mesage
    if (static_cast<FTPProtocol::FTPMessageType>(header.messageType) == FTPProtocol::FTPMessageType::FILE_DATA ||
        static_cast<FTPProtocol::FTPMessageType>(header.messageType) == FTPProtocol::FTPMessageType::FILE_START ||
        static_cast<FTPProtocol::FTPMessageType>(header.messageType) == FTPProtocol::FTPMessageType::FILE_END) {
        std::cout << "File sent successfully!" << std::endl;
        return true;
    } else {
        std::cerr << "Server reported error during file transfer" << std::endl;
        return false;
    }
}

bool FileTransferClient::handleVersionExchange() {
    std::string serverVersion;
    if (!ssh_.exchangeVersionStrings(serverVersion)) {
        std::cerr << "Version exchange failed" << std::endl;
        return false;
    }
    
    std::cout << "Connected to server: " << serverVersion;
    
    return true;
}

bool FileTransferClient::handleKexinitExchange() {
    std::cout << "\nPhase 1: Key Exchange Init" << std::endl;
    
    // send KEXINIT
    std::vector<uint8_t> kexPayload = buildKexPayload();
    std::vector<uint8_t> kexPacket = wrapPacket(kexPayload);
    send(ssh_.getSocketFd(), kexPacket.data(), kexPacket.size(), 0);
    std::cout << "Sent KEXINIT packet" << std::endl;

    // receive Server KEXINIT
    uint8_t kexBuf[2048] = {0};
    ssize_t kexLen = recv(ssh_.getSocketFd(), kexBuf, sizeof(kexBuf), 0);
    if (kexLen <= 0) {
        std::cerr << "Failed to receive KEXINIT from server" << std::endl;
        return false;
    }
    std::vector<uint8_t> serverKexReply(kexBuf, kexBuf + kexLen);
    std::cout << "Received server KEXINIT (" << kexLen << " bytes)" << std::endl;

    std::vector<uint8_t> serverKexInitPayload = unwrapPacket(serverKexReply);
    
    // parse KEX payloads and do first match
    KexInformation clientKexInfo = parseKexPayload(kexPayload);
    KexInformation serverKexInfo = parseKexPayload(serverKexInitPayload);
    
    std::cout << "Client Kex Info" << std::endl;
    printKexInformation(clientKexInfo);
    
    std::cout << "Server Kex Info" << std::endl;
    printKexInformation(serverKexInfo);
    
    KexMatch matchedKex;
    if (!kexFirstMatch(matchedKex, serverKexInfo, clientKexInfo)) {
        std::cout << "KexFirstMatch failed" << std::endl;
        return false;
    }
    std::cout << "===============================" << std::endl;
    printMatchKex(matchedKex);
    
    return true;
}

bool FileTransferClient::handleKeyExchange() {
    std::cout << "\nPhase 2: Key Exchange" << std::endl;
    
    // BUILD KEXDH_INIT
    DH client_dh;
    uint64_t client_publicKey = client_dh.generatePublicKey();
    
    std::vector<uint8_t> kexdhPayload;
    kexdhPayload.push_back(30); // message code 30
    
    // add public key from DH
    auto pub_key_bytes = DH::uint64ToBytes(client_publicKey);
    uint32_t length = htonl(pub_key_bytes.size());
    kexdhPayload.insert(kexdhPayload.end(), (uint8_t*)&length, (uint8_t*)&length + 4);
    kexdhPayload.insert(kexdhPayload.end(), pub_key_bytes.begin(), pub_key_bytes.end());

    std::vector<uint8_t> kexdhPacket = wrapPacket(kexdhPayload);
    send(ssh_.getSocketFd(), kexdhPacket.data(), kexdhPacket.size(), 0);

    std::cout << "Sent KEXDH_INIT" << std::endl;

    // server response
    uint8_t replyBuf[4096] = {0};
    ssize_t replyLen = recv(ssh_.getSocketFd(), replyBuf, sizeof(replyBuf), 0);
    if (replyLen <= 0) {
        std::cerr << "Failed to receive server response" << std::endl;
        return false;
    }
    
    std::vector<uint8_t> serverResponse(replyBuf, replyBuf + replyLen);
    
    // parse to extract KEXDH_REPLY and NEWKEYS
    std::vector<uint8_t> kexdhReply, serverNewkeysPkt;
    size_t offset = 0;
    
    while (offset < serverResponse.size()) {
        if (offset + 4 > serverResponse.size()) {
            std::cerr << "Incomplete packet at offset " << offset << std::endl;
            return false;
        }
        
        // read packet length from Big Endian
        uint32_t packetLength = (serverResponse[offset] << 24) | 
                               (serverResponse[offset + 1] << 16) | 
                               (serverResponse[offset + 2] << 8) | 
                               serverResponse[offset + 3];
        
        if (packetLength == 0 || offset + 4 + packetLength > serverResponse.size()) {
            std::cerr << "Invalid packet length: " << packetLength << " at offset " << offset << std::endl;
            return false;
        }
        
        // copy the packet using length
        std::vector<uint8_t> packet(serverResponse.begin() + offset, 
                                   serverResponse.begin() + offset + 4 + packetLength);
        
        // check for KEXDH_REPLY or NEWKEYS
        if (packet.size() > 5) {
            uint8_t messageType = packet[5];

            if (messageType == 31) { // KEXDH_REPLY
                std::cout << "Found KEXDH_REPLY packet (" << packet.size() << " bytes)" << std::endl;
                kexdhReply = packet;
            } else if (messageType == 21) { // NEWKEYS
                std::cout << "Found NEWKEYS packet (" << packet.size() << " bytes)" << std::endl;
                serverNewkeysPkt = packet;
            }
        }
        
        offset += 4 + packetLength;
    }
    
    if (kexdhReply.empty()) {
        std::cerr << "Could not find KEXDH_REPLY in server response" << std::endl;
        return false;
    }
    
    if (serverNewkeysPkt.empty()) {
        std::cerr << "Could not find NEWKEYS in server response" << std::endl;
        return false;
    }
    
    // read KEXDH_REPLY for server secret
    std::vector<uint8_t> kexdhReplyPayload = unwrapPacket(kexdhReply);
    if (kexdhReplyPayload.empty()) {
        std::cerr << "Failed to unwrap KEXDH_REPLY packet" << std::endl;
        return false;
    }

    // get shared secret
    uint64_t sharedSecret;
    if (!handleKexDhReply(kexdhReplyPayload, client_dh, sharedSecret)) {
        std::cerr << "Failed to handle DH reply" << std::endl;
        return false;
    }

    std::cout << "Key exchange successful" << std::endl;

    // get keys
    std::vector<uint8_t> sharedSecret_bytes = DH::uint64ToBytes(sharedSecret);
    
    sendCrypto_ = new SimpleCrypto(sharedSecret, true);  // client_to_server
    recvCrypto_ = new SimpleCrypto(sharedSecret, false); // server_to_client

    // NEWKEYS step
    std::cout << "\nPhase 3: NEWKEYS Exchange" << std::endl;
    
    auto serverNewkeysPayload = unwrapPacket(serverNewkeysPkt);
    if (serverNewkeysPayload.empty() || serverNewkeysPayload[0] != 21) {
        std::cerr << "Unexpected message type when expecting SSH_MSG_NEWKEYS: "
                  << (serverNewkeysPayload.empty() ? -1 : serverNewkeysPayload[0]) << std::endl;
        return false;
    }
    std::cout << "Received SSH_MSG_NEWKEYS from server" << std::endl;

    // Send our NEWKEYS and start ecryption
    std::vector<uint8_t> newkeysMsg = { 21 };
    auto pkt = wrapPacket(newkeysMsg);
    send(ssh_.getSocketFd(), pkt.data(), pkt.size(), 0);
    std::cout << "Sent SSH_MSG_NEWKEYS" << std::endl;

    return true;
}

bool FileTransferClient::handleAuthentication(const std::string& username, const std::string& password) {
    std::cout << "\nPhase 4: User Authentication" << std::endl;

    // send auth request
    if (!AuthProtocol::sendAuthRequest(ssh_.getSocketFd(), username, password)) {
        std::cerr << "Failed to send authentication request" << std::endl;
        return false;
    }

    // get responce
    bool auth_success;
    if (!AuthProtocol::receiveAuthResponse(ssh_.getSocketFd(), auth_success)) {
        std::cerr << "Failed to receive authentication response" << std::endl;
        return false;
    }

    if (!auth_success) {
        std::cerr << "Authentication failed" << std::endl;
        return false;
    }

    std::cout << "Authenticated successfully!" << std::endl;
    return true;
}

void FileTransferClient::disconnect() {
    FTPProtocol::sendEncryptedMessage(ssh_.getSocketFd(), static_cast<uint8_t>(FTPProtocol::FTPMessageType::DISCONNECT), {}, 0, *sendCrypto_);
    ssh_.closeConnection();
} 