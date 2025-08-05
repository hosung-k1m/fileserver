#include "../include/s_kex.h"
#include "../include/s_byte_stream.h"
#include <cstdlib>
#include <iostream>
#include <algorithm>

// first message for SSH handshake and key exchange phase

// client --> server then server --> client


std::vector<uint8_t> buildKexPayload() {
    ByteStream bs;

    // SSH message code
    bs.writeByte(0x14);

    // Random cookie
    for (int i = 0; i < 16; i++) {
        bs.writeByte(rand() % 256);
    }

    // Key exchange algorithms
    bs.writeNameList({
        "diffie-hellman-simple",
    });

    // Host key algorithms
    bs.writeNameList({
        "kim-rsa",
        "RoseIsCoolDog"
    });

    // Encryption algorithms
    bs.writeNameList({
        "simple-encrypt",
        "hard-encrypt"
    });
    bs.writeNameList({
        "abcd123-ctr"
    });

    // MAC algorithms
    bs.writeNameList({
        "hmac-kim",
        "hmac-sha2-256"
    });
    bs.writeNameList({
        "bigMac-meal"
    });

    // Compression algorithms
    bs.writeNameList({"none"});
    bs.writeNameList({"none"});

    // Language tags
    bs.writeNameList({});
    bs.writeNameList({});

    // First KEX packet follows
    bs.writeByte(0);

    // Reserved must b 0
    bs.writeUint32(0);

    return bs.data();
}

KexInformation parseKexPayload(std::vector<uint8_t> rawPayload) {
    KexInformation kexInfo;

    size_t offset = 0;

    if (rawPayload[offset++] != 0x14) {
        std::cout << "Did not recieve a Kex payload, first byte is not 0x14 \n" << std::endl;
        return kexInfo;
    }
    
    // skip cookie
    offset += 16;

    kexInfo.keyExchange = parseList(rawPayload, offset);
    kexInfo.hostKey = parseList(rawPayload, offset);
    kexInfo.encryptionClientToServer = parseList(rawPayload, offset);
    kexInfo.encryptionServerToClient = parseList(rawPayload, offset);
    kexInfo.MACClientToServer = parseList(rawPayload, offset);
    kexInfo.MACServerToClient = parseList(rawPayload, offset);
    kexInfo.CompressionClientToServer = parseList(rawPayload, offset);
    kexInfo.CompressionServerToClient = parseList(rawPayload, offset);
    kexInfo.LanguageTagClientToServer = parseList(rawPayload, offset);
    kexInfo.LanguageTagServerToClient = parseList(rawPayload, offset);

    return kexInfo;
}

uint32_t read32BigEndian(const std::vector<uint8_t>& data, size_t& offset) {
    if (offset + 4 > data.size()) {
        std::cout << "Kex error not enough bytes to read uint32" << std::endl;
    }
    // manual Big Endian conversion
    uint32_t result = (data[offset] << 24) |
                      (data[offset + 1] << 16) |
                      (data[offset + 2] << 8) |
                      (data[offset + 3]);

    offset += 4;
    return result;
}

std::vector<std::string> parseList(const std::vector<uint8_t>& data, size_t& offset) {
    
    uint32_t lenRead = read32BigEndian(data, offset);

    if ( (offset + lenRead) > data.size()) {
        std::cout << "Not enough room to kex list size" << std::endl;
    }
    
    std::string convertedString(data.begin() + offset, data.begin() + offset + lenRead);
    offset += lenRead;

    std::vector<std::string> res;

    std::string curr;

    for (char c : convertedString) {
        if (c == ',') {
            res.push_back(curr);
            curr = "";
        }
        else {
            curr += c;
        }
    }

    if (!curr.empty()) {
        res.push_back(curr);
    }

    return res;
}

bool kexFirstMatch(KexMatch& matchedKex, const KexInformation& serverKex, const KexInformation& clientKex) {

    std::string res = "";
    if (match(res, serverKex.keyExchange, clientKex.keyExchange)) {
        matchedKex.keyExchange = res;
    }
    else {
        std::cout << "keyExchange match failed" << std::endl;
        return false;
    }

    res = "";
    if (match(res, serverKex.hostKey, clientKex.hostKey)) {
        matchedKex.hostKey = res;
    }
    else {
        std::cout << "hostKey match failed" << std::endl;
        return false;
    }

    res = "";
    if (match(res, serverKex.encryptionClientToServer, clientKex.encryptionClientToServer)) {
        matchedKex.encryptionClientToServer = res;
    }
    else {
        std::cout << "encryptionClientToServer match failed" << std::endl;
        return false;
    }

    res = "";
    if (match(res, serverKex.encryptionServerToClient, clientKex.encryptionServerToClient)) {
        matchedKex.encryptionServerToClient = res;
    }
    else {
        std::cout << "encryptionServerToClient match failed" << std::endl;
        return false;
    }

    res = "";
    if (match(res, serverKex.MACClientToServer, clientKex.MACClientToServer)) {
        matchedKex.MACClientToServer = res;
    }
    else {
        std::cout << "MACClientToServer match failed" << std::endl;
        return false;
    }

    res = "";
    if (match(res, serverKex.MACServerToClient, clientKex.MACServerToClient)) {
        matchedKex.MACServerToClient = res;
    }
    else {
        std::cout << "MACServerToClient match failed" << std::endl;
        return false;
    }

    res = "";
    if (match(res, serverKex.CompressionClientToServer, clientKex.CompressionClientToServer)) {
        matchedKex.CompressionClientToServer = res;
    }
    else {
        std::cout << "CompressionClientToServer match failed" << std::endl;
        return false;
    }

    res = "";
    if (match(res, serverKex.CompressionServerToClient, clientKex.CompressionServerToClient)) {
        matchedKex.CompressionServerToClient = res;
    }
    else {
        std::cout << "CompressionServerToClient match failed" << std::endl;
        return false;
    }


    return true;
}

bool match(std::string& matchString, const std::vector<std::string>& serverList, const std::vector<std::string>& clientList) {
    for (const auto& clientString : clientList) {
        if (std::find(serverList.begin(), serverList.end(), clientString) != serverList.end()) {
            matchString = clientString;
            return true;
        }
    }

    return false;
}

void printKexInformation(const KexInformation& kexInfo) {
    std::cout << "=== KEX Information ===" << std::endl;
    
    std::cout << "Key Exchange Algorithms:" << std::endl;
    for (const auto& algo : kexInfo.keyExchange) {
        std::cout << "  - " << algo << std::endl;
    }
    
    std::cout << "Host Key Algorithms:" << std::endl;
    for (const auto& algo : kexInfo.hostKey) {
        std::cout << "  - " << algo << std::endl;
    }
    
    std::cout << "Encryption Algorithms (Client->Server):" << std::endl;
    for (const auto& algo : kexInfo.encryptionClientToServer) {
        std::cout << "  - " << algo << std::endl;
    }
    
    std::cout << "Encryption Algorithms (Server->Client):" << std::endl;
    for (const auto& algo : kexInfo.encryptionServerToClient) {
        std::cout << "  - " << algo << std::endl;
    }
    
    std::cout << "MAC Algorithms (Client->Server):" << std::endl;
    for (const auto& algo : kexInfo.MACClientToServer) {
        std::cout << "  - " << algo << std::endl;
    }
    
    std::cout << "MAC Algorithms (Server->Client):" << std::endl;
    for (const auto& algo : kexInfo.MACServerToClient) {
        std::cout << "  - " << algo << std::endl;
    }
    
    std::cout << "Compression Algorithms (Client->Server):" << std::endl;
    for (const auto& algo : kexInfo.CompressionClientToServer) {
        std::cout << "  - " << algo << std::endl;
    }
    
    std::cout << "Compression Algorithms (Server->Client):" << std::endl;
    for (const auto& algo : kexInfo.CompressionServerToClient) {
        std::cout << "  - " << algo << std::endl;
    }
    
    std::cout << "Language Tags (Client->Server):" << std::endl;
    for (const auto& tag : kexInfo.LanguageTagClientToServer) {
        std::cout << "  - " << tag << std::endl;
    }
    
    std::cout << "Language Tags (Server->Client):" << std::endl;
    for (const auto& tag : kexInfo.LanguageTagServerToClient) {
        std::cout << "  - " << tag << std::endl;
    }
    
    std::cout << "=====================" << std::endl;
}

void printMatchKex(const KexMatch& res) {
    std::cout << "MATCHED KEX VALUES" << std::endl;
    std::cout << " keyExchange: "<< res.keyExchange << std::endl;
    std::cout << " hostKey: "<< res.hostKey << std::endl;
    std::cout << " encryptionClientToServer: "<< res.encryptionClientToServer << std::endl;
    std::cout << " encryptionServerToClient: "<< res.encryptionServerToClient << std::endl;
    std::cout << " MACClientToServer: "<< res.MACClientToServer << std::endl;
    std::cout << " MACServerToClient: "<< res.MACServerToClient << std::endl;
    std::cout << " CompressionClientToServer: "<< res.CompressionClientToServer << std::endl;
    std::cout << " CompressionServerToClient: "<< res.CompressionServerToClient << std::endl;
}