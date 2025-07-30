#pragma once
#include <vector>
#include <cstdint>
#include <string>

struct KexInformation {
    std::vector<std::string> keyExchange;
    std::vector<std::string> hostKey;
    std::vector<std::string> encryptionClientToServer;
    std::vector<std::string> encryptionServerToClient;
    std::vector<std::string> MACClientToServer;
    std::vector<std::string> MACServerToClient;
    std::vector<std::string> CompressionClientToServer;
    std::vector<std::string> CompressionServerToClient;
    std::vector<std::string> LanguageTagClientToServer;
    std::vector<std::string> LanguageTagServerToClient;
};

std::vector<uint8_t> buildKexInitPayload();

struct KexInformation parseKexPayload(std::vector<uint8_t> rawPayload);

uint32_t read32BigEndian(const std::vector<uint8_t>& data, size_t& offset);

std::vector<std::string> parseList(const std::vector<uint8_t>& data, size_t& offset);

void printKexInformation(const KexInformation& kexInfo);