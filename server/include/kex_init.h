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

struct KexMatch {
    std::string keyExchange;
    std::string hostKey;
    std::string encryptionClientToServer;
    std::string encryptionServerToClient;
    std::string MACClientToServer;
    std::string MACServerToClient;
    std::string CompressionClientToServer;
    std::string CompressionServerToClient;
};

std::vector<uint8_t> buildKexInitPayload();

struct KexInformation parseKexPayload(std::vector<uint8_t> rawPayload);

uint32_t read32BigEndian(const std::vector<uint8_t>& data, size_t& offset);

std::vector<std::string> parseList(const std::vector<uint8_t>& data, size_t& offset);

void printKexInformation(const KexInformation& kexInfo);

bool kexFirstMatch(KexMatch& matchedKex, const KexInformation& serverKex, const KexInformation& clientKex);

bool match(std::string& matchString, const std::vector<std::string>& serverList, const std::vector<std::string>& clientList);

void printMatchKex(const KexMatch& kexMatch);