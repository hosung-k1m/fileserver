#pragma once
#include <vector>
#include <cstdint>

// build the SSH_SG_KEXDH and returns the packet
std::vector<uint8_t> buildKexDHInitPacket(std::vector<uint8_t>& e_bytes, void** dh_ctx);

// parse KEXDH_REPLY and extract shared secret and compute H

bool handleKexDHReply(
    const std::vector<uint8_t>& packet,
    const std::vector<uint8_t>& e_bytes,
    void* dh_ctx,
    std::vector<uint8_t>& sharedSecret,
    std::vector<uint8_t> exchangeHash,
    std::vector<uint8_t>& sessionID
);