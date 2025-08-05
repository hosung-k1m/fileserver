#pragma once
#include <vector>
#include <cstdint>

std::vector<uint8_t> wrapPacket(const std::vector<uint8_t>& payload);
std::vector<uint8_t> unwrapPacket(const std::vector<uint8_t>& packet);