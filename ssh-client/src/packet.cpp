#include "packet.h"
#include <cstdlib>

/*
FORMAT NEEDED:
packet length
padding length
payload
padding
*/

std::vector<uint8_t> wrapPacket(const std::vector<uint8_t>& payload) {
    size_t blockSize = 8;
    size_t payloadLen = payload.size();
    size_t minPad = 4;

    size_t totalNoPad = 1 + payloadLen;
    size_t paddingLen = blockSize - (totalNoPad % blockSize);

    if (paddingLen < minPad) {
        paddingLen += blockSize;
    }

    size_t packetLength = totalNoPad + paddingLen;
    std::vector<uint8_t> packet;
    packet.reserve(4 + packetLength);

    //packet length
    packet.push_back((packetLength >> 24) & 0xFF);
    packet.push_back((packetLength >> 16) & 0xFF);
    packet.push_back((packetLength >> 8) & 0xFF);
    packet.push_back((packetLength & 0xFF));

    // padding length
    packet.push_back(static_cast<uint8_t>(paddingLen));

    //payload
    packet.insert(packet.end(), payload.begin(), payload.end());

    // random pading (needed)
    for (size_t i=0; i< paddingLen; i++) {
        packet.push_back(rand() % 256);
    }

    return packet;

}