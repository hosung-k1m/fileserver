#include "kex_init.h"
#include "byte_stream.h"
#include <cstdlib>

// first message for SSH handshake and key exchange phase

// client --> server then server --> client

std::vector<uint8_t> buildKexInitPayload() {
    ByteStream bs;

    // ssh message code
    bs.writeByte(0x14);

    // random cookie
    for (int i=0; i < 16; i++) {
        bs.writeByte(rand() % 256);
    }

    // Kex allgorithms
    bs.writeNameList({"diffie-hellman-group14-sha1"});

    // host key algo
    bs.writeNameList({"ssh-rsa"});

    // encryption algo 
    bs.writeNameList({"aes128-ctr"});
    bs.writeNameList({"aes128-ctr"});

    // MAC Algo
    bs.writeNameList({"hmac-sha1"});
    bs.writeNameList({"hmac-sha1"});

    // compression algo
    bs.writeNameList({"none"});
    bs.writeNameList({"none"});

    // language client
    bs.writeNameList({});
    bs.writeNameList({});

    // bool first_kex_packet_follows, for round tip negotiation
    bs.writeByte(0);

    // must be 0
    bs.writeUint32(0);

    return bs.data();
}