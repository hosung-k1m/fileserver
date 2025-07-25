#include "dh_kex.h"
#include "byte_stream.h"
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <cstring>
#include <iostream>

// convert hex to OpenSSL BIGNUM
static BIGNUM* hexToBN(const char* hex) {
    BIGNUM* bn = nullptr;
    BN_hex2bn(&bn, hex);
    return bn;
}

std::vector<uint8_t> buildKexDHInitPacket(std::vector<uint8_t>& e_bytes, void** dh_ctx_out) {
    // large prime number
    const char* primeHex = 
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A36210000000000090563";

    // create openSSL object
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p = hexToBN(primeHex);

    BIGNUM* g = BN_new();
    BN_set_word(g, 2);

    BIGNUM* x = BN_new();
    BN_rand(x, 2048, -1, 0); // private key
    BIGNUM* e = BN_new();
    
    // e = g^x % p
    BN_mod_exp(e, g, x, p, ctx);

    int len = BN_num_bytes(e);
    e_bytes.resize(len);
    BN_bn2bin(e, e_bytes.data());

    struct DHContext {
        BN_CTX* ctx;
        BIGNUM* p;
        BIGNUM* x;
    };

    *dh_ctx_out = new DHContext{ctx, p, x};

    ByteStream bs;
    bs.writeByte(30);
    bs.writeMPint(e_bytes);

    return bs.data();
}


bool handleKexDHReply(
    const std::vector<uint8_t>& packet,
    const std::vector<uint8_t>& e_bytes,
    void* dh_ctx_void,
    std::vector<uint8_t>& sharedSecret,
    std::vector<uint8_t>& exchangeHash,
    std::vector<uint8_t>& sessionID
) {
    const uint8_t* data = packet.data();
    size_t offset = 0;

    if (data[offset++] != 31) {
        std::cerr << "Expected SSH_MSG_KEXDH_REPLY\n";
        return false;
    }

    auto readString = [&](std::vector<uint8_t>& out) {
        uint32_t len = (data[offset] << 24) | (data[offset+1] << 16) | (data[offset+2] << 8) | (data[offset + 3]);
        offset += 4;
        out.assign(data + offset, data + offset + len);
        offset += len;
    };

    std::vector<uint8_t> K_S, f_bytes, sig;
    readString(K_S); 
    readString(f_bytes);
    readString(sig);

    // get the shared secret k= f^x % p
    DHContext* dh = (DHContext*)dh_ctx_void;
    BIGNUM* f = BN_bin2bn(f_bytes.data(), f_bytes.size(), NULL);
    BIGNUM* K = BN_new();
    BN_mod_exp(K, f, dh->x, dh->p, dh->ctx);

    int K_len = BN_num_bytes(K);
    sharedSecret.resize(K_len);
    BN_bn2bin(K, sharedSecret.data());;

    // get the exxchange hash
    ByteStream H;
    std::string V_C = "SSH-2.0-CustomClient_0.1\r\n";
    std::string V_S = "SSH-2.0-OpenSSH_9.2\r\n"; // optionally parse this dynamically
    H.writeString(V_C);
    H.writeString(V_S);
    H.writeString(std::string{}); // I_C placeholder
    H.writeString(std::string{}); // I_S placeholder
    H.writeString(K_S);
    H.writeMpint(e_bytes);
    H.writeMpint(f_bytes);
    H.writeMpint(sharedSecret);

    // SHA1 hash of H
    exchangeHash.resize(SHA_DIGEST_LENGTH);
    SHA1(H.data().data(), H.data().size(), exchangeHash.data());

    sessionID = exchangeHash; // first H becomes session ID

    // Cleanup
    BN_free(f);
    BN_free(K);
    delete dh;
    return true;
}