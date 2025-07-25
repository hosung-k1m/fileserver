#include <iostream>
#include "ssh_socket.h"
#include "kex_init.h"
#include "packet.h"
#include <sys/socket.h>  // for send()
#include "dh_kex.h"


int main() {
    SSHSocket ssh("github.com", 22); // port 22 is ssh

    if (!ssh.connectToServer()) {
        std::cerr << "Failed to connect to SSH server.\n";
        return 1;
    }

    std::string serverVersion;
    if (!ssh.exchangeVersionStrings(serverVersion)) {
        std::cerr << "Version exchange failed.\n";
        return 1;
    }

    std::cout << "Server Version: " << serverVersion << std::endl;

    // Send KEXINIT
    std::vector<uint8_t> kexPayload = buildKexInitPayload();
    std::vector<uint8_t> kexPacket = wrapPacket(kexPayload);
    send(ssh.getSocketFd(), kexPacket.data(), kexPacket.size(), 0);
    std::cout << "Sent KEXINIT packet\n";

    // Recieve Server Kexinit
    uint8_t kexBuf[2048] = {0};
    ssize_t kexLen = recv(ssh.getSocketFd(), kexBuf, sizeof(kexBuf), 0);
    if (kexLen <= 0) {
        std::cerr << "Failed to receive KEXINIT from server\n";
        return 1;
    }
    std::vector<uint8_t> serverKexReply(kexBuf, kexBuf + kexLen);
    std::cout << "Received server KEXINIT (" << kexLen << " bytes)\n";

    // build and send KEXDH_INIT
    std::vector<uint8_t> e_bytes;
    void* dh_ctx = nullptr;
    std::vector<uint8_t> kexdhPayload = buildKexDHInitPacket(e_bytes, &dh_ctx);
    std::vector<uint8_t> kexdhPacket = wrapPacket(kexdhPayload);
    send(ssh.getSocketFd(), kexdhPacket.data(), kexdhPacket.size(), 0);
    std::cout << "Sent KEXDH_INIT\n";

    // Recieve KEXDH_REPLY
    uint8_t replyBuf[2048] = {0};
    ssize_t replyLen = recv(ssh.getSocketFd(), replyBuf, sizeof(replyBuf), 0);
    if (replyLen <= 0) {
        std::cerr << "Failed to receive KEXDH_REPLY\n";
        return 1;
    }
    std::vector<uint8_t> kexdhReply(replyBuf, replyBuf + replyLen);
    std::cout << "Received KEXDH_REPLY (" << replyLen << " bytes)\n";

    // Handle KEXDH_REPLY and compute values
    std::vector<uint8_t> sharedSecret, exchangeHash, sessionID;
    if (!handleKexDHReply(kexdhReply, e_bytes, dh_ctx, sharedSecret, exchangeHash, sessionID)) {
        std::cerr << "❌ Failed to handle KEXDH_REPLY\n";
        return 1;
    }

    std::cout << "Computed shared secret and session ID\n";
    std::cout << "Session ID (SHA1): ";
    for (uint8_t b : sessionID) std::cout << std::hex << (int)b;
    std::cout << std::dec << std::endl;

    ssh.closeConnection();
    return 0;
}
