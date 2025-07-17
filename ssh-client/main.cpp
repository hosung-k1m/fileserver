#include <iostream>
#include "ssh_socket.h"

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

    ssh.closeConnection();
    return 0;
}
