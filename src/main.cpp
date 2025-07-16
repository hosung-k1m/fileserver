#include <iostream>
#include "ssh_socket.h"

int main() {
    SSHSocket ssh("github.com", 22); // port 22 is ssh

    if (ssh.connectToServer()) {
        ssh.exchangeVersionStrings();
        ssh.closeConnection();
    }
    else {
        std::cerr << "Error connecting \n";
    }
    
    return 0;
}
