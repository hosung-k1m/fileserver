#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <map>
#include <atomic>
#include <thread>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "include/s_file_transfer_server.h"

int main(int argc, char* argv[]) {
    // error chekcing for incorrect paramaters
    if (argc != 3) {
        std::cerr << "Correct usage --> arg1 = port , arg2 = upload directory\n";
        return 1;
    }
    
    int port = std::stoi(argv[1]);
    std::string uploadDir = argv[2];
    
    // create KimCloud object
    FileTransferServer server(port, uploadDir);
    
    // will listen on socket
    if (!server.start()) {
        std::cerr << "Failed to start KimCloud :(" << std::endl;
        return 1;
    }
    
    server.run();
    
    return 0;
} 