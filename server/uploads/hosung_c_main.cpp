#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>

#include "include/c_interactive_client.h"


int main(int argc, char* argv[]) {
    // start the client
    InteractiveClient client;
    client.run();
    return 0;
} 