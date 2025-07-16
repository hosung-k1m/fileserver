#include "ssh_socket.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

// make the constructor for the class
SSHSocket::SSHSocket(const std::string& hostname, int  port) {
    hostname_ = hostname;
    port_ = port;
    socketfd_ = -1;
}

// deconstructor, for socket destuction
SSHSocket::~SSHSocket() {
    closeConnection();
}

// function to do the TCP connection
bool SSHSocket::connectToServer() {
    struct addrinfo input{};
    struct addrinfo *res;

    input.ai_family = AF_UNSPEC; //ipv4 or 6
    input.ai_socktype = SOCK_STREAM; // TCP

    int status;
    if (status = getaddrinfo(hostname_.c_str(), std::to_string(port_).c_str(), &input, &res) != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(status) << std::endl; // if not found show errors
        return false;
    }

    // res has possible socket configs
    socketfd_ = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (socketfd_== -1) {
        perror("socket");
        return false;
    }

    // connect the socket fd
    if(::connect(socketfd_, res->ai_addr, res->ai_addrlen) == -1) {
        perror("connect");
        return false;
    }

    std::cout << "connected to " << hostname_ << "on port number " << port_ <<std::endl;

    freeaddrinfo(res);

    return true;
}

// first step of SSH protocol
void SSHSocket::exchangeVersionStrings() {
    // send version string on socket
    const std::string clientVersion = "SSH-2.0-CustomClient_0.1\r\n";
    send(socketfd_, clientVersion.c_str(), clientVersion.size(), 0);
    
    // allocate buffer for incoming message
    char buffer[256];
    memset(buffer, 0, sizeof(buffer));
    ssize_t bytesReceived = recv(socketfd_, buffer, sizeof(buffer) -1, 0);

    if (bytesReceived > 0) {
        std::cout << "Server Version: " << buffer;
    }
    else {
        std::cerr << "Failed to recieve version string from server \n";
    }
}

void SSHSocket::closeConnection() {
    // check if socket is open and close accordingly
    if (socketfd_ != -1) {
        close(socketfd_);
        socketfd_ = -1;
    }
}