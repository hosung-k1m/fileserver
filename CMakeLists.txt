cmake_minimum_required(VERSION 3.10)
project(ssh_client)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(ssh-client
    src/main.cpp
    src/ssh_socket.cpp
)
