cmake_minimum_required(VERSION 3.16)
project(ssh_file_transfer_client)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

include_directories(include)

set(SRC_FILES 
    src/c_ssh_socket.cpp
    src/c_byte_stream.cpp
    src/c_packet.cpp
    src/c_kex.cpp
    src/c_dh.cpp
    src/c_simple_crypto.cpp
    src/c_internet_traffic_protocol.cpp
    src/c_file_transfer_protocol.cpp
    src/c_authentication_protocol.cpp
    src/c_file_transfer_client.cpp
    src/c_interactive_client.cpp
)

add_executable(ssh_client c_main.cpp ${SRC_FILES})

target_link_libraries(ssh_client 
    OpenSSL::Crypto
    OpenSSL::SSL
)

target_compile_options(ssh_client PRIVATE -Wall -Wextra -O2) 