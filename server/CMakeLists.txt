cmake_minimum_required(VERSION 3.16)
project(ssh_file_transfer_server)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

include_directories(include)

set(SRC_FILES 
    src/s_byte_stream.cpp
    src/s_packet.cpp
    src/s_kex.cpp
    src/s_dh.cpp
    src/s_simple_crypto.cpp
    src/s_internet_traffic_protocol.cpp
    src/s_file_transfer_protocol.cpp
    src/s_authentication_protocol.cpp
    src/s_file_transfer_server.cpp
)

add_executable(ssh_server s_main.cpp ${SRC_FILES})

target_link_libraries(ssh_server 
    OpenSSL::Crypto
    OpenSSL::SSL
    Threads::Threads
)

target_compile_options(ssh_server PRIVATE -Wall -Wextra -O2) 