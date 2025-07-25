cmake_minimum_required(VERSION 3.10)
project(ssh_client)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include headers
include_directories(include)

# Collect all .cpp files in src/
file(GLOB SRC_FILES
    "src/*.cpp"
)

# Main entry point
add_executable(ssh_client main.cpp ${SRC_FILES})

# Link OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(ssh_client OpenSSL::Crypto)
