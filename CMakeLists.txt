cmake_minimum_required(VERSION 3.10)
project(ssh_client)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add source files
add_executable(ssh-client src/main.cpp)
