#include "../include/c_interactive_client.h"
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
#include <limits>
#include <algorithm>

// constructor
InteractiveClient::InteractiveClient(){
    client_ = nullptr;
    connected_ = false;
    authenticated_ = false;
}

// destructor
InteractiveClient::~InteractiveClient() {
    if (client_) {
        client_->disconnect();
        delete client_;
    }
}

void InteractiveClient::run() {
    std::cout << "========= KimCloud Client =========" << std::endl;
    std::cout << "====================================" << std::endl;
    
    while (true) {
        if (!connected_) {
            if (!getConnectionDetails()) {
                continue;
            }
            if (!connectToServer()) {
                continue;
            }
        }
        
        if (!authenticated_) {
            if (!authenticate()) {
                continue;
            }
        }
        
        showMainMenu();
    }
}

bool InteractiveClient::getConnectionDetails() {
    std::cout << "\n--- Connection Setup! ---" << std::endl;
    
    // get server ip
    std::cout << "Enter server address: ";
    std::getline(std::cin, hostname_);
    if (hostname_.empty()) {
        std::cout << "Hostname cannot be empty!" << std::endl;
        return false;
    }
    
    // get port
    std::cout << "Enter port (default 2222): ";
    std::string portStr;
    std::getline(std::cin, portStr);
    if (portStr.empty()) {
        port_ = 2222;
    } else {
        try {
            port_ = std::stoi(portStr);
            if (port_ <= 0 || port_ > 65535) {
                std::cout << "Invalid port number!" << std::endl;
                return false;
            }
        } catch (const std::exception& e) {
            std::cout << "Invalid port number!" << std::endl;
            return false;
        }
    }
    
    // username
    std::cout << "Enter username: ";
    std::getline(std::cin, username_);
    if (username_.empty()) {
        std::cout << "Username cannot be empty!" << std::endl;
        return false;
    }
    
    // get password
    std::cout << "Enter password: ";
    std::getline(std::cin, password_);
    if (password_.empty()) {
        std::cout << "Password cannot be empty!" << std::endl;
        return false;
    }
    
    return true;
}

bool InteractiveClient::connectToServer() {
    std::cout << "\nConnecting to " << hostname_ << ":" << port_ << "..." << std::endl;
    
    if (client_) {
        delete client_;
    }
    
    client_ = new FileTransferClient(hostname_, port_);
    
    if (!client_->connect()) {
        std::cout << "Failed to connect to server!" << std::endl;
        return false;
    }
    
    connected_ = true;
    std::cout << "Connected successfully!" << std::endl;
    return true;
}

bool InteractiveClient::authenticate() {
    std::cout << "\nAuthenticating..." << std::endl;
    
    if (!client_->authenticate(username_, password_)) {
        std::cout << "Authentication failed!" << std::endl;
        return false;
    }
    
    authenticated_ = true;
    std::cout << "Authentication successful!" << std::endl;
    return true;
}

void InteractiveClient::showMainMenu() {
    while (true) {
        std::cout << "\n--- Main Menu ---" << std::endl;
        std::cout << "1. Upload a file" << std::endl;
        std::cout << "2. Upload multiple files" << std::endl;
        std::cout << "3. Browse and select file" << std::endl;
        std::cout << "4. Reconnect to server" << std::endl;
        std::cout << "5. Exit" << std::endl;
        std::cout << "Enter your choice (1-5): ";
        
        std::string choice;
        std::getline(std::cin, choice);
        
        if (choice == "1") {
            uploadSingleFile();
        } else if (choice == "2") {
            uploadMultipleFiles();
        } else if (choice == "3") {
            browseAndSelectFile();
        } else if (choice == "4") {
            reconnect();
            break;
        } else if (choice == "5") {
            std::cout << "Goodbye!" << std::endl;
            exit(0);
        } else {
            std::cout << "Invalid choice! Please enter 1-5." << std::endl;
        }
    }
}

void InteractiveClient::uploadSingleFile() {
    std::cout << "\n--- Upload Single File ---" << std::endl;
    std::cout << "Enter file path: ";
    
    std::string filePath;
    std::getline(std::cin, filePath);
    
    if (filePath.empty()) {
        std::cout << "File path cannot be empty!" << std::endl;
        return;
    }
    
    // ~ is starting from home directory
    if (filePath[0] == '~') {
        const char* home = getenv("HOME");
        if (home) {
            filePath = std::string(home) + filePath.substr(1);
        }
    }
    
    if (!std::filesystem::exists(filePath)) {
        std::cout << "File does not exist: " << filePath << std::endl;
        return;
    }
    
    if (!std::filesystem::is_regular_file(filePath)) {
        std::cout << "Path is not a regular file: " << filePath << std::endl;
        return;
    }
    
    std::cout << "Uploading file: " << filePath << std::endl;
    
    if (client_->sendFile(filePath)) {
        std::cout << "File uploaded successfully!" << std::endl;
    } else {
        std::cout << "File upload failed!" << std::endl;
    }
}

void InteractiveClient::uploadMultipleFiles() {
    std::cout << "\n--- Upload Multiple Files ---" << std::endl;
    std::cout << "Enter file paths (one per line, empty line to finish):" << std::endl;
    
    std::vector<std::string> filePaths;
    std::string filePath;
    
    while (true) {
        std::cout << "File path (or empty to finish): ";
        std::getline(std::cin, filePath);
        
        // empty to finished
        if (filePath.empty()) {
            break;
        }
        
        // ~ is starting from home directory
        if (filePath[0] == '~') {
            const char* home = getenv("HOME");
            if (home) {
                filePath = std::string(home) + filePath.substr(1);
            }
        }
        
        if (!std::filesystem::exists(filePath)) {
            std::cout << "File does not exist: " << filePath << std::endl;
            continue;
        }
        
        if (!std::filesystem::is_regular_file(filePath)) {
            std::cout << "Path is not a regular file: " << filePath << std::endl;
            continue;
        }
        
        filePaths.push_back(filePath);
    }
    
    if (filePaths.empty()) {
        std::cout << "No files selected for upload." << std::endl;
        return;
    }
    
    std::cout << "\nUploading " << filePaths.size() << " files..." << std::endl;
    
    int successCount = 0;
    for (const auto& path : filePaths) {
        std::cout << "\nUploading: " << path << std::endl;
        if (client_->sendFile(path)) {
            std::cout << "Success!" << std::endl;
            successCount++;
        } else {
            std::cout << "Failed!" << std::endl;
        }
    }
    
    std::cout << "\nUpload complete: " << successCount << "/" << filePaths.size() << " files uploaded successfully." << std::endl;
}

void InteractiveClient::browseAndSelectFile() {
    std::cout << "\n--- Browse and Select File ---" << std::endl;
    std::cout << "Enter directory path to browse (or empty for current directory): ";
    
    std::string dirPath;
    std::getline(std::cin, dirPath);
    
    if (dirPath.empty()) {
        dirPath = ".";
    }
    
    if (dirPath[0] == '~') {
        const char* home = getenv("HOME");
        if (home) {
            dirPath = std::string(home) + dirPath.substr(1);
        }
    }
    
    if (!std::filesystem::exists(dirPath)) {
        std::cout << "Directory does not exist: " << dirPath << std::endl;
        return;
    }
    
    if (!std::filesystem::is_directory(dirPath)) {
        std::cout << "Path is not a directory: " << dirPath << std::endl;
        return;
    }
    
    std::vector<std::filesystem::path> files;
    try {
        for (const auto& entry : std::filesystem::directory_iterator(dirPath)) {
            if (entry.is_regular_file()) {
                files.push_back(entry.path());
            }
        }
    } catch (const std::exception& e) {
        std::cout << "Error reading directory: " << e.what() << std::endl;
        return;
    }
    
    if (files.empty()) {
        std::cout << "No files found in directory." << std::endl;
        return;
    }
    
    // sort files alphabetically
    std::sort(files.begin(), files.end());
    
    // output files to view
    std::cout << "\nFiles in " << dirPath << ":" << std::endl;
    for (size_t i = 0; i < files.size(); ++i) {
        std::cout << (i + 1) << ". " << files[i].filename().string() << std::endl;
    }
    
    std::cout << "\nEnter file number to upload (or 0 to cancel): ";
    std::string choiceStr;
    std::getline(std::cin, choiceStr);
    
    try {
        int choice = std::stoi(choiceStr);
        if (choice == 0) {
            return;
        }
        
        if (choice < 1 || choice > static_cast<int>(files.size())) {
            std::cout << "Invalid file number!" << std::endl;
            return;
        }
        
        std::string selectedFile = files[choice - 1].string();
        std::cout << "Uploading: " << selectedFile << std::endl;
        
        if (client_->sendFile(selectedFile)) {
            std::cout << "File uploaded successfully!" << std::endl;
        } else {
            std::cout << "File upload failed!" << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cout << "Invalid input!" << std::endl;
    }
}

void InteractiveClient::reconnect() {
    std::cout << "\nDisconnecting from current server..." << std::endl;
    if (client_) {
        client_->disconnect();
        delete client_;
        client_ = nullptr;
    }
    //reset
    connected_ = false;
    authenticated_ = false;
} 