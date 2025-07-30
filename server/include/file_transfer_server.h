#include <string>
#include <vector>
#include <map>
#include <atomic>
#include <thread>

class FileTransferServer {
private:
    int serverSocket_;
    int port_;
    std::string uploadDir_;
    std::atomic<bool> running_;
    
    // for user authentication
    // TODO: CHANGE THIS TO SOMETHING BETTER
    // Current is map<username, password>
    std::map<std::string, std::string> users_;


public:
    // defauly values --> port = 2222, uploadDir = ./uploads
    FileTransferServer(int port = 2222, const std::string& uploadDir = "./uploads");

    ~FileTransferServer();
    
    bool start();
    void run();
    void stop();

private:
    void handleClient(int clientSocket);
    bool handleVersionExchange(int clientSocket);
    bool handleKexinitExchange(int clientSocker);
    bool handleKeyExchange(int clientSocket);
    std::vector<uint8_t> generateKexdhReply(const std::vector<uint8_t>& clientKexdhPayload);
    bool handleAuthentication(int clientSocket, std::string& username);
    void handleFileTransfer(int clientSocket, const std::string& username);
};