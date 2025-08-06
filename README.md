# KimCloud File Transfer System

A custom implementation of an SSH-like file transfer protocol built from scratch in C++. This project consists of a client-server architecture that implements key components of the SSH protocol including key exchange, authentication, cryptogrophy, and secure file transfer.

## Simplified Version of SSH Protocol from Scratch
- **Version Exchange**: Implements SSH version exchange
- **KEXINIT**: Key exchange initialization with first match algorithm negotiation
- **DH Key Exchange**: Simplified Diffie-Hellman key exchange for secure key generation
- **Authentication**: Username/password authentication
- **Encryption**: Simple symmetric encryption for data protection
- **File Transfer Protocol**: Simple file transfer protocol using encryption
- **Network Traffic**: Low level socket handling and custom byte stream manipulations 
## How to Run with Docker Containers
1. **Build the Docker images:**
   ```bash
   # Build server image
   cd server
   docker build -t KimCloud-Server .
   ```
   ```bash
   # Build client image
   cd client
   docker build -t KimCloud-Client .
   ```

2. **Run the server:**
   ```bash
   # Run server container
   docker run -d \
     --name KimCloud-Server \
     -p 2222:2222 \
     -v $(pwd)/uploads:/app/uploads \
     KimCloud-Server
   ```

3. **Run the client:**
   ```bash
   # Run client container
   docker run -it \
     --name KimCloud-Client \
     --network host \
     -v $(pwd)/uploads:/app/uploads \
     KimCloud-Client
   ```

### Default credentials are: 
**username**: hosung \
**password**: kim

> NOTE: If running two containers on the same machine use `--network bridge` and the server IP will be `172.17.0.1` or `172.17.0.1`