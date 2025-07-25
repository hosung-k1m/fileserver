# Use a minimal base image
FROM ubuntu:22.04

# Install build dependencies
RUN apt-get update && \
    apt-get install -y \
        build-essential \
        cmake \
        openssl \
        libssl-dev \
        netcat \
        iputils-ping

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Create build directory and build the project
RUN mkdir -p build && cd build && cmake .. && make

# Run the SSH client by default
CMD ["./build/ssh_client"]
