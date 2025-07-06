# Use Ubuntu base image
FROM ubuntu:22.04

# Install essential packages
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Set working directory inside the container
WORKDIR /app

# Copy all project files into the container
COPY . .

# Create build directory and compile
RUN cmake -S . -B build && cmake --build build

# Run the compiled program
CMD ["./build/ssh-client"]
