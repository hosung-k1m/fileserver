FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN mkdir -p build && cd build && \
    cmake .. && \
    cmake --build .

RUN mkdir -p /app/uploads

RUN echo '#!/bin/bash\n\
echo "Starting SSH-like File Transfer Server..."\n\
echo "Upload directory: /app/uploads"\n\
echo "Port: 2222"\n\
echo ""\n\
./build/ssh_server 2222 /app/uploads' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

EXPOSE 2222

VOLUME ["/app/uploads"]

ENTRYPOINT ["/app/entrypoint.sh"] 