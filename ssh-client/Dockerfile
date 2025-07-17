FROM ubuntu:22.04

# get packages and dependancies
RUN apt-get update && \
    apt-get install -y build-essential cmake openssl libssl-dev netcat iputils-ping

WORKDIR /app

COPY . .

RUN mkdir build && cd build && cmake .. && make

CMD ["./build/ssh_client"]
