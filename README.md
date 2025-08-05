# Docker Commands to Run Locally (both in same machine)
## Client
```bash
docker build -t kim-client .
```

```bash
docker run -it --rm --network bridge -v $(pwd)/uploads:/app/uploads kim-client
```
Server Address: `172.17.0.2` last value changes\
Port : `2222`\
Username: `hosung` \
Password: `kim`

## Server
```bash 
docker build -t kim-server .
```


```bash
docker run -it --rm --name kim-server -p 2222:2222 -v $(pwd)/uploads:/app/uploads kim-server
```