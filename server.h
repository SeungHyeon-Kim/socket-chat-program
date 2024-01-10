#ifndef SERVER_H
#define SERVER_H

#include <iostream>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <thread>
#include <mutex>

#define BLOCK_SIZE 16
#define MAX_MSG_SIZE BLOCK_SIZE * 64


struct MSG {
    uint8_t m[MAX_MSG_SIZE];
    uint8_t t[16];
    int len;
};

class Server {
    private:
    int serv = -1;
    sockaddr_in serv_addr;

    void handle(int sock, std::vector<int> & clients) noexcept;
    
    public:
    void setup(const in_addr_t ipv4, const in_port_t port_num);
    void run();
    void stop() noexcept {
        if (serv != -1) {
            close(serv);
        }
    };
};

#endif /* SERVER_H */
