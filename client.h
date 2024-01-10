#ifndef CLIENT_H
#define CLIENT_H

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <thread>
#include "aria_gcm.h"

#define MAX_MSG_SIZE ARIA_BLOCK_SIZE * 64
#define TAG_SIZE     ARIA_BLOCK_SIZE


struct MSG {
    uint8_t m[MAX_MSG_SIZE];
    uint8_t t[TAG_SIZE];
    int len;
};

class Client {
    // Socket
    int sock;
    sockaddr_in serv_addr;

    // Crypto
    uint8_t  *auth   = nullptr;
    ARIA_GCM *crypto = nullptr;
    int       len_auth;

    void send(int sock) noexcept;
    
    public:
    void init_crypto(const uint8_t *key, const uint8_t *iv, uint8_t *auth_data, const int len_auth);
    void connect(const char* ipv4, const in_port_t port_num);
    void quit() noexcept {
        if (sock != -1) {
            close(sock);
        }
        if (crypto != nullptr) {
            delete crypto;
        }
    };
};

#endif /* CLIENT_H */
