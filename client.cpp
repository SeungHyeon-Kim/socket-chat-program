#include "client.h"

// For using crypto system
void Client::init_crypto(const uint8_t *key, const uint8_t *iv, uint8_t *auth_data, const int len_auth) {
    crypto = new ARIA_GCM();
    if (crypto == nullptr) {
        std::runtime_error("ARIA_GCM allocation error\n");
    }

    crypto->init(key, iv);
    this->auth = auth_data;
    this->len_auth = len_auth;

    std::cout << "[INFO] Using ARIA_GCM..\n";
}

// Create a socket and try to connect with the server
void Client::connect(const char* ipv4, const in_port_t port_num) {
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        std::runtime_error("socket() error\n");
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ipv4);
    serv_addr.sin_port = htons(port_num);

    std::cout << "[INFO] Completed binding a socket..\n";

    if ((::connect(sock, (sockaddr*)&serv_addr, sizeof(serv_addr))) == -1) {
        std::runtime_error("connect() error\n");
    }

    std::cout << "[INFO] Connected to the server..\n\n";

    // Sending a message in thread
    std::thread send(&Client::send, this, sock);

    // Receive a message
    MSG m;
    uint8_t b[MAX_MSG_SIZE];

    while (true) {
        if (recv(sock, &m, sizeof(m), 0) > 0) {
            memset(b, 0, MAX_MSG_SIZE);
            // Decrypt a message and print-out if the tags are same
            if ((crypto->auth_dec(m.m, ntohl(m.len), auth, len_auth, m.t, TAG_SIZE, b))) {
                std::cout << b << '\n';
            }
            else {
                std::cout << "unkown message(this message can't be decrypted.)\n";
            }
        } else {
            break;
        }
    }

    send.join();
    quit();
}

// Function to sending message in thread
void Client::send(int sock) noexcept {
    MSG m;
    char b[MAX_MSG_SIZE];
    int len_m, len_b;

    // Setting user nickname
    std::cout << "// Enter your nickname to use in the chat!\n";
    std::cin.getline(b+1, 13); len_b = strlen(b+1) + 1;
    b[0] = '<'; b[len_b++] = '>'; b[len_b++] = ' ';
    std::cout << "// Now, you can type a message!\n\n";

    while (true) {
        std::cin.getline(b+len_b, MAX_MSG_SIZE-len_b);
        if (!strcmp(b+len_b, "q") || !strcmp(b+len_b, "Q")) {
            close(sock); return;
        }
        
        len_m = strlen(b); // std::cout << "\33[2K"; std::cout << "\x1b[A";
        memset(&m.m, 0, MAX_MSG_SIZE);

        crypto->auth_enc((uint8_t *)b, len_m, auth, len_auth, TAG_SIZE, m.m, m.t);    // Encrypt a message
        m.len = htonl(len_m);
        ::send(sock, &m, sizeof(m), 0);
    }
}

int main(void) {
    // Initial
    const char ipv4[] = "127.0.0.1";
    const in_port_t port = 9999;

    uint8_t IV[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t Key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t AuthData[12] = {0x9e, 0xa2, 0x77, 0xf5, 0x4c, 0xae, 0x27, 0xd6, 0xfc, 0x39, 0x0a, 0xd4};

    // Socket
    Client ChatServer;

    try {
        ChatServer.init_crypto(Key, IV, AuthData, 12);
        ChatServer.connect(ipv4, port);
    } catch (std::runtime_error &e) {
        std::cout << e.what();
        ChatServer.quit();
    }

    return 0;
}