#include "server.h"

std::mutex m;

// Create a socket and bind
void Server::setup(const in_addr_t ipv4, const in_port_t port_num) {
    serv = socket(PF_INET, SOCK_STREAM, 0);
    if (serv == -1) {
        throw std::runtime_error("socket() error\n");
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = ipv4;
    serv_addr.sin_port = htons(port_num);
    
    if (bind(serv, (sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
        throw std::runtime_error("bind() error\n");
    }

    std::cout << "[INFO] Completed create a socket and bind address..\n";
}

void Server::run() {
    int clnt;
    std::vector<int> clients;
    sockaddr_in clnt_addr;
    socklen_t clnt_addr_size;

    if (listen(serv, 5) == -1) {
        throw std::runtime_error("listen() error\n");
    }

    std::cout << "[INFO] Running server..\n";

    for (int i = 0; i < 5; i++) {
        clnt_addr_size = sizeof(clnt_addr);
        clnt = accept(serv, (sockaddr*)&clnt_addr, &clnt_addr_size);
        if (clnt == -1) {
            throw std::runtime_error("accept() error\n");
        }

        m.lock(); clients.emplace_back(clnt); m.unlock();

        std::thread thd(&Server::handle, this, clnt, std::ref(clients));
        thd.detach();

        std::cout << "[INFO] Connected Client..(" << inet_ntoa(clnt_addr.sin_addr) << ") (# of Users: " << clients.size() << ")\n";
    }

    stop();
}

void Server::handle(int sock, std::vector<int> &clients) noexcept {
    MSG msg;
    int len;

    // Send a message to clients
    while ((len = recv(sock, &msg, sizeof(msg), 0)) != -1) { 
        if (len > 0) {
            m.lock(); for (const int & clnt : clients) { send(clnt, &msg, sizeof(msg), 0); } m.unlock();
        } else {
            break;
        }
    }

    m.lock();
    clients.erase(std::remove_if(clients.begin(), clients.end(), [&sock](int & clnt) { return sock == clnt; }));
    std::cout << "[INFO] Disconnected Client.. (# of Users: " << clients.size() << ")\n";
    m.unlock();
    
    close(sock);
}

int main(void) {
    Server ChatServer;

    try {
        ChatServer.setup(INADDR_ANY, 9999);     // IPv4 and Port
        ChatServer.run();                       // The server will start to listen.
    } catch (std::runtime_error & e) {
        std::cout << e.what();
        ChatServer.stop();
    }

    return 0;
}