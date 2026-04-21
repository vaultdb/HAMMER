#include "util/fhe/fhe_network.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include "util/google_test_flags.h"

namespace vaultdb {

FheNetworkIO::FheNetworkIO(const std::string& host, int port, bool is_server)
    : socket_fd_(-1), is_server_(is_server) {

    if (is_server_) {
        socket_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd_ < 0) {
            throw std::runtime_error("Failed to create server socket");
        }

        int opt = 1;
        if (setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            close(socket_fd_);
            throw std::runtime_error("Failed to set socket options");
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(socket_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            int err = errno;
            close(socket_fd_);
            std::string msg = "Failed to bind socket to port " + std::to_string(port);
            if (err == EADDRINUSE) {
                msg += ". Port in use (stale process?). Run: pkill -f fhe_tpch_test; sleep 2. Or use --fhe_mpc_port="
                       + std::to_string(port + 1) + " on all three parties.";
            }
            throw std::runtime_error(msg);
        }

        if (listen(socket_fd_, 1) < 0) {
            close(socket_fd_);
            throw std::runtime_error("Failed to listen on socket");
        }

        if (FLAGS_debug) std::cout << "[FheNetworkIO] Party B (Server): Listening on port " << port << std::endl;

        struct sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(socket_fd_, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            close(socket_fd_);
            throw std::runtime_error("Failed to accept connection");
        }
        close(socket_fd_);
        socket_fd_ = client_fd;

        if (FLAGS_debug) std::cout << "[FheNetworkIO] Party B (Server): Accepted connection from "
                  << inet_ntoa(client_addr.sin_addr) << std::endl;
    } else {
        socket_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd_ < 0) {
            throw std::runtime_error("Failed to create client socket");
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
            close(socket_fd_);
            throw std::runtime_error("Invalid address: " + host);
        }

        if (connect(socket_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(socket_fd_);
            throw std::runtime_error("Failed to connect to " + host + ":" + std::to_string(port));
        }

        if (FLAGS_debug) std::cout << "[FheNetworkIO] Party A (Client): Connected to " << host << ":" << port << std::endl;
    }
}

FheNetworkIO::~FheNetworkIO() {
    if (socket_fd_ >= 0) {
        close(socket_fd_);
    }
}

void FheNetworkIO::sendData(const void* data, size_t size) {
    if (socket_fd_ < 0) {
        throw std::runtime_error("Socket not initialized");
    }

    const char* ptr = static_cast<const char*>(data);
    size_t total_sent = 0;
    while (total_sent < size) {
#ifdef MSG_NOSIGNAL
        ssize_t sent = send(socket_fd_, ptr + total_sent, size - total_sent, MSG_NOSIGNAL);
#else
        ssize_t sent = send(socket_fd_, ptr + total_sent, size - total_sent, 0);
#endif
        if (sent < 0) {
            throw std::runtime_error("Failed to send data");
        }
        total_sent += sent;
    }
}

void FheNetworkIO::recvData(void* data, size_t size) {
    if (socket_fd_ < 0) {
        throw std::runtime_error("Socket not initialized");
    }

    char* ptr = static_cast<char*>(data);
    size_t total_recv = 0;
    while (total_recv < size) {
        ssize_t recv_len = recv(socket_fd_, ptr + total_recv, size - total_recv, 0);
        if (recv_len < 0) {
            throw std::runtime_error("Failed to receive data");
        }
        if (recv_len == 0) {
            throw std::runtime_error("Connection closed by peer");
        }
        total_recv += recv_len;
    }
}

void FheNetworkIO::sendString(const std::string& str) {
    size_t len = str.length();
    sendData(&len, sizeof(size_t));
    if (len > 0) {
        sendData(str.data(), len);
    }
}

std::string FheNetworkIO::recvString() {
    size_t len;
    recvData(&len, sizeof(size_t));
    std::string str(len, '\0');
    if (len > 0) {
        recvData(&str[0], len);
    }
    return str;
}

void FheNetworkIO::flush() {}

} // namespace vaultdb
