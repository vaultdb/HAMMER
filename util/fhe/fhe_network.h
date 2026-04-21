#ifndef _FHE_NETWORK_H
#define _FHE_NETWORK_H

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace vaultdb {

/**
 * Simple socket-based network communication for FHE 2-party protocol
 * Party A (client) generates keys and encrypts predicates
 * Party B (server) receives public keys and encrypted predicates, executes queries
 */
class FheNetworkIO {
public:
    FheNetworkIO(const std::string& host, int port, bool is_server);
    ~FheNetworkIO();

    void sendData(const void* data, size_t size);
    void recvData(void* data, size_t size);

    void sendString(const std::string& str);
    std::string recvString();

    template<typename T>
    void sendVector(const std::vector<T>& vec) {
        size_t size = vec.size();
        sendData(&size, sizeof(size_t));
        if (size > 0) {
            sendData(vec.data(), size * sizeof(T));
        }
    }

    template<typename T>
    std::vector<T> recvVector() {
        size_t size;
        recvData(&size, sizeof(size_t));
        std::vector<T> vec(size);
        if (size > 0) {
            recvData(vec.data(), size * sizeof(T));
        }
        return vec;
    }

    void flush();

private:
    int socket_fd_;
    bool is_server_;
};

} // namespace vaultdb

#endif // _FHE_NETWORK_H
