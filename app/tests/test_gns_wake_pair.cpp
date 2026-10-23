#include <arpa/inet.h>
#include <cassert>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
namespace SteamNetworkingSocketsLib { int NSL_GNS_WakePair(int out[2]); }
static unsigned sockets_called, fail_socket, options_called, fail_option;
extern "C" int __real_socket(int, int, int);
extern "C" int __wrap_socket(int family, int type, int protocol) {
    if (++sockets_called == fail_socket) { errno = ENOBUFS; return -1; }
    return __real_socket(family, type, protocol);
}
extern "C" int __real_setsockopt(int, int, int, const void *, socklen_t);
extern "C" int __wrap_setsockopt(int fd, int level, int option, const void *value, socklen_t size) {
    if (++options_called == fail_option) { errno = ENOBUFS; return -1; }
    return __real_setsockopt(fd, level, option, value, size);
}
static unsigned fds() {
    unsigned count = 0;
    for (int fd = 0; fd < 1024; ++fd) count += fcntl(fd, F_GETFD) != -1;
    return count;
}
int main() {
    unsigned baseline = fds();
    for (unsigned launch = 0; launch < 2; ++launch) {
        int pair[2];
        assert(SteamNetworkingSocketsLib::NSL_GNS_WakePair(pair) == 0);
        for (int fd : pair) {
            int rx = 0, tx = 0; socklen_t size = sizeof(rx);
            assert(!getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rx, &size));
            size = sizeof(tx); assert(!getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &tx, &size));
            // Linux doubles requests; allow that, not its large default buffers.
            assert(rx >= 8192 && rx <= 16384 && tx >= 8192 && tx <= 16384);
        }
        for (unsigned i = 0; i < 2; ++i) {
            char tx = 'w', rx = 0;
            assert(send(pair[i], &tx, 1, 0) == 1);
            assert(recv(pair[1-i], &rx, 1, 0) == 1 && rx == tx);
        }
        for (int fd : pair) close(fd);
        assert(fds() == baseline);
    }
    for (unsigned failure = 1; failure <= 6; ++failure) {
        sockets_called = options_called = 0;
        fail_socket = failure <= 2 ? failure : 0;
        fail_option = failure > 2 ? failure - 2 : 0;
        int pair[2] = {-7, -7};
        assert(SteamNetworkingSocketsLib::NSL_GNS_WakePair(pair) == -1 && errno == ENOBUFS);
        assert(pair[0] == -7 && pair[1] == -7 && fds() == baseline);
    }
}
