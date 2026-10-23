#include "control_udp.h"
#include <arpa/inet.h>
#include <cerrno>
#include <unistd.h>

namespace SteamNetworkingSocketsLib {
/* Horizon has no AF_LOCAL socketpair. Both small control sockets are bound
 * and connected before publication; the SDK owns their eventual close. */
int NSL_GNS_WakePair(int out[2]) {
    int sockets[2] = {-1, -1};
    sockaddr_in addresses[2] = {};
    for (int i = 0; i < 2; ++i) {
        sockets[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sockets[i] < 0 || !sl_control_udp_buffers(sockets[i])) goto fail;
        addresses[i].sin_family = AF_INET;
        addresses[i].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(sockets[i], reinterpret_cast<sockaddr *>(&addresses[i]), sizeof(sockaddr_in)))
            goto fail;
        socklen_t size = sizeof(sockaddr_in);
        if (getsockname(sockets[i], reinterpret_cast<sockaddr *>(&addresses[i]), &size))
            goto fail;
    }
    for (int i = 0; i < 2; ++i)
        if (connect(sockets[i], reinterpret_cast<sockaddr *>(&addresses[1 - i]), sizeof(sockaddr_in)))
            goto fail;
    out[0] = sockets[0]; out[1] = sockets[1];
    return 0;
fail:
    int saved = errno;
    for (int fd : sockets) if (fd >= 0) close(fd);
    errno = saved;
    return -1;
}
}
