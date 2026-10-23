#pragma once
#include <sys/socket.h>
#include <stdbool.h>
/* D-A103: libnx's BSD transfer-memory pool is shared. The streaming client
 * configures a 1MiB default UDP receive buffer, so even debug and SDK wake
 * sockets initially request media-sized storage. Real Switch SDR creation
 * failed with ENOBUFS (105) after host success/certificate installation.
 * Keep auxiliary sockets small BEFORE creating the next socket; a later
 * setsockopt on a socket that cannot be created cannot repair exhaustion.
 * Do not change IHS media or the SDK's 256KiB relay buffers here. */
static inline bool sl_control_udp_buffers(int fd) {
    int bytes = 8192;
    return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes)) == 0 &&
           setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes)) == 0;
}
