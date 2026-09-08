#include "platform/system.h"
#include "build_identity.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <switch.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static bool sockets, fonts;
static int log_fd = -1;
bool sl_system_init(void) {
    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    SocketInitConfig cfg = *socketGetDefaultInitConfig();
    /* Preserve the proven client configuration. Enlarging UDP defaults made
     * socket() fail with ENOBUFS on the Switch (2026-09-08 device log). */
    cfg.udp_rx_buf_size = 1024U * 1024U;
    sockets = R_SUCCEEDED(socketInitialize(&cfg));
    if (!sockets)
        sockets = R_SUCCEEDED(socketInitializeDefault());
    if (!sockets)
        return false;
    fonts = R_SUCCEEDED(plInitialize(PlServiceType_User));
    if (!fonts) {
        socketExit();
        sockets = false;
        return false;
    }
    mkdir("sdmc:/switch/nsteamlink", 0777);
    if (NSL_DIAGNOSTICS && __nxlink_host.s_addr) {
        log_fd = nxlinkConnectToHost(false, false);
        if (log_fd >= 0)
            fcntl(log_fd, F_SETFL, O_NONBLOCK);
    }
    return true;
}
bool sl_system_running(void) {
    return appletMainLoop();
}
void sl_system_shutdown(void) {
    if (log_fd >= 0) {
        close(log_fd);
        log_fd = -1;
    }
    if (fonts) {
        plExit();
        fonts = false;
    }
    if (sockets) {
        socketExit();
        sockets = false;
    }
}
bool sl_system_random(void *data, size_t size) {
    randomGet(data, size);
    return true;
}
const char *sl_system_data_dir(void) {
    return "sdmc:/switch/nsteamlink";
}
const void *sl_system_font(int index, size_t *size, const char **path) {
    *path = NULL;
    *size = 0;
    if (index > 2)
        return NULL;
    PlFontData font;
    if (R_FAILED(plGetSharedFontByType(&font, index == 0 ? PlSharedFontType_Standard
                                              : index == 1
                                                  ? PlSharedFontType_ChineseSimplified
                                                  : PlSharedFontType_ExtChineseSimplified)))
        return NULL;
    *size = font.size;
    return font.address;
}
uint64_t sl_system_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void sl_system_log(const char *message) {
#if NSL_DIAGNOSTICS
    if (log_fd < 0)
        return;
    char line[240];
    size_t n = strnlen(message, sizeof(line) - 2);
    memcpy(line, message, n);
    line[n++] = '\n';
    send(log_fd, line, n, MSG_DONTWAIT);
#else
    (void)message;
#endif
}

uint32_t sl_system_dns_begin(void) {
    return resolverGetCancelHandle();
}
void sl_system_dns_cancel(uint32_t handle) {
    if (handle)
        resolverCancel(handle);
}
