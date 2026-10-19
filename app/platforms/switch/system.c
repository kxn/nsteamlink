#include "platform/system.h"
#include "build_identity.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <libavutil/cpu.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <switch.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static bool sockets, fonts;
static atomic_bool docked;
static int log_fd = -1;
bool sl_system_init(void) {
    atomic_store(&docked, appletGetOperationMode() == AppletOperationMode_Console);
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
#if NSL_DIAGNOSTICS
    if (__nxlink_host.s_addr) {
        log_fd = nxlinkConnectToHost(false, false);
        if (log_fd >= 0)
            fcntl(log_fd, F_SETFL, O_NONBLOCK);
    }
#endif
    return true;
}
bool sl_system_running(void) {
    bool running = appletMainLoop();
    atomic_store(&docked, appletGetOperationMode() == AppletOperationMode_Console);
    return running;
}
bool sl_system_docked(void) {
    return atomic_load(&docked);
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

const char *sl_system_locale(void) {
    u64 code = 0;
    if (R_FAILED(setInitialize()))
        return "en";
    Result result = setGetSystemLanguage(&code);
    SetLanguage language = SetLanguage_ENUS;
    if (R_SUCCEEDED(result))
        result = setMakeLanguage(code, &language);
    setExit();
    if (R_SUCCEEDED(result) && (language == SetLanguage_ZHCN || language == SetLanguage_ZHTW ||
                                language == SetLanguage_ZHHANS || language == SetLanguage_ZHHANT))
        return "zh-CN";
    return "en";
}

uint8_t sl_system_video_cpu_count(void) {
    /* The installed Switch SDK detector reads InfoType_CoreMask, with its own
     * fallback. SDL 2.28.5's detector only returns 1 on this target (§100).
     * This is the platform input; selection gates remain the original policy. */
    return (uint8_t)av_cpu_count();
}

sl_system_stream_info sl_system_streaming_info(void) {
    /* Describe this backend, not another client's hardware. Unknown decode /
     * burst bitrate maxima remain zero so negotiation omits those fields;
     * the former 30/90 Mbps values were neither enforced nor measured (§111).
     * Steam has no confirmed Switch OSType. -197 is Linux 3.6, not Android. */
    sl_system_stream_info info = {
        .decoder_info = "FFmpeg NVDEC",
        .can_suspend = true,
    };
    bool tv = sl_system_docked();
    snprintf(info.system_info, sizeof(info.system_info),
             "\"SystemInfo\"\n{\n\t\"LogicalCPUCount\"\t\"4\"\n"
             "\t\"VideoDisplayX\"\t\"%u\"\n\t\"VideoDisplayY\"\t\"%u\"\n"
             "\t\"VideoDisplayNameID\"\t\"Nintendo Switch\"\n}\n",
             tv ? 1920u : 1280u, tv ? 1080u : 720u);
    return info;
}
