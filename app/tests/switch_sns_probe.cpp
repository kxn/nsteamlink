#include <switch.h>
#include <steam/steamnetworkingsockets.h>
#include <steam/isteamnetworkingutils.h>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <ctime>
#include <cstdarg>
#include <cstdlib>
#include <sys/socket.h>
#include <dirent.h>

extern "C" void SteamNetworkingSockets_SetManualPollMode(bool);
extern "C" void SteamNetworkingSockets_Poll(int);
/* D-015: keep stdio owned by the runtime. Closing a redirected nxlink fd
 * before C/C++ exit handlers is not an accepted loader cleanup path. */
static int log_fd = -1;
static char transcript[65536];
static size_t used, delivered;
static void send_pending() {
    if (log_fd >= 0 && delivered < used) {
        ssize_t n = send(log_fd, transcript + delivered, used - delivered, MSG_DONTWAIT);
        if (n > 0) delivered += size_t(n);
    }
}
static const char *stage_path = "sdmc:/switch/nsteamlink-sns-probe.stage";
static void trace(const char *format, ...) {
    char line[512];
    va_list args;
    va_start(args, format);
    int n = vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    if (n > 0) {
        size_t length = size_t(n) < sizeof(line) ? size_t(n) : sizeof(line) - 1;
        if (length <= sizeof(transcript) - used) {
            memcpy(transcript + used, line, length);
            used += length;
        }
        send_pending();
    }
}
static void save_stage(const char *name) {
    FILE *file = fopen(stage_path, "w");
    if (file) {
        fprintf(file, "%s\n", name);
        fclose(file);
    }
}
static void sdk_exit_returned() { save_stage("sdk_atexit_returned"); }
static uint64_t now_ms() {
    timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return uint64_t(t.tv_sec) * 1000 + uint64_t(t.tv_nsec) / 1000000;
}
static void read_report(const char *directory) {
    DIR *dir = opendir(directory);
    if (!dir) return;
    char latest[256] = {};
    while (dirent *entry = readdir(dir)) {
        size_t n = strlen(entry->d_name);
        if (n > 4 && !strcmp(entry->d_name + n - 4, ".log") &&
            strcmp(entry->d_name, latest) > 0 && n < sizeof(latest))
            strcpy(latest, entry->d_name);
    }
    closedir(dir);
    if (!latest[0]) return;
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", directory, latest);
    FILE *file = fopen(path, "r");
    if (!file) return;
    trace("REPORT_BEGIN %s\n", path);
    char line[384];
    size_t total = 0;
    while (total < 16384 && fgets(line, sizeof(line), file)) {
        total += strlen(line);
        trace("REPORT %s", line);
    }
    fclose(file);
    trace("REPORT_END bytes=%zu\n", total);
}
static bool cycle(unsigned round) {
    SteamNetworkingSockets_SetManualPollMode(true);
    SteamNetworkingErrMsg error;
    bool initialized = GameNetworkingSockets_Init(nullptr, error);
    trace("{\"test\":\"sns\",\"round\":%u,\"stage\":\"init\",\"ok\":%s}\n",
        round, initialized ? "true" : "false");
    if (!initialized) {
        SteamNetworkingSockets_SetManualPollMode(false);
        return false;
    }
    auto *s = SteamNetworkingSockets();
    SteamNetworkingUtils()->SetDebugOutputFunction(k_ESteamNetworkingSocketsDebugOutputType_None, nullptr);
    HSteamNetConnection a = 0, b = 0;
    bool ok = s->CreateSocketPair(&a, &b, true, nullptr, nullptr);
    uint64_t deadline = now_ms() + 5000;
    while (ok && now_ms() < deadline) {
        SteamNetworkingSockets_Poll(0);
        SteamNetConnectionInfo_t x, y;
        ok = s->GetConnectionInfo(a, &x) && s->GetConnectionInfo(b, &y);
        if (ok && x.m_eState == k_ESteamNetworkingConnectionState_Connected &&
            y.m_eState == k_ESteamNetworkingConnectionState_Connected)
            break;
        usleep(1000);
    }
    if (now_ms() >= deadline)
        ok = false;
    unsigned char bytes[4096];
    for (unsigned i = 0; i < sizeof(bytes); ++i)
        bytes[i] = uint8_t(i ^ 0xa5);
    if (ok)
        ok = s->SendMessageToConnection(a, bytes, 31, 0x15, nullptr) == k_EResultOK &&
            s->SendMessageToConnection(a, bytes, sizeof(bytes), 0x15, nullptr) == k_EResultOK;
    unsigned messages = 0, sizes = 0;
    deadline = now_ms() + 5000;
    while (ok && messages < 2 && now_ms() < deadline) {
        SteamNetworkingSockets_Poll(0);
        SteamNetworkingMessage_t *incoming[8];
        int count = s->ReceiveMessagesOnConnection(b, incoming, 8);
        if (count < 0) {
            ok = false;
            break;
        }
        for (int i = 0; i < count; ++i) {
            auto *m = incoming[i];
            unsigned size_bit = m->m_cbSize == 31 ? 1u :
                m->m_cbSize == sizeof(bytes) ? 2u : 0u;
            bool exact = size_bit && !(sizes & size_bit);
            if (exact)
                exact = !memcmp(m->m_pData, bytes, size_t(m->m_cbSize));
            ok = ok && exact;
            sizes |= size_bit;
            m->Release();
            ++messages;
        }
        usleep(1000);
    }
    ok = ok && messages == 2 && sizes == 3;
    trace("{\"test\":\"sns\",\"round\":%u,\"stage\":\"datagrams\",\"messages\":%u,\"ok\":%s}\n",
        round, messages, ok ? "true" : "false");
    if (a) s->CloseConnection(a, 1000, "probe complete", false);
    if (b) s->CloseConnection(b, 1000, "probe complete", false);
    GameNetworkingSockets_Kill();
    SteamNetworkingSockets_SetManualPollMode(false);
    trace("{\"test\":\"sns\",\"round\":%u,\"stage\":\"sdk_destroyed\",\"ok\":true}\n", round);
    return ok;
}
int main(int, char **) {
    Result initialized = socketInitializeDefault();
    if (R_FAILED(initialized))
        return 1;
    log_fd = nxlinkConnectToHost(false, false);
    if (log_fd >= 0)
        fcntl(log_fd, F_SETFL, fcntl(log_fd, F_GETFL) | O_NONBLOCK);
    FILE *previous = fopen(stage_path, "r");
    if (previous) {
        char text[96] = {};
        if (fgets(text, sizeof(text), previous)) {
            text[strcspn(text, "\r\n")] = 0;
            trace("{\"test\":\"sns\",\"stage\":\"previous_exit\",\"value\":\"%s\"}\n", text);
        }
        fclose(previous);
    }
    trace("{\"test\":\"sns\",\"stage\":\"probe_version\",\"revision\":2,\"stdio_redirected\":false}\n");
    read_report("sdmc:/atmosphere/crash_reports");
    read_report("sdmc:/atmosphere/fatal_reports");
    save_stage("started");
    /* Runs after SDK's dynamically registered atexit handler, before earlier
     * static destructors. It cannot prove the loader accepted our return. */
    atexit(sdk_exit_returned);
    bool first = cycle(1);
    bool second = cycle(2);
    trace("{\"test\":\"sns\",\"stage\":\"result\",\"ok\":%s,\"cycles\":2}\n",
        first && second ? "true" : "false");
    save_stage("sdk_destroyed");
    trace("{\"test\":\"sns\",\"stage\":\"cleanup\",\"order\":\"sdk_destroyed,log_close,socket_exit,return\"}\n");
    uint64_t log_deadline = now_ms() + 500;
    while (delivered < used && now_ms() < log_deadline) {
        send_pending();
        usleep(1000);
    }
    if (log_fd >= 0) {
        int fd = log_fd;
        log_fd = -1;
        close(fd);
    }
    save_stage("log_closed");
    socketExit();
    save_stage("socket_exit_returned");
    return first && second ? 0 : 1;
}
