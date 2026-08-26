// M2 tool: discover Steam hosts, show a pairing code, and persist client identity.
// Output goes to both the libnx console and a manually-managed nxlink socket.
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>

#include <switch.h> /* Includes random/runtime/nxlink helpers. */

#include <ihslib/client.h>
#include <ihslib/common.h>
#include <ihslib/net.h>

#include "client_pri.h"
#include "discovery.pb-c.h"
#include "pb_utils.h"

#define AUTH_DIR      "sdmc:/switch/nsteamlink"
#define AUTH_PATH     AUTH_DIR "/auth.bin"
#define AUTH_TMP_PATH AUTH_DIR "/auth.tmp"
#define EXCEPTION_PATH AUTH_DIR "/exception_dump.txt"
#define EXIT_STAGE_PATH AUTH_DIR "/exit_stage.txt"
#define AUTH_MAGIC    "NSLAUTH"
#define AUTH_VERSION  1U
#define DEVICE_NAME   "nsteamlink-switch"
#define FALLBACK_HOST "10.10.10.166"

#define MAX_HOSTS      8
#define PAIR_CODE_SIZE 5
#define LOGQ_LEN       24
#define LOGQ_MSG       192
#define DEBUG_PORT     28772
#define DEBUG_RX       256
#define DEBUG_TX       1200

typedef struct __attribute__((packed)) sl_auth_file {
    char magic[8];
    uint32_t version;
    uint32_t size;
    uint64_t device_id;
    uint8_t secret_key[32];
    char device_name[64];
    uint64_t steam_id;
    char last_hostname[64];
    uint8_t last_host_ipv4[4];
    uint16_t last_host_port;
    uint8_t reserved[30];
} sl_auth_file;

typedef enum app_mode {
    APP_DISCOVERING,
    APP_AUTHORIZING,
    APP_DONE,
    APP_ERROR,
} app_mode;

typedef struct app_state {
    pthread_mutex_t lock;
    sl_auth_file auth;
    bool auth_loaded;
    bool auth_saved;
    bool auth_save_pending;
    bool auth_remove_requested;

    IHS_HostInfo hosts[MAX_HOSTS];
    int host_count;
    int selected_host;
    int fallback_frame;
    uint32_t fallback_seq;

    app_mode mode;
    char pairing_code[PAIR_CODE_SIZE];
    IHS_AuthorizationResult auth_result;
    char status[128];
    bool exit_requested;
} app_state;

typedef struct debug_server {
    int fd;
    struct in_addr allowed_host;
} debug_server;

static int cons_fd = -1;
static int nxlink_fd = -1;
static bool nxlink_active = false;

__attribute__((aligned(16))) u8 __nx_exception_stack[0x1000];
u64 __nx_exception_stack_size = sizeof(__nx_exception_stack);

void __libnx_exception_handler(ThreadExceptionDump *ctx) {
    mkdir(AUTH_DIR, 0777);
    FILE *fp = fopen(EXCEPTION_PATH, "w");
    if (fp == NULL) {
        fp = fopen("exception_dump", "w");
    }
    if (fp == NULL) {
        return;
    }

    fprintf(fp, "nsteamlink switch-discover exception dump\n");
    fprintf(fp, "error_desc: 0x%x\n", ctx->error_desc);
    for (int i = 0; i < 29; i++) {
        fprintf(fp, "x%d: 0x%016" PRIx64 "\n", i, (uint64_t)ctx->cpu_gprs[i].x);
    }
    fprintf(fp, "fp: 0x%016" PRIx64 "\n", (uint64_t)ctx->fp.x);
    fprintf(fp, "lr: 0x%016" PRIx64 "\n", (uint64_t)ctx->lr.x);
    fprintf(fp, "sp: 0x%016" PRIx64 "\n", (uint64_t)ctx->sp.x);
    fprintf(fp, "pc: 0x%016" PRIx64 "\n", (uint64_t)ctx->pc.x);
    fprintf(fp, "pstate: 0x%x\n", ctx->pstate);
    fprintf(fp, "afsr0: 0x%x\n", ctx->afsr0);
    fprintf(fp, "afsr1: 0x%x\n", ctx->afsr1);
    fprintf(fp, "esr: 0x%x\n", ctx->esr);
    fprintf(fp, "far: 0x%016" PRIx64 "\n", (uint64_t)ctx->far.x);
    fclose(fp);
}

/* Callback thread -> main thread log queue. The libnx console has one writer. */
static char logq[LOGQ_LEN][LOGQ_MSG];
static int logq_head = 0, logq_tail = 0;
static pthread_mutex_t logq_lock = PTHREAD_MUTEX_INITIALIZER;

static void set_status(app_state *state, const char *fmt, ...) {
    pthread_mutex_lock(&state->lock);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(state->status, sizeof(state->status), fmt, ap);
    va_end(ap);
    pthread_mutex_unlock(&state->lock);
}

/* Main thread only: write to console and the nxlink socket when active. */
static void logline(const char *fmt, ...) {
    char buf[LOGQ_MSG];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (cons_fd >= 0) {
        dprintf(cons_fd, "%s\n", buf);
    }
    if (nxlink_active && nxlink_fd >= 0) {
        if (dprintf(nxlink_fd, "%s\n", buf) < 0) {
            nxlink_active = false;
        }
    }
}

static void nxlink_log_close(void) {
    if (nxlink_fd < 0) {
        nxlink_active = false;
        return;
    }

    int fd = nxlink_fd;
    nxlink_fd = -1;
    nxlink_active = false;
    close(fd);
}

/* IHSlib callback thread: enqueue only, no direct IO. */
static void logline_net(const char *fmt, ...) {
    pthread_mutex_lock(&logq_lock);
    char *slot = logq[logq_head];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(slot, LOGQ_MSG, fmt, ap);
    va_end(ap);
    logq_head = (logq_head + 1) % LOGQ_LEN;
    if (logq_head == logq_tail) {
        logq_tail = (logq_tail + 1) % LOGQ_LEN; /* Drop the oldest entry. */
    }
    pthread_mutex_unlock(&logq_lock);
}

/* Main thread only: drain callback logs to console/nxlink. */
static void logq_drain(void) {
    for (;;) {
        pthread_mutex_lock(&logq_lock);
        if (logq_head == logq_tail) {
            pthread_mutex_unlock(&logq_lock);
            return;
        }
        char local[LOGQ_MSG];
        strncpy(local, logq[logq_tail], LOGQ_MSG);
        local[LOGQ_MSG - 1] = '\0';
        logq_tail = (logq_tail + 1) % LOGQ_LEN;
        pthread_mutex_unlock(&logq_lock);
        logline("%s", local);
    }
}

static void ihs_log(IHS_LogLevel level, const char *tag, const char *message) {
    if (level >= IHS_LogLevelDebug) {
        return;
    }
    logline_net("[IHS:%d][%s] %s", (int)level, tag, message);
}

static bool fallback_address(IHS_SocketAddress *address) {
    memset(address, 0, sizeof(*address));
    address->port = 27036;
    return IHS_IPAddressFromString(&address->ip, FALLBACK_HOST);
}

static void auth_fill_new(sl_auth_file *auth) {
    memset(auth, 0, sizeof(*auth));
    memcpy(auth->magic, AUTH_MAGIC, sizeof(auth->magic));
    auth->version = AUTH_VERSION;
    auth->size = sizeof(*auth);
    randomGet(&auth->device_id, sizeof(auth->device_id));
    auth->device_id = (auth->device_id & 0x00FFFFFFFFFFFFFFULL) | 0x5300000000000000ULL;
    if (auth->device_id == 0) {
        auth->device_id = 0x53574E5357590053ULL;
    }
    randomGet(auth->secret_key, sizeof(auth->secret_key));
    strncpy(auth->device_name, DEVICE_NAME, sizeof(auth->device_name) - 1);
}

static bool auth_valid(const sl_auth_file *auth) {
    return memcmp(auth->magic, AUTH_MAGIC, sizeof(auth->magic)) == 0 &&
           auth->version == AUTH_VERSION && auth->size == sizeof(*auth);
}

static bool ensure_auth_dir(void) {
    if (mkdir(AUTH_DIR, 0777) == 0 || errno == EEXIST) {
        return true;
    }
    return false;
}

static void write_exit_stage(const char *stage) {
    int saved_errno = errno;
    if (ensure_auth_dir()) {
        FILE *fp = fopen(EXIT_STAGE_PATH, "w");
        if (fp != NULL) {
            fprintf(fp, "%s\n", stage);
            fclose(fp);
        }
    }
    errno = saved_errno;
}

static bool auth_save(const sl_auth_file *auth) {
    if (!ensure_auth_dir()) {
        return false;
    }

    FILE *fp = fopen(AUTH_TMP_PATH, "wb");
    if (fp == NULL) {
        return false;
    }
    bool ok = fwrite(auth, 1, sizeof(*auth), fp) == sizeof(*auth);
    ok = fclose(fp) == 0 && ok;
    if (!ok) {
        remove(AUTH_TMP_PATH);
        return false;
    }
    if (rename(AUTH_TMP_PATH, AUTH_PATH) == 0) {
        return true;
    }
    remove(AUTH_PATH);
    return rename(AUTH_TMP_PATH, AUTH_PATH) == 0;
}

static bool auth_load_or_create(sl_auth_file *auth, bool *loaded_existing) {
    *loaded_existing = false;

    FILE *fp = fopen(AUTH_PATH, "rb");
    if (fp != NULL) {
        sl_auth_file disk;
        bool ok = fread(&disk, 1, sizeof(disk), fp) == sizeof(disk);
        fclose(fp);
        if (ok && auth_valid(&disk)) {
            *auth = disk;
            *loaded_existing = true;
            return true;
        }
    }

    auth_fill_new(auth);
    return auth_save(auth);
}

static void auth_record_host(sl_auth_file *auth, const IHS_HostInfo *host, uint64_t steam_id) {
    auth->steam_id = steam_id;
    strncpy(auth->last_hostname, host->hostname, sizeof(auth->last_hostname) - 1);
    auth->last_hostname[sizeof(auth->last_hostname) - 1] = '\0';
    auth->last_host_port = host->address.port;
    memset(auth->last_host_ipv4, 0, sizeof(auth->last_host_ipv4));
    if (host->address.ip.family == IHS_IPAddressFamilyIPv4) {
        memcpy(auth->last_host_ipv4, host->address.ip.v4.data, sizeof(auth->last_host_ipv4));
    }
}

static int host_find(app_state *state, const IHS_HostInfo *host) {
    for (int i = 0; i < state->host_count; i++) {
        const IHS_HostInfo *cur = &state->hosts[i];
        if (cur->clientId == host->clientId && cur->instanceId == host->instanceId &&
            IHS_IPAddressCompare(&cur->address.ip, &host->address.ip) == 0) {
            return i;
        }
    }
    return -1;
}

static void on_discovered(IHS_Client *client, const IHS_HostInfo *host, void *context) {
    (void)client;
    app_state *state = context;
    char *ip = IHS_IPAddressToString(&host->address.ip);

    pthread_mutex_lock(&state->lock);
    int index = host_find(state, host);
    if (index < 0 && state->host_count < MAX_HOSTS) {
        index = state->host_count++;
    }
    if (index >= 0) {
        state->hosts[index] = *host;
        if (state->selected_host < 0) {
            state->selected_host = index;
        }
        if (state->mode == APP_DISCOVERING) {
            snprintf(state->status, sizeof(state->status), "Host found. Press A to pair.");
        }
    }
    pthread_mutex_unlock(&state->lock);

    logline_net("host found: %s (%s) gamesRunning=%d", host->hostname, ip ? ip : "?",
                (int)host->gamesRunning);
    free(ip);
}

static void on_authorization_progress(IHS_Client *client, const IHS_HostInfo *host, void *context) {
    (void)client;
    (void)host;
    set_status(context, "Steam is authorizing...");
    logline_net("authorization in progress");
}

static void on_authorization_success(IHS_Client *client, const IHS_HostInfo *host,
                                     uint64_t steam_id, void *context) {
    (void)client;
    app_state *state = context;
    pthread_mutex_lock(&state->lock);
    auth_record_host(&state->auth, host, steam_id);
    state->auth_save_pending = true;
    state->auth_result = IHS_AuthorizationSuccess;
    state->mode = APP_DONE;
    state->pairing_code[0] = '\0';
    snprintf(state->status, sizeof(state->status), "Authorization success, steamId=%" PRIu64,
             steam_id);
    pthread_mutex_unlock(&state->lock);
    logline_net("authorization success steamId=%" PRIu64, steam_id);
}

static void on_authorization_failed(IHS_Client *client, const IHS_HostInfo *host,
                                    IHS_AuthorizationResult result, void *context) {
    (void)client;
    (void)host;
    app_state *state = context;
    pthread_mutex_lock(&state->lock);
    state->auth_result = result;
    state->mode = APP_DISCOVERING;
    state->pairing_code[0] = '\0';
    snprintf(state->status, sizeof(state->status), "Authorization failed result=%d; press A for new code",
             (int)result);
    pthread_mutex_unlock(&state->lock);
    logline_net("authorization failed result=%d", (int)result);
}

static void console_draw(app_state *state) {
    if (cons_fd < 0) {
        return;
    }

    pthread_mutex_lock(&state->lock);
    app_state s = *state;
    pthread_mutex_unlock(&state->lock);

    dprintf(cons_fd, "\x1b[2J\x1b[H");
    dprintf(cons_fd, "nsteamlink M2 pairing tool\n");
    dprintf(cons_fd, "deviceId: 0x%016" PRIx64 "  auth: %s\n", s.auth.device_id,
            s.auth.steam_id ? "saved" : "not paired");
    if (s.auth.steam_id) {
        dprintf(cons_fd, "steamId: %" PRIu64 "  last host: %s\n", s.auth.steam_id,
                s.auth.last_hostname[0] ? s.auth.last_hostname : "?");
    }
    dprintf(cons_fd, "status: %s\n\n", s.status[0] ? s.status : "-");

    if (s.mode == APP_DISCOVERING) {
        dprintf(cons_fd, "Discovering Steam hosts...\n");
        dprintf(cons_fd,
                "A: pair selected host  UP/DOWN: select host  Y: delete auth.bin  PLUS: exit\n\n");
        if (s.host_count == 0) {
            dprintf(cons_fd, "No hosts yet. Keep Steam running; UDP 27036 must be reachable.\n");
        }
        for (int i = 0; i < s.host_count; i++) {
            char *ip = IHS_IPAddressToString(&s.hosts[i].address.ip);
            dprintf(cons_fd, "%c %d. %s  %s  gamesRunning=%d\n", i == s.selected_host ? '>' : ' ',
                    i + 1, s.hosts[i].hostname, ip ? ip : "?", (int)s.hosts[i].gamesRunning);
            free(ip);
        }
    } else if (s.mode == APP_AUTHORIZING) {
        const IHS_HostInfo *host = s.selected_host >= 0 ? &s.hosts[s.selected_host] : NULL;
        dprintf(cons_fd, "Pairing with: %s\n\n", host ? host->hostname : "?");
        dprintf(cons_fd, "Enter this code in Steam on the host:\n\n");
        dprintf(cons_fd, "        %s\n\n", s.pairing_code[0] ? s.pairing_code : "----");
        dprintf(cons_fd, "Steam path: Settings > Remote Play > Pair Steam Link app\n\n");
        dprintf(cons_fd, "B: cancel authorization  PLUS: exit\n");
    } else if (s.mode == APP_DONE) {
        dprintf(cons_fd, "M2 pairing complete.\n");
        dprintf(cons_fd, "auth.bin saved to %s\n", AUTH_PATH);
        dprintf(cons_fd, "PLUS: return to hbmenu\n");
    } else {
        dprintf(cons_fd, "Error. PLUS: return to hbmenu\n");
    }
}

static void request_auth_save_if_needed(app_state *state) {
    sl_auth_file auth;
    bool should_save = false;

    pthread_mutex_lock(&state->lock);
    if (state->auth_save_pending) {
        auth = state->auth;
        state->auth_save_pending = false;
        should_save = true;
    }
    pthread_mutex_unlock(&state->lock);

    if (!should_save) {
        return;
    }
    if (auth_save(&auth)) {
        set_status(state, "auth.bin saved; this identity will be reused");
        logline("auth.bin saved: %s", AUTH_PATH);
    } else {
        set_status(state, "Authorization OK, but auth.bin save failed errno=%d", errno);
        logline("auth.bin save failed errno=%d", errno);
    }
}

static void request_auth_remove_if_needed(app_state *state) {
    bool should_remove = false;
    pthread_mutex_lock(&state->lock);
    if (state->auth_remove_requested) {
        state->auth_remove_requested = false;
        should_remove = true;
    }
    pthread_mutex_unlock(&state->lock);

    if (!should_remove) {
        return;
    }
    remove(AUTH_TMP_PATH);
    if (remove(AUTH_PATH) == 0 || errno == ENOENT) {
        set_status(state, "auth.bin deleted; relaunch to create a new identity");
        logline("auth.bin removed; relaunch to generate a new identity");
    } else {
        set_status(state, "auth.bin delete failed errno=%d", errno);
        logline("auth.bin remove failed errno=%d", errno);
    }
}

static void maybe_send_fallback_discovery(app_state *state, IHS_Client *client) {
    bool should_send = false;
    uint32_t seq = 0;

    pthread_mutex_lock(&state->lock);
    if (state->mode == APP_DISCOVERING) {
        state->fallback_frame++;
        if (state->fallback_frame == 1 || state->fallback_frame % 120 == 0) {
            seq = ++state->fallback_seq;
            should_send = true;
        }
    }
    pthread_mutex_unlock(&state->lock);

    if (!should_send) {
        return;
    }

    IHS_SocketAddress address;
    if (!fallback_address(&address)) {
        return;
    }
    CMsgRemoteClientBroadcastDiscovery msg = CMSG_REMOTE_CLIENT_BROADCAST_DISCOVERY__INIT;
    PROTOBUF_C_SET_VALUE(msg, seq_num, seq);
    bool sent = IHS_ClientSend(client, address, k_ERemoteClientBroadcastMsgDiscovery,
                               (ProtobufCMessage *)&msg);
    if (seq == 1 || !sent) {
        logline("fallback discovery -> %s:27036 ret=%d", FALLBACK_HOST, (int)sent);
    }
}

static const char *mode_name(app_mode mode) {
    switch (mode) {
    case APP_DISCOVERING:
        return "discovering";
    case APP_AUTHORIZING:
        return "pairing";
    case APP_DONE:
        return "done";
    case APP_ERROR:
        return "error";
    default:
        return "unknown";
    }
}

static void make_pairing_code(char out[PAIR_CODE_SIZE]) {
    uint32_t r = 0;
    randomGet(&r, sizeof(r));
    snprintf(out, PAIR_CODE_SIZE, "%04u", (unsigned)(r % 10000U));
}

static bool start_pairing(app_state *state, IHS_Client *client, char *err, size_t err_len) {
    IHS_HostInfo host;
    char code[PAIR_CODE_SIZE];
    make_pairing_code(code);

    pthread_mutex_lock(&state->lock);
    if (state->mode == APP_ERROR) {
        if (err != NULL && err_len > 0) {
            snprintf(err, err_len, "app is in error mode");
        }
        pthread_mutex_unlock(&state->lock);
        return false;
    }
    if (state->mode == APP_AUTHORIZING) {
        if (err != NULL && err_len > 0) {
            snprintf(err, err_len, "authorization already in progress");
        }
        pthread_mutex_unlock(&state->lock);
        return false;
    }
    if (state->selected_host < 0 || state->selected_host >= state->host_count) {
        if (err != NULL && err_len > 0) {
            snprintf(err, err_len, "no selected host");
        }
        pthread_mutex_unlock(&state->lock);
        return false;
    }

    host = state->hosts[state->selected_host];
    strncpy(state->pairing_code, code, sizeof(state->pairing_code));
    state->pairing_code[sizeof(state->pairing_code) - 1] = '\0';
    state->mode = APP_AUTHORIZING;
    state->auth_result = IHS_AuthorizationInProgress;
    snprintf(state->status, sizeof(state->status), "Enter code %s in Steam on host", code);
    pthread_mutex_unlock(&state->lock);

    (void)IHS_ClientStartDiscovery(client, 0);
    if (!IHS_ClientAuthorizationRequest(client, &host, code)) {
        set_status(state, "IHS_ClientAuthorizationRequest failed");
        pthread_mutex_lock(&state->lock);
        state->mode = APP_DISCOVERING;
        state->pairing_code[0] = '\0';
        pthread_mutex_unlock(&state->lock);
        if (err != NULL && err_len > 0) {
            snprintf(err, err_len, "IHS_ClientAuthorizationRequest failed");
        }
        return false;
    }
    logline("pairing code for %s: %s", host.hostname, code);
    return true;
}

static bool should_cancel_authorization(app_state *state) {
    pthread_mutex_lock(&state->lock);
    bool cancel = state->mode == APP_AUTHORIZING;
    pthread_mutex_unlock(&state->lock);
    return cancel;
}

static void cleanup_client(app_state *state, IHS_Client *client) {
    if (client == NULL) {
        return;
    }

    if (should_cancel_authorization(state)) {
        logline("cleanup: cancel authorization");
        IHS_ClientAuthorizationCancel(client);
    }

    logline("cleanup: stop discovery");
    IHS_ClientStopDiscovery(client);
    logline("cleanup: stop IHS worker");
    IHS_ClientStop(client);
    logline("cleanup: join IHS worker");
    IHS_ClientThreadedJoin(client);
    logq_drain();
    logline("cleanup: destroy IHS client");
    IHS_ClientDestroy(client);
    logq_drain();
}

static void handle_input(app_state *state, IHS_Client *client, u64 kdown) {
    if (kdown & HidNpadButton_Plus) {
        pthread_mutex_lock(&state->lock);
        state->exit_requested = true;
        pthread_mutex_unlock(&state->lock);
        return;
    }

    if (kdown & HidNpadButton_Y) {
        pthread_mutex_lock(&state->lock);
        state->auth_remove_requested = true;
        pthread_mutex_unlock(&state->lock);
        return;
    }

    pthread_mutex_lock(&state->lock);
    if (state->mode == APP_DISCOVERING) {
        if ((kdown & HidNpadButton_Down) && state->host_count > 0) {
            state->selected_host = (state->selected_host + 1) % state->host_count;
        } else if ((kdown & HidNpadButton_Up) && state->host_count > 0) {
            state->selected_host =
                (state->selected_host + state->host_count - 1) % state->host_count;
        } else if ((kdown & HidNpadButton_A) && state->selected_host >= 0) {
            pthread_mutex_unlock(&state->lock);
            char err[96];
            if (!start_pairing(state, client, err, sizeof(err))) {
                set_status(state, "%s", err);
            }
            return;
        }
    } else if (state->mode == APP_AUTHORIZING) {
        if (kdown & HidNpadButton_B) {
            state->mode = APP_DISCOVERING;
            state->pairing_code[0] = '\0';
            snprintf(state->status, sizeof(state->status), "Authorization canceled; press A for new code");
            pthread_mutex_unlock(&state->lock);
            IHS_ClientAuthorizationCancel(client);
            return;
        }
    }
    pthread_mutex_unlock(&state->lock);
}

static bool ascii_ieq(const char *a, const char *b) {
    while (*a != '\0' && *b != '\0') {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return false;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static char *trim_ascii(char *s) {
    while (isspace((unsigned char)*s)) {
        s++;
    }
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) {
        *--end = '\0';
    }
    return s;
}

static bool parse_button(const char *name, u64 *button) {
    if (ascii_ieq(name, "A")) {
        *button = HidNpadButton_A;
    } else if (ascii_ieq(name, "B")) {
        *button = HidNpadButton_B;
    } else if (ascii_ieq(name, "Y")) {
        *button = HidNpadButton_Y;
    } else if (ascii_ieq(name, "PLUS") || ascii_ieq(name, "+")) {
        *button = HidNpadButton_Plus;
    } else if (ascii_ieq(name, "UP")) {
        *button = HidNpadButton_Up;
    } else if (ascii_ieq(name, "DOWN")) {
        *button = HidNpadButton_Down;
    } else if (ascii_ieq(name, "LEFT")) {
        *button = HidNpadButton_Left;
    } else if (ascii_ieq(name, "RIGHT")) {
        *button = HidNpadButton_Right;
    } else {
        return false;
    }
    return true;
}

static void state_line(app_state *state, char *out, size_t out_len) {
    IHS_HostInfo host;
    bool have_host = false;
    app_mode mode;
    int host_count;
    int selected_host;
    uint64_t steam_id;
    char pairing_code[sizeof(state->pairing_code)];
    char status[sizeof(state->status)];

    pthread_mutex_lock(&state->lock);
    mode = state->mode;
    host_count = state->host_count;
    selected_host = state->selected_host;
    steam_id = state->auth.steam_id;
    strncpy(pairing_code, state->pairing_code, sizeof(pairing_code));
    pairing_code[sizeof(pairing_code) - 1] = '\0';
    strncpy(status, state->status, sizeof(status));
    status[sizeof(status) - 1] = '\0';
    if (selected_host >= 0 && selected_host < host_count) {
        host = state->hosts[selected_host];
        have_host = true;
    }
    pthread_mutex_unlock(&state->lock);

    char *ip = have_host ? IHS_IPAddressToString(&host.address.ip) : NULL;
    snprintf(out, out_len,
             "mode=%s hosts=%d selected=%d host=%s ip=%s games=%d paired=%d steamId=%" PRIu64
             " code=%s status=\"%s\"",
             mode_name(mode), host_count, selected_host + 1, have_host ? host.hostname : "-",
             ip ? ip : "-", have_host ? (int)host.gamesRunning : -1, steam_id != 0, steam_id,
             pairing_code[0] ? pairing_code : "-", status[0] ? status : "-");
    free(ip);
}

static void debug_reply(debug_server *dbg, const struct sockaddr_in *peer, const char *fmt, ...) {
    char out[DEBUG_TX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(out, sizeof(out), fmt, ap);
    va_end(ap);
    sendto(dbg->fd, out, strlen(out), 0, (const struct sockaddr *)peer, sizeof(*peer));
}

static bool debug_peer_allowed(const debug_server *dbg, const struct sockaddr_in *peer) {
    return dbg->allowed_host.s_addr == 0 || peer->sin_addr.s_addr == dbg->allowed_host.s_addr;
}

static void debug_reply_hosts(debug_server *dbg, const struct sockaddr_in *peer, app_state *state) {
    IHS_HostInfo hosts[MAX_HOSTS];
    int host_count;
    int selected_host;

    pthread_mutex_lock(&state->lock);
    host_count = state->host_count;
    selected_host = state->selected_host;
    for (int i = 0; i < host_count; i++) {
        hosts[i] = state->hosts[i];
    }
    pthread_mutex_unlock(&state->lock);

    char out[DEBUG_TX];
    int off = snprintf(out, sizeof(out), "OK hosts=%d selected=%d", host_count, selected_host + 1);
    for (int i = 0; i < host_count && off > 0 && off < (int)sizeof(out); i++) {
        char *ip = IHS_IPAddressToString(&hosts[i].address.ip);
        off += snprintf(out + off, sizeof(out) - (size_t)off, "\n%d %s %s games=%d", i + 1,
                        hosts[i].hostname, ip ? ip : "-", (int)hosts[i].gamesRunning);
        free(ip);
    }
    sendto(dbg->fd, out, strlen(out), 0, (const struct sockaddr *)peer, sizeof(*peer));
}

static bool debug_select_host(app_state *state, const char *arg, char *err, size_t err_len) {
    char *end = NULL;
    long one_based = strtol(arg, &end, 10);
    if (end == arg || *trim_ascii(end) != '\0') {
        snprintf(err, err_len, "select expects a host number");
        return false;
    }

    pthread_mutex_lock(&state->lock);
    if (one_based < 1 || one_based > state->host_count) {
        snprintf(err, err_len, "host number out of range");
        pthread_mutex_unlock(&state->lock);
        return false;
    }
    state->selected_host = (int)one_based - 1;
    snprintf(state->status, sizeof(state->status), "Selected host %ld", one_based);
    pthread_mutex_unlock(&state->lock);
    return true;
}

static void debug_reply_state(debug_server *dbg, const struct sockaddr_in *peer, app_state *state,
                              const char *prefix) {
    char line[DEBUG_TX - 16];
    state_line(state, line, sizeof(line));
    debug_reply(dbg, peer, "%s %s", prefix, line);
}

static void debug_handle_command(debug_server *dbg, const struct sockaddr_in *peer, app_state *state,
                                 IHS_Client *client, char *line) {
    char *cmd = trim_ascii(line);
    char *arg = cmd;
    while (*arg != '\0' && !isspace((unsigned char)*arg)) {
        arg++;
    }
    if (*arg != '\0') {
        *arg++ = '\0';
        arg = trim_ascii(arg);
    }

    if (*cmd == '\0' || ascii_ieq(cmd, "help")) {
        debug_reply(dbg, peer,
                    "OK commands: ping state hosts press <A|B|Y|PLUS|UP|DOWN|LEFT|RIGHT> "
                    "select <n> pair code delete-auth exit");
    } else if (ascii_ieq(cmd, "ping")) {
        debug_reply(dbg, peer, "OK pong");
    } else if (ascii_ieq(cmd, "state")) {
        debug_reply_state(dbg, peer, state, "OK");
    } else if (ascii_ieq(cmd, "hosts")) {
        debug_reply_hosts(dbg, peer, state);
    } else if (ascii_ieq(cmd, "press")) {
        u64 button = 0;
        if (!parse_button(arg, &button)) {
            debug_reply(dbg, peer, "ERR unknown button");
            return;
        }
        handle_input(state, client, button);
        debug_reply_state(dbg, peer, state, "OK");
    } else if (ascii_ieq(cmd, "select")) {
        char err[96];
        if (!debug_select_host(state, arg, err, sizeof(err))) {
            debug_reply(dbg, peer, "ERR %s", err);
            return;
        }
        debug_reply_state(dbg, peer, state, "OK");
    } else if (ascii_ieq(cmd, "pair")) {
        if (*arg != '\0') {
            debug_reply(dbg, peer, "ERR pair takes no PIN; Switch generates the code");
            return;
        }
        char err[96];
        if (!start_pairing(state, client, err, sizeof(err))) {
            debug_reply(dbg, peer, "ERR %s", err);
            return;
        }
        debug_reply_state(dbg, peer, state, "OK");
    } else if (ascii_ieq(cmd, "code")) {
        debug_reply_state(dbg, peer, state, "OK");
    } else if (ascii_ieq(cmd, "pin") || ascii_ieq(cmd, "submit")) {
        debug_reply(dbg, peer, "ERR deprecated; pairing code is generated on Switch, use pair");
    } else if (ascii_ieq(cmd, "delete-auth")) {
        pthread_mutex_lock(&state->lock);
        state->auth_remove_requested = true;
        pthread_mutex_unlock(&state->lock);
        debug_reply_state(dbg, peer, state, "OK");
    } else if (ascii_ieq(cmd, "exit")) {
        pthread_mutex_lock(&state->lock);
        state->exit_requested = true;
        pthread_mutex_unlock(&state->lock);
        debug_reply_state(dbg, peer, state, "OK");
    } else {
        debug_reply(dbg, peer, "ERR unknown command");
    }
}

static void debug_server_init(debug_server *dbg) {
    memset(dbg, 0, sizeof(*dbg));
    dbg->fd = -1;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        logline("debug udp disabled: socket errno=%d", errno);
        return;
    }

    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DEBUG_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        logline("debug udp disabled: bind %d errno=%d", DEBUG_PORT, errno);
        close(fd);
        return;
    }

    dbg->fd = fd;
    dbg->allowed_host = __nxlink_host;
    logline("debug udp ready: port=%d allowed=%s", DEBUG_PORT,
            dbg->allowed_host.s_addr ? inet_ntoa(dbg->allowed_host) : "any");
}

static void debug_server_poll(debug_server *dbg, app_state *state, IHS_Client *client) {
    if (dbg->fd < 0) {
        return;
    }

    for (int i = 0; i < 8; i++) {
        char buf[DEBUG_RX];
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        ssize_t n = recvfrom(dbg->fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&peer, &peer_len);
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                logline("debug udp recv errno=%d", errno);
            }
            return;
        }
        buf[n] = '\0';
        if (!debug_peer_allowed(dbg, &peer)) {
            continue;
        }
        debug_handle_command(dbg, &peer, state, client, buf);
    }
}

static void debug_server_close(debug_server *dbg) {
    if (dbg->fd >= 0) {
        close(dbg->fd);
        dbg->fd = -1;
    }
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    Result exit_lock_rc = appletLockExit();
    bool exit_lock_active = R_SUCCEEDED(exit_lock_rc);

    consoleInit(NULL);
    cons_fd = dup(1);
    Result sleep_lock_rc = appletRequestToAcquireSleepLock();
    bool sleep_lock_active = R_SUCCEEDED(sleep_lock_rc);

    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    PadState pad;
    padInitializeDefault(&pad);

    app_state state;
    memset(&state, 0, sizeof(state));
    pthread_mutex_init(&state.lock, NULL);
    state.selected_host = -1;
    state.mode = APP_DISCOVERING;

    bool loaded_existing = false;
    if (!auth_load_or_create(&state.auth, &loaded_existing)) {
        snprintf(state.status, sizeof(state.status), "auth.bin init failed errno=%d", errno);
        state.mode = APP_ERROR;
    } else {
        state.auth_loaded = loaded_existing;
        state.auth_saved = true;
        snprintf(state.status, sizeof(state.status), "%s auth.bin: %s",
                 loaded_existing ? "Loaded" : "Created", AUTH_PATH);
    }

    if (R_FAILED(socketInitializeDefault())) {
        logline("socketInitialize failed");
        if (sleep_lock_active) {
            appletReleaseSleepLock();
        }
        if (cons_fd >= 0) {
            close(cons_fd);
            cons_fd = -1;
        }
        consoleExit(NULL);
        if (exit_lock_active) {
            appletUnlockExit();
        }
        return 1;
    }
    bool socket_active = true;
    nxlink_fd = nxlinkConnectToHost(false, false); /* Keep stdout/stderr owned by console. */
    nxlink_active = nxlink_fd >= 0;

    logline("nsteamlink M2 pairing tool");
    if (!exit_lock_active) {
        logline("appletLockExit failed rc=0x%x", (unsigned)exit_lock_rc);
    }
    if (!sleep_lock_active) {
        logline("sleep lock not acquired rc=0x%x", (unsigned)sleep_lock_rc);
    }
    logline("%s auth.bin: deviceId=0x%016" PRIx64, loaded_existing ? "loaded" : "created",
            state.auth.device_id);

    debug_server debug;
    debug_server_init(&debug);

    IHS_Init(); /* Must run before creating an IHS client. */
    bool ihs_active = true;

    IHS_ClientConfig config = {
        .deviceId = state.auth.device_id,
        .secretKey = state.auth.secret_key,
        .deviceName = state.auth.device_name,
    };
    IHS_Client *client = IHS_ClientCreate(&config);
    if (client == NULL) {
        logline("IHS_ClientCreate failed");
        write_exit_stage("client_create_failed:ihs_quit:start");
        IHS_Quit();
        ihs_active = false;
        write_exit_stage("client_create_failed:ihs_quit:done");
        debug_server_close(&debug);
        if (nxlink_fd >= 0) {
            logline("cleanup: close nxlink log socket");
            write_exit_stage("client_create_failed:nxlink_close:start");
            nxlink_log_close();
            write_exit_stage("client_create_failed:nxlink_close:done");
        }
        if (socket_active) {
            write_exit_stage("client_create_failed:socket_exit:start");
            socketExit();
            write_exit_stage("client_create_failed:socket_exit:done");
        }
        if (sleep_lock_active) {
            write_exit_stage("client_create_failed:sleep_release:start");
            appletReleaseSleepLock();
            write_exit_stage("client_create_failed:sleep_release:done");
        }
        if (cons_fd >= 0) {
            close(cons_fd);
            cons_fd = -1;
        }
        write_exit_stage("client_create_failed:console_exit:start");
        consoleExit(NULL);
        if (exit_lock_active) {
            write_exit_stage("client_create_failed:applet_unlock:start");
            appletUnlockExit();
            write_exit_stage("client_create_failed:applet_unlock:done");
        }
        return 1;
    }
    IHS_ClientSetLogFunction(client, ihs_log);

    static const IHS_ClientDiscoveryCallbacks discovery_callbacks = {
        .discovered = on_discovered,
    };
    static const IHS_ClientAuthorizationCallbacks authorization_callbacks = {
        .progress = on_authorization_progress,
        .success = on_authorization_success,
        .failed = on_authorization_failed,
    };
    IHS_ClientSetDiscoveryCallbacks(client, &discovery_callbacks, &state);
    IHS_ClientSetAuthorizationCallbacks(client, &authorization_callbacks, &state);

    if (state.mode != APP_ERROR) {
        bool started = IHS_ClientStartDiscovery(client, 500);
        logline("StartDiscovery -> %d", (int)started);
    }

    while (appletMainLoop()) {
        padUpdate(&pad);
        u64 kdown = padGetButtonsDown(&pad);
        handle_input(&state, client, kdown);
        debug_server_poll(&debug, &state, client);
        maybe_send_fallback_discovery(&state, client);
        request_auth_save_if_needed(&state);
        request_auth_remove_if_needed(&state);
        logq_drain();
        console_draw(&state);
        consoleUpdate(NULL);

        pthread_mutex_lock(&state.lock);
        bool should_exit = state.exit_requested;
        pthread_mutex_unlock(&state.lock);
        if (should_exit) {
            break;
        }
        svcSleepThread(16 * 1000 * 1000);
    }

    write_exit_stage("cleanup:client:start");
    cleanup_client(&state, client);
    write_exit_stage("cleanup:client:done");

    write_exit_stage("cleanup:debug_close:start");
    debug_server_close(&debug);
    write_exit_stage("cleanup:debug_close:done");

    if (ihs_active) {
        logline("cleanup: IHS_Quit");
        write_exit_stage("cleanup:ihs_quit:start");
        IHS_Quit();
        ihs_active = false;
        write_exit_stage("cleanup:ihs_quit:done");
    }

    write_exit_stage("cleanup:state_destroy:start");
    pthread_mutex_destroy(&state.lock);
    write_exit_stage("cleanup:state_destroy:done");

    logline("cleanup: close nxlink log socket");
    if (nxlink_fd >= 0) {
        write_exit_stage("cleanup:nxlink_close:start");
        nxlink_log_close();
        write_exit_stage("cleanup:nxlink_close:done");
    }
    if (socket_active) {
        logline("cleanup: socketExit");
        write_exit_stage("cleanup:socket_exit:start");
        socketExit();
        socket_active = false;
        write_exit_stage("cleanup:socket_exit:done");
    }
    if (sleep_lock_active) {
        write_exit_stage("cleanup:sleep_release:start");
        appletReleaseSleepLock();
        sleep_lock_active = false;
        write_exit_stage("cleanup:sleep_release:done");
    }
    if (cons_fd >= 0) {
        close(cons_fd);
        cons_fd = -1;
    }
    write_exit_stage("cleanup:console_exit:start");
    consoleExit(NULL);
    write_exit_stage("cleanup:console_exit:done");
    if (exit_lock_active) {
        write_exit_stage("cleanup:applet_unlock:start");
        appletUnlockExit();
        write_exit_stage("cleanup:applet_unlock:done");
    }
    write_exit_stage("cleanup:return");
    return 0;
}
