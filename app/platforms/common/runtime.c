#include "platform/runtime.h"
#include "client_pri.h"
#include "connection_wait.h"
#include "discovery.pb-c.h"
#include "media.h"
#include "network_stats_file.h"
#include "platform/shortcut.h"
#include "platform/system.h"
#include "protobuf/remoteplay.pb-c.h"
#include "services/i18n.h"
#include "services/launch_watch.h"
#include "services/update_config.h"
#include "stream_settings.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ihslib/client.h>
#include <ihslib/input.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct sl_runtime {
    pthread_t worker;
    atomic_bool exit_requested, worker_finished;
    bool waiting_video;
    atomic_uint foreground_generation;
    atomic_bool player_input_focus; /* Separate from app lifecycle/pause edges. */
    unsigned foreground_applied;    /* Runtime worker only. */
    uint64_t session_id;
    sl_runtime_facts facts;
    pthread_mutex_t lock;
    pthread_cond_t wake;
    bool started, quit, request_pending, save_pending, snapshot_pending;
    sl_language save_language;
    bool save_update_check;
    sl_command pending, active;
    sl_auth_store store, save;
    sl_stream_settings settings;
    sl_stream_preferences settings_view;
    uint64_t settings_view_revision;
    bool settings_view_ready;
    sl_runtime_event events[48];
    int count;
    IHS_Client *client;
    /* Discovery metadata is transient; keep it out of the profile ABI. */
    IHS_HostInfo discovered_hosts[SL_HOST_LIMIT];
    unsigned discovered_count, discovered_next;
    IHS_Session *session;
    IHS_Session *test_session; /* Dedicated protocol owner; never a video player. */
    bool test_active, test_joined;
    uint64_t test_sample_at;
    sl_network_test_view test_view;
    IHS_HIDProvider *provider;
    IHS_ClientConfig config;
    IHS_SessionInfo session_info;
    bool player_hardware_decoding; /* Player cache, distinct from silent EIO config changes. */
    sl_launch_watch launch;
    uint64_t launch_probe_at;
    sl_end_game_watch end_game;
    bool session_ready, connected, finished, host_stopped, first_reported, auth_ready,
        auth_consumed, auth_persist_attempted, request_terminal;
    uint64_t auth_account, request_at, last_diag;
    uint32_t connect_wait_tick;
    uint8_t auth_secret[32];
    sl_debug_snapshot debug;
    stream_media_snapshot previous;
    int udp;
};

#if NSL_DIAGNOSTICS
/* The log producer never waits for disk or the network. */
static pthread_mutex_t log_lock;
static atomic_bool log_ready;
static char log_tail_text[3501], log_previous_text[3501];
static size_t log_tail_size;
static char log_queue[128][224];
static unsigned log_head, log_tail;
static pthread_t log_worker;
static atomic_bool log_stop;
static bool log_started;
void sl_log(const char *s) {
    if (!atomic_load(&log_ready) || pthread_mutex_trylock(&log_lock))
        return;
    if (log_head - log_tail < 128) {
        snprintf(log_queue[log_head++ % 128], 224, "%.220s", s);
    }
    pthread_mutex_unlock(&log_lock);
}
static void *log_main(void *unused) {
    (void)unused;
    char path[512];
    snprintf(path, sizeof(path), "%s/stream_diag.log", sl_system_data_dir());
    char previous[512], older[512];
    snprintf(previous, sizeof(previous), "%s/stream_diag_prev.log", sl_system_data_dir());
    snprintf(older, sizeof(older), "%s/stream_diag_older.log", sl_system_data_dir());
    remove(older);
    rename(previous, older);
    rename(path, previous);
    FILE *old = fopen(previous, "r");
    if (old) {
        fseek(old, 0, SEEK_END);
        long length = ftell(old);
        if (length > 3500)
            fseek(old, length - 3500, SEEK_SET);
        else
            rewind(old);
        char text[3501];
        size_t n = fread(text, 1, 3500, old);
        text[n] = 0;
        fclose(old);
        pthread_mutex_lock(&log_lock);
        memcpy(log_previous_text, text, n + 1);
        pthread_mutex_unlock(&log_lock);
    }
    FILE *f = fopen(path, "w");
    size_t bytes = 0;
    for (;;) {
        char message[224] = {0};
        pthread_mutex_lock(&log_lock);
        if (log_tail < log_head)
            memcpy(message, log_queue[log_tail++ % 128], 224);
        bool empty = log_tail == log_head;
        if (message[0]) {
            size_t len = strlen(message);
            if (log_tail_size + len + 1 > 3500) {
                size_t drop = log_tail_size + len + 1 - 3500;
                memmove(log_tail_text, log_tail_text + drop, log_tail_size - drop);
                log_tail_size -= drop;
            }
            memcpy(log_tail_text + log_tail_size, message, len);
            log_tail_size += len;
            log_tail_text[log_tail_size++] = '\n';
            log_tail_text[log_tail_size] = 0;
        }
        pthread_mutex_unlock(&log_lock);
        if (message[0])
            sl_system_log(message);
        if (message[0] && f && bytes < 4 * 1024 * 1024) {
            int n = fprintf(f, "%llu %s\n", (unsigned long long)sl_system_now(), message);
            if (n > 0)
                bytes += (size_t)n;
            fflush(f);
        }
        if (atomic_load(&log_stop) && empty)
            break;
        if (!message[0])
            usleep(20000);
    }
    if (f)
        fclose(f);
    return NULL;
}
bool sl_log_start(void) {
    if (atomic_load(&log_ready))
        return true;
    pthread_mutex_init(&log_lock, NULL);
    log_head = log_tail = 0;
    log_tail_size = 0;
    log_tail_text[0] = log_previous_text[0] = 0;
    atomic_store(&log_stop, false);
    atomic_store(&log_ready, true);
    log_started = pthread_create(&log_worker, NULL, log_main, NULL) == 0;
    if (!log_started) {
        atomic_store(&log_ready, false);
        pthread_mutex_destroy(&log_lock);
    }
    return log_started;
}
void sl_log_finish(void) {
    if (!log_started)
        return;
    atomic_store(&log_stop, true);
    pthread_join(log_worker, NULL);
    log_started = false;
    atomic_store(&log_ready, false);
    pthread_mutex_destroy(&log_lock);
}
static void ihs_log(IHS_LogLevel level, const char *tag, const char *message) {
    if (level > IHS_LogLevelWarn && strcmp(tag, "Activity") && strcmp(tag, "StreamState"))
        return;
    char s[224];
    snprintf(s, sizeof(s), "%.24s: %.190s", tag, message);
    sl_log(s);
}
#else
void sl_log(const char *s) {
    (void)s;
}
bool sl_log_start(void) {
    return true;
}
void sl_log_finish(void) {
}
#define ihs_log NULL
#endif
static void post(sl_runtime *r, sl_runtime_event e) {
    pthread_mutex_lock(&r->lock);
    if (e.type != SL_EVENT_HOST && e.type != SL_EVENT_NETWORK)
        e.generation = r->active.generation;
    /* Discovery is coalesced and capped below the reserved terminal capacity. */
    if (e.type == SL_EVENT_HOST) {
        for (int i = 0; i < r->count; ++i)
            if (r->events[i].type == SL_EVENT_HOST &&
                r->events[i].host.client_id == e.host.client_id &&
                r->events[i].host.instance_id == e.host.instance_id) {
                r->events[i] = e;
                pthread_mutex_unlock(&r->lock);
                return;
            }
        if (r->count >= 32) {
            pthread_mutex_unlock(&r->lock);
            return;
        }
    }
    if (r->count < 48)
        r->events[r->count++] = e;
    else {
        r->events[47] =
            (sl_runtime_event){.type = SL_EVENT_FAILURE, .generation = r->active.generation};
        snprintf(r->events[47].text, 192, "%s", sl_tr(SL_T_ERROR_QUEUE));
    }
    pthread_mutex_unlock(&r->lock);
}
static void fail(sl_runtime *r, const char *s) {
    pthread_mutex_lock(&r->lock);
    if (r->active.type == SL_CMD_STREAM)
        r->facts.failed = true;
    pthread_mutex_unlock(&r->lock);
    sl_log(s);
    sl_runtime_event e = {.type = SL_EVENT_FAILURE};
    snprintf(e.text, sizeof(e.text), "%s", s);
    post(r, e);
}
static sl_host host_from(const IHS_HostInfo *info) {
    sl_host h = {.client_id = info->clientId,
                 .instance_id = info->instanceId,
                 .games_running = info->gamesRunning};
    snprintf(h.name, sizeof(h.name), "%s", info->hostname);
    char *ip = IHS_IPAddressToString(&info->address.ip);
    snprintf(h.address, sizeof(h.address), "%s", ip ? ip : "");
    free(ip);
    const char *os = info->ostype >= 0      ? "Windows"
                     : info->ostype <= -200 ? "Linux"
                     : info->ostype <= -70  ? "macOS"
                                            : "";
    snprintf(h.system, sizeof(h.system), "%s", os);
    return h;
}
static void discovered(IHS_Client *client, const IHS_HostInfo *h, void *ctx) {
    (void)client;
    sl_runtime *r = ctx;
    pthread_mutex_lock(&r->lock);
    unsigned index;
    for (index = 0; index < r->discovered_count; ++index)
        if (r->discovered_hosts[index].clientId == h->clientId &&
            r->discovered_hosts[index].instanceId == h->instanceId)
            break;
    if (index == r->discovered_count) {
        if (r->discovered_count < SL_HOST_LIMIT)
            ++r->discovered_count;
        else {
            index = r->discovered_next;
            r->discovered_next = (index + 1) % SL_HOST_LIMIT;
        }
    }
    r->discovered_hosts[index] = *h;
    if (r->active.type == SL_CMD_STREAM && h->clientId == r->active.host.client_id &&
        h->instanceId == r->active.host.instance_id && h->address.port == 27036) {
        char *ip = IHS_IPAddressToString(&h->address.ip);
        if (ip && !strcmp(ip, r->active.host.address)) {
            sl_launch_status(&r->launch, h->hasGamesRunning, h->gamesRunning, h->hasTimestamp,
                             h->timestamp);
            sl_end_game_status(&r->end_game, h->hasGamesRunning, h->gamesRunning, h->hasTimestamp,
                               h->timestamp);
        }
        free(ip);
    }
    pthread_mutex_unlock(&r->lock);
    sl_host observed = host_from(h);
    char line[192];
    snprintf(line, sizeof(line), "discovery: response %.63s %.63s", observed.name,
             observed.address);
    sl_log(line);
    post(r, (sl_runtime_event){.type = SL_EVENT_HOST, .host = observed});
}
/* Deferred authorization dispatch runs on this runtime worker, which owns
 * store. Attempt persistence before the library emits Confirmed; source ignores
 * filesystem failure for protocol progression (protocol RE §129). */
static void persist_authorization(IHS_Client *client, const IHS_HostInfo *host, uint64_t account,
                                  const uint8_t secret[32], void *ctx) {
    (void)client;
    (void)host;
    sl_runtime *r = ctx;
    if (r->active.type != SL_CMD_PAIR && r->active.type != SL_CMD_STREAM)
        return;
    if (r->active.type == SL_CMD_PAIR)
        post(r, (sl_runtime_event){.type = SL_EVENT_SAVING});
    sl_host *h = sl_host_find(&r->store.registry, r->active.host.id);
    if (!h && r->store.registry.count < SL_HOST_LIMIT) {
        h = &r->store.registry.hosts[r->store.registry.count++];
        *h = r->active.host;
    }
    if (h) {
        h->paired = true;
        h->account = account;
        h->has_secret = memcmp(secret, r->store.secret, 32) != 0;
        if (h->has_secret)
            memcpy(h->secret, secret, 32);
        else
            memset(h->secret, 0, sizeof(h->secret));
        if (!sl_auth_save(&r->store, sl_system_data_dir()))
            sl_log("pair: profile save failed; authorization continues");
        r->auth_persist_attempted = true;
        pthread_mutex_lock(&r->lock);
        r->active.host = *h;
        pthread_mutex_unlock(&r->lock);
    }
}

static void stream_authorization(IHS_Client *client, const IHS_HostInfo *host, const char *pin,
                                 uint64_t account, void *ctx) {
    (void)client;
    (void)host;
    sl_runtime *r = ctx;
    if (r->active.type != SL_CMD_STREAM)
        return;
    if (pin) {
        sl_runtime_event e = {.type = SL_EVENT_STREAM_AUTHORIZATION};
        snprintf(e.text, sizeof(e.text), "%.4s", pin);
        post(r, e);
    } else {
        /* A compatibility no-key Success carries the account without a new
         * secret. Keep the original STREAM command/generation/test intent. */
        pthread_mutex_lock(&r->lock);
        r->active.host.paired = true;
        if (account)
            r->active.host.account = account;
        pthread_mutex_unlock(&r->lock);
        sl_host *known = sl_host_find(&r->store.registry, r->active.host.id);
        if (known) {
            known->paired = true;
            if (account)
                known->account = account;
        }
        post(r, (sl_runtime_event){.type = SL_EVENT_STREAM_RESUMED,
                                   .account = r->test_active,
                                   .host = r->active.host});
    }
}

static void authorized(IHS_Client *client, const IHS_HostInfo *h, uint64_t account, void *ctx) {
    (void)h;
    sl_runtime *r = ctx;
    pthread_mutex_lock(&r->lock);
    if (r->active.type == SL_CMD_PAIR && !r->auth_consumed) {
        r->auth_account = account;
        /* After a key exchange the client already switched to the key
         * negotiated with this computer; a legacy pairing keeps ours. */
        IHS_ClientGetSecretKey(client, r->auth_secret);
        r->auth_ready = true;
        r->auth_consumed = true;
        sl_log("pair: authorization success callback");
    }
    pthread_mutex_unlock(&r->lock);
}
static void auth_failed(IHS_Client *c, const IHS_HostInfo *h, IHS_AuthorizationResult result,
                        void *ctx) {
    (void)c;
    (void)h;
    sl_runtime *r = ctx;
    pthread_mutex_lock(&r->lock);
    r->request_terminal = true;
    pthread_mutex_unlock(&r->lock);
    fail(r, result == IHS_AuthorizationDenied        ? sl_tr(SL_T_PAIR_DENIED)
            : result == IHS_AuthorizationTimedOut    ? sl_tr(SL_T_PAIR_TIMEOUT)
            : result == IHS_AuthorizationNotLoggedIn ? sl_tr(SL_T_LOGIN_STEAM)
                                                     : sl_tr(SL_T_PAIR_FAILED));
}
static void accepted(IHS_Client *c, const IHS_HostInfo *h, const IHS_SocketAddress *address,
                     const uint8_t *key, size_t len, void *ctx) {
    (void)c;
    (void)h;
    sl_runtime *r = ctx;
    if (len > 32) {
        fail(r, sl_tr(SL_T_INVALID_RESPONSE));
        return;
    }
    pthread_mutex_lock(&r->lock);
    r->session_info = (IHS_SessionInfo){
        .address = *address, .sessionKeyLen = len, .steamId = r->active.host.account};
    memcpy(r->session_info.sessionKey, key, len);
    r->session_ready = true;
    pthread_mutex_unlock(&r->lock);
}
static void rejected(IHS_Client *c, const IHS_HostInfo *h, IHS_StreamingResult result, void *ctx) {
    (void)c;
    (void)h;
    sl_runtime *r = ctx;
    pthread_mutex_lock(&r->lock);
    r->request_terminal = true;
    pthread_mutex_unlock(&r->lock);
    if (result == IHS_StreamingPINRequired)
        post(r, (sl_runtime_event){.type = SL_EVENT_PIN});
    else
        fail(r, result == IHS_StreamingScreenLocked       ? sl_tr(SL_T_UNLOCK_PC)
                : result == IHS_StreamingBusy             ? sl_tr(SL_T_PC_BUSY)
                : result == IHS_StreamingGameLaunchFailed ? sl_tr(SL_T_GAME_FAILED)
                : result == IHS_StreamingDisabled         ? sl_tr(SL_T_ENABLE_REMOTE_PLAY)
                                                          : sl_tr(SL_T_CANNOT_CONNECT));
}
static void configuring(IHS_Session *s, IHS_SessionConfig *c, void *ctx) {
    (void)s;
    (void)ctx;
    /* The full saved config supplies preferences. Only apply actual platform
     * limits here; copying legacy command defaults would erase saved fields. */
    c->enableHevc = false;
    if (!c->maxWidth || c->maxWidth > 1280)
        c->maxWidth = 1280;
    if (!c->maxHeight || c->maxHeight > 720)
        c->maxHeight = 720;
    if (!c->maxFps || c->maxFps > 60)
        c->maxFps = 60;
}
static void connected(IHS_Session *s, void *ctx) {
    (void)s;
    sl_runtime *r = ctx;
    pthread_mutex_lock(&r->lock);
    r->connected = true;
    r->facts.connected = true;
    pthread_mutex_unlock(&r->lock);
}
static void disconnected(IHS_Session *s, void *ctx) {
    sl_runtime *r = ctx;
    pthread_mutex_lock(&r->lock);
    r->finished = true;
    r->host_stopped = IHS_SessionHostRequestedStop(s);
    sl_log(r->host_stopped ? "session end: explicit host stop"
                           : "session end: transport/local disconnect");
    pthread_mutex_unlock(&r->lock);
}
static int video_prepare(IHS_Session *s, const IHS_StreamVideoConfig *config, void *ctx) {
    (void)ctx;
    return sl_media_video_prepare(s, config);
}
static int video_start(IHS_Session *s, const IHS_VideoEpochInfo *epoch,
                       const IHS_StreamVideoConfig *c, void *ctx) {
    sl_runtime *r = ctx;
    int result = sl_media_video_start_tracked(s, epoch, c);
    pthread_mutex_lock(&r->lock);
    if (result >= 0 && r->facts.session_id == epoch->session_id) {
        r->facts.epoch = epoch->video_epoch;
        ++r->facts.video_transition;
        r->facts.paused = false;
        r->facts.presented = false;
    }
    pthread_mutex_unlock(&r->lock);
    return result;
}
static IHS_StreamVideoSubmitResult video_submit(IHS_Session *s, const IHS_VideoEpochInfo *epoch,
                                                uint16_t id, IHS_FrameTicket *ticket, IHS_Buffer *b,
                                                IHS_StreamVideoFrameFlag flags, bool *taken,
                                                void *ctx) {
    (void)ctx;
    return sl_media_video_submit_tracked(s, epoch, id, ticket, b, flags, taken);
}
static void video_stop(IHS_Session *s, const IHS_VideoEpochInfo *epoch, void *ctx) {
    sl_runtime *r = ctx;
    sl_media_video_stop_tracked(s, epoch);
    pthread_mutex_lock(&r->lock);
    if (r->facts.session_id == epoch->session_id && r->facts.epoch == epoch->video_epoch) {
        ++r->facts.video_transition;
        r->facts.paused = true;
    }
    pthread_mutex_unlock(&r->lock);
}
static void video_flush(IHS_Session *s, const IHS_VideoEpochInfo *epoch,
                        IHS_StreamVideoFlushPhase phase, void *ctx) {
    (void)ctx;
    sl_media_video_flush_tracked(s, epoch, phase);
}
static void video_interrupt(IHS_Session *s, const IHS_VideoEpochInfo *epoch, bool restarting,
                            void *ctx) {
    (void)ctx;
    sl_media_video_interrupt_tracked(s, epoch, restarting);
}
static void video_think(IHS_Session *s, const IHS_VideoEpochInfo *epoch, void *ctx) {
    (void)ctx;
    sl_media_video_think_tracked(s, epoch);
}
static void activity(IHS_Session *s, int kind, uint64_t id, const char *name, void *ctx) {
    (void)s;
    sl_runtime *r = ctx;
    stream_media_snapshot media;
    stream_media_get_snapshot(&media);
    pthread_mutex_lock(&r->lock);
    sl_launch_activity(&r->launch, kind, id, media.displayed_frames);
    r->launch_probe_at = 0;
    pthread_mutex_unlock(&r->lock);
    /* Only Game activities belong in recent history. */
    if (kind != 2 || !id || !name || !name[0])
        return;
    sl_runtime_event e = {.type = SL_EVENT_ACTIVITY, .account = r->active.host.account};
    e.game.id = id;
    e.host.id = r->active.host.id;
    snprintf(e.game.name, sizeof(e.game.name), "%s", name);
    post(r, e);
}
static const IHS_ClientDiscoveryCallbacks discovery_cb = {.discovered = discovered};
static const IHS_ClientAuthorizationCallbacks auth_cb = {
    .persist = persist_authorization, .success = authorized, .failed = auth_failed};
static const IHS_ClientStreamingCallbacks stream_cb = {.success = accepted,
                                                       .failed = rejected,
                                                       .authorization = stream_authorization,
                                                       .authorizationFailed = auth_failed};
static void client_config_saved(IHS_Session *session, const uint8_t *wire, size_t size, void *ctx) {
    sl_runtime *r = ctx;
    sl_stream_settings_receive(session, wire, size, &r->settings);
    pthread_cond_signal(&r->wake);
}
static void client_config_begin(IHS_Session *session, sl_runtime *r) {
    r->player_hardware_decoding = IHS_SessionVideoHardwareDecodingEnabled(session);
}
static void client_config_changed(IHS_Session *session, const uint8_t *wire, size_t size,
                                  bool local_only, void *ctx) {
    (void)wire;
    (void)size;
    (void)local_only;
    sl_runtime *r = ctx;
    bool present;
    bool hardware = IHS_SessionVideoHardwareDecodingPreference(session, &present);
    if (present && hardware != r->player_hardware_decoding) {
        /* Official player 32a250: presence -> compare cache -> request -> cache.
         * Registered after pre-worker config setup; live callbacks run on RX.
         * EIO bypasses this delegate, so neither EIO nor epoch start updates it. */
        IHS_SessionVideoRequestReset(session);
        r->player_hardware_decoding = hardware;
    }
}
static bool same_preferences(sl_stream_preferences a, sl_stream_preferences b) {
    return a.quality == b.quality && a.bitrate_kbps == b.bitrate_kbps &&
           a.unreliable_fec == b.unreliable_fec;
}
static void sync_stream_settings(sl_runtime *r, bool refresh) {
    bool changed = sl_stream_settings_drain(&r->settings);
    if (!changed && !refresh)
        return;
    sl_stream_preferences before = {r->store.quality, r->store.bitrate_kbps,
                                    r->store.unreliable_fec};
    sl_stream_settings_project(&r->settings, &r->store);
    sl_stream_preferences after = {r->store.quality, r->store.bitrate_kbps,
                                   r->store.unreliable_fec};
    if (r->settings.dirty && !sl_stream_settings_save(&r->settings, sl_system_data_dir()))
        sl_log("settings: full configuration save failed");
    if (!same_preferences(before, after) && !sl_auth_save(&r->store, sl_system_data_dir()))
        sl_log("settings: profile projection save failed");
    pthread_mutex_lock(&r->lock);
    r->settings_view = after;
    r->settings_view_revision = r->settings.applied_revision;
    r->settings_view_ready = true;
    pthread_mutex_unlock(&r->lock);
}
static const IHS_StreamSessionCallbacks session_cb = {.configuring = configuring,
                                                      .connected = connected,
                                                      .disconnected = disconnected,
                                                      .saveClientConfig = client_config_saved,
                                                      .clientConfigChanged = client_config_changed};
static const IHS_StreamVideoCallbacks video_cb = {.startTracked = video_start,
                                                  .submitTracked = video_submit,
                                                  .stopTracked = video_stop,
                                                  .prepare = video_prepare,
                                                  .flushTracked = video_flush,
                                                  .reportsDecoderInfo = true,
                                                  .interruptTracked = video_interrupt,
                                                  .thinkTracked = video_think};
static const IHS_StreamInputCallbacks input_cb = {.activityState = activity};
static void publish_test(sl_runtime *r, sl_network_test_view view) {
    pthread_mutex_lock(&r->lock);
    view.generation = r->active.generation;
    view.revision = r->test_view.revision + 1;
    view.test_only = r->active.test_only;
    r->test_view = view;
    pthread_mutex_unlock(&r->lock);
}
static void stop_network_test(sl_runtime *r) {
    if (r->test_session) {
        IHS_SessionDisconnect(r->test_session);
        if (!r->test_joined)
            IHS_SessionThreadedJoin(r->test_session);
        IHS_SessionDestroy(r->test_session);
        r->test_session = NULL;
        sl_log("network test: workers joined, session destroyed");
    }
    r->test_active = r->test_joined = false;
    r->test_sample_at = 0;
    publish_test(r, (sl_network_test_view){.phase = SL_TEST_IDLE});
}
static void stop_client(sl_runtime *r) {
    if (!r->client)
        return;
    IHS_ClientStopDiscovery(r->client);
    IHS_ClientAuthorizationCancel(r->client);
    IHS_ClientStreamingCancel(r->client);
    IHS_ClientStop(r->client);
    IHS_ClientThreadedJoin(r->client);
    IHS_ClientDestroy(r->client);
    r->client = NULL;
}
static bool start_client(sl_runtime *r) {
    sl_log("discovery: creating IHS client");
    r->client = IHS_ClientCreate(&r->config);
    if (!r->client)
        return false;
    IHS_ClientSetAuthorizationDeferred(r->client, true);
    IHS_ClientSetLogFunction(r->client, ihs_log);
    IHS_ClientSetDiscoveryCallbacks(r->client, &discovery_cb, r);
    IHS_ClientSetAuthorizationCallbacks(r->client, &auth_cb, r);
    IHS_ClientSetStreamingCallbacks(r->client, &stream_cb, r);
    sl_log("discovery: client created; registering periodic broadcast");
    bool started = IHS_ClientStartDiscovery(r->client, 3000);
    sl_log(started ? "discovery: periodic broadcast registered" : "discovery: registration failed");
    return started;
}
/* Return completion observed before/during join, before destroying its owner. */
static bool stop_session(sl_runtime *r) {
    bool host_completed = false;
    stop_network_test(r);
    sl_media_close_video();
    r->waiting_video = true;
    sl_log("cleanup: stop/join HID worker");
    stream_media_set_hid_session(NULL, false);
    if (r->session) {
        sl_log("cleanup: session disconnect/join");
        IHS_SessionDisconnect(r->session);
        /* Disconnect attempts one goodbye before stopping workers. Join before
         * releasing session, sockets and decoder dependencies. */
        IHS_SessionThreadedJoin(r->session);
        host_completed = IHS_SessionHostRequestedStop(r->session);
        /* Workers are joined. Detached frame tickets can outlive the session. */
        stream_media_audio_stop(r->session);
        IHS_SessionDestroy(r->session);
        r->session = NULL;
        sl_log("cleanup: session destroyed");
        /* SDL_main quits the client before the focused player's teardown.
         * This port has no Android hard/background process modes. */
        sl_media_end_stream_player(atomic_load(&r->player_input_focus), false, false);
    }
    pthread_mutex_lock(&r->lock);
    host_completed = host_completed || (r->end_game.at && r->end_game.empty >= 2);
    r->end_game = (sl_end_game_watch){0};
    r->connected = r->finished = r->host_stopped = r->session_ready = false;
    r->facts.connected = false;
    r->facts.test_failure_pending = false;
    r->facts.requests_closed = true;
    r->facts.protocol_closed = true;
    pthread_mutex_unlock(&r->lock);
    r->first_reported = false;
    r->request_at = 0;
    return host_completed;
}
static bool launch_session(sl_runtime *r, IHS_SessionInfo info) {
    r->session = IHS_SessionCreate(&r->config, &info);
    static atomic_uint_fast64_t next_session_id = 1;
    uint64_t next = atomic_load(&next_session_id);
    while (next != UINT64_MAX && !atomic_compare_exchange_weak(&next_session_id, &next, next + 1)) {
    }
    r->session_id = next == UINT64_MAX ? 0 : next;
    if (r->session && (!r->session_id || r->session_id == UINT64_MAX ||
                       !IHS_SessionSetVideoTrackingIdentity(r->session, r->session_id))) {
        IHS_SessionDestroy(r->session);
        r->session = NULL;
    }
    if (!r->session)
        return false;
    const sl_stream_request_limits limits = {
        .width = 1280, .height = 720, .fps = 60, .hevc = false};
    if (!sl_stream_settings_apply_limited(&r->settings, r->session, &limits)) {
        IHS_SessionDestroy(r->session);
        r->session = NULL;
        return false;
    }
    r->foreground_applied = atomic_load(&r->foreground_generation);
    IHS_SessionSetForeground(r->session, !(r->foreground_applied & 1u));
    sl_system_stream_info platform = sl_system_streaming_info();
    IHS_StreamClientCapabilities caps = {
        .systemInfo = platform.system_info[0] ? platform.system_info : NULL,
        .decoderInfo = platform.decoder_info,
        /* Actual SDK thread metadata is reported by get_format, not guessed here. */
        .hasVideoDecoderCapabilities = true,
        .supportsVideoHevc = false, /* The runtime's validated pipeline is H264. */
        .maximumDecodeBitrateKbps = platform.maximum_decode_bitrate_kbps,
        .maximumBurstBitrateKbps = platform.maximum_burst_bitrate_kbps,
        .hasSystemCanSuspend = true,
        .systemCanSuspend = platform.can_suspend,
        .formFactor = platform.form_factor == SL_STREAM_FORM_COMPUTER
                          ? IHS_StreamDeviceFormFactorComputer
                          : IHS_StreamDeviceFormFactorUnknown,
    };
    if (!IHS_SessionSetClientCapabilities(r->session, &caps)) {
        IHS_SessionDestroy(r->session);
        r->session = NULL;
        return false;
    }
    pthread_mutex_lock(&r->lock);
    r->facts.session_id = r->session_id;
    pthread_mutex_unlock(&r->lock);
    IHS_SessionSetLogFunction(r->session, ihs_log);
    /* Original active player Init copies the effective field value (§97).
     * Initialize once per player/session, not again when a decoder epoch opens. */
    client_config_begin(r->session, r);
    IHS_SessionSetSessionCallbacks(r->session, &session_cb, r);
    IHS_SessionSetVideoCallbacks(r->session, &video_cb, r);
    IHS_SessionSetAudioCallbacks(r->session, sl_media_audio_callbacks(), r);
    IHS_SessionSetInputCallbacks(r->session, &input_cb, r);
    if (r->provider)
        IHS_SessionHIDAddProvider(r->session, r->provider);
    if (!IHS_SessionConnect(r->session))
        return false;
    r->connect_wait_tick = sl_connection_wait_tick(sl_system_now());
    IHS_ClientStreamingEstablished(r->client);
    return true;
}
static bool host_info(sl_runtime *r, const sl_host *h, IHS_HostInfo *out) {
    memset(out, 0, sizeof(*out));
    out->clientId = h->client_id;
    out->instanceId = h->instance_id;
    out->address.port = 27036;
    /* Legacy profiles do not contain universe. Public is this application's
     * retail-Steam default; observed metadata must override it, even if invalid. */
    out->universe = IHS_SteamUniversePublic;
    pthread_mutex_lock(&r->lock);
    for (unsigned n = 0; n < r->discovered_count; ++n)
        if (r->discovered_hosts[n].clientId == h->client_id &&
            r->discovered_hosts[n].instanceId == h->instance_id) {
            out->universe = r->discovered_hosts[n].universe;
            out->ostype = r->discovered_hosts[n].ostype;
            break;
        }
    pthread_mutex_unlock(&r->lock);
    snprintf(out->hostname, sizeof(out->hostname), "%s", h->name);
    return IHS_IPAddressFromString(&out->address.ip, h->address);
}
static bool request_stream(sl_runtime *r, bool network_test) {
    IHS_HostInfo host;
    if (!r->client || !host_info(r, &r->active.host, &host))
        return false;
    IHS_ClientStopDiscovery(r->client);
    const sl_host *paired = sl_host_find(&r->store.registry, r->active.host.id);
    IHS_ClientSetSecretKey(r->client,
                           paired && paired->has_secret ? paired->secret : r->store.secret);
    const CStreamingClientConfig *config = r->settings.config;
    IHS_StreamingRequest req = {
        .networkTest = network_test,
        .streamingEnable = {config->enable_video_streaming, config->enable_audio_streaming,
                            config->enable_input_streaming},
        .maxResolution = {1280, 720},
        .audioChannelCount = 2,
        .streamingInterface = IHS_StreamInterfaceBigPicture,
        .gamepadCount = 1,
        /* Recent-game launch is this application's extension. A dedicated
         * test ticket must not launch the selected game before the real stream. */
        .gameId = network_test ? 0 : r->active.game_id,
    };
    snprintf(req.pin, sizeof(req.pin), "%.15s", r->active.text);
    r->request_at = sl_system_now();
    r->first_reported = false;
    if (!network_test) {
        pthread_mutex_lock(&r->lock);
        r->launch = (sl_launch_watch){.target = r->active.game_id};
        if (!r->request_pending && !atomic_load(&r->exit_requested))
            sl_media_allow_video();
        pthread_mutex_unlock(&r->lock);
    }
    return IHS_ClientStreamingRequest(r->client, &host, &req);
}
static bool launch_network_test(sl_runtime *r, IHS_SessionInfo info) {
    IHS_NetworkTestMode mode;
    uint32_t target;
    if (!sl_stream_settings_network_test_plan(&r->settings, &mode, &target))
        return false;
    r->test_session = IHS_SessionCreate(&r->config, &info);
    if (!r->test_session || !IHS_SessionConfigureNetworkTest(r->test_session, mode, target))
        return false;
    IHS_SessionSetLogFunction(r->test_session, ihs_log);
    if (!IHS_SessionConnect(r->test_session))
        return false;
    IHS_ClientStreamingEstablished(r->client);
    r->request_at = 0;
    publish_test(r, (sl_network_test_view){.phase = SL_TEST_RUNNING,
                                           .target_kbps = target,
                                           .bandwidth_test = mode == IHS_NetworkTestBandwidth});
    return true;
}
static void fail_network_test(sl_runtime *r) {
    /* Original failed test is already closed, but manager state6/ID remains
     * until finished(int)->OnActionCancel. Do not turn this into an automatic
     * Stop, a retry, a successful result, or a new ordinary request (RE §124). */
    stop_network_test(r);
    pthread_mutex_lock(&r->lock);
    r->facts.failed = r->facts.test_failure_pending = true;
    unsigned port = r->session_info.address.port;
    pthread_mutex_unlock(&r->lock);
    sl_network_test_view view = {.phase = SL_TEST_FAILED};
    snprintf(view.error, sizeof(view.error), sl_tr(SL_T_TEST_FAILED_DETAIL), r->active.host.name,
             port);
    sl_log(view.error);
    publish_test(r, view);
}
static void sample_network_test(sl_runtime *r, uint64_t now) {
    if (!r->test_session || r->test_joined)
        return;
    IHS_NetworkTestResult result;
    IHS_SessionGetNetworkTestResult(r->test_session, &result);
    if (result.status == IHS_NetworkTestRunning || result.status == IHS_NetworkTestIdle) {
        if (r->test_sample_at && now - r->test_sample_at < 250)
            return;
        r->test_sample_at = now;
        publish_test(
            r, (sl_network_test_view){.phase = SL_TEST_RUNNING,
                                      .target_kbps = result.targetKbps,
                                      .progress = result.progressPercent,
                                      .bandwidth_test = result.mode == IHS_NetworkTestBandwidth});
        return;
    }
    IHS_SessionThreadedJoin(r->test_session);
    r->test_joined = true;
    IHS_SessionGetNetworkTestResult(r->test_session, &result);
    if (result.status != IHS_NetworkTestComplete || !result.valid) {
        fail_network_test(r);
        return;
    }
    /* Keep the joined Session/full samples until the result is acknowledged.
     * Neither the result nor progress depends on event queue capacity. */
    publish_test(r, (sl_network_test_view){
                        .phase = SL_TEST_RESULT,
                        .target_kbps = result.targetKbps,
                        .previous_target_kbps = result.previousTargetKbps,
                        .bandwidth_test = result.mode == IHS_NetworkTestBandwidth,
                        .progress = result.progressPercent,
                        .loss_percent = result.lossPercent,
                        .mean_ms = result.meanNetworkMs,
                        .deviation_ms = result.deviationMs,
                        .rating = result.result,
                        .recommendation =
                            sl_stream_settings_network_test_recommendation(&r->settings, &result)});
}
static void confirm_network_test(sl_runtime *r, const sl_command *cmd) {
    if (!r->test_active || !r->test_session || !r->test_joined ||
        cmd->generation != r->active.generation)
        return;
    IHS_NetworkTestResult result;
    IHS_SessionGetNetworkTestResult(r->test_session, &result);
    if (result.status != IHS_NetworkTestComplete)
        return;
    pthread_mutex_lock(&r->lock);
    unsigned recommendation = r->test_view.recommendation;
    pthread_mutex_unlock(&r->lock);
    if (cmd->accept_recommendation && recommendation) {
        /* Current validated display path has no 4K/HEVC capability. The stored
         * preset remains distinct from the final 720p60/H264 request limits. */
        sl_stream_preset preset = recommendation == 1 ? SL_PRESET_FAST : SL_PRESET_ENHANCED_1080;
        if (!sl_stream_settings_preset(&r->settings, preset)) {
            stop_network_test(r);
            fail(r, sl_tr(SL_T_SAVE_SETTINGS_FAILED));
            return;
        }
        sync_stream_settings(r, true);
    }
    if (!sl_network_stats_save_session(sl_system_data_dir(), r->test_session))
        sl_log("network test: statistics save failed; continuing original completion action");
    bool test_only = r->active.test_only;
    stop_network_test(r);
    /* File publication can overlap a local cancel/exit. Let the queued owner
     * command run before issuing a new ticket (and potentially launching a game). */
    pthread_mutex_lock(&r->lock);
    bool interrupted = atomic_load(&r->exit_requested) ||
                       (r->request_pending && r->pending.type != SL_CMD_TEST_CONFIRM &&
                        r->pending.type != SL_CMD_SAVE);
    pthread_mutex_unlock(&r->lock);
    if (interrupted)
        return;
    if (test_only) {
        stop_session(r);
        post(r, (sl_runtime_event){.type = SL_EVENT_STOPPED});
        IHS_ClientStartDiscovery(r->client, 3000);
    } else {
        publish_test(r, (sl_network_test_view){.phase = SL_TEST_CONTINUING});
        if (!request_stream(r, false))
            fail(r, sl_tr(SL_T_REQUEST_STREAM_FAILED));
    }
}
static void execute(sl_runtime *r, sl_command cmd) {
    char trace[120];
    snprintf(trace, sizeof(trace), "command: type=%d generation=%llu host=%llu", cmd.type,
             (unsigned long long)cmd.generation, (unsigned long long)cmd.host.id);
    sl_log(trace);
    if (cmd.type == SL_CMD_SAVE)
        return;
    if (cmd.type == SL_CMD_TEST_CONFIRM) {
        confirm_network_test(r, &cmd);
        return;
    }
    if (cmd.type == SL_CMD_SHORTCUT) {
        pthread_mutex_lock(&r->lock);
        r->active.generation = cmd.generation;
        pthread_mutex_unlock(&r->lock);
        char detail[64];
        sl_text_id result = sl_shortcut_install(detail, sizeof(detail));
        sl_runtime_event e = {.type = SL_EVENT_SHORTCUT};
        snprintf(e.text, sizeof(e.text), "%s%s%s", sl_tr(result), detail[0] ? "\n" : "", detail);
        post(r, e);
        return;
    }
    if (cmd.type == SL_CMD_END_GAME) {
        pthread_mutex_lock(&r->lock);
        r->active.generation = cmd.generation;
        bool already_sent = r->end_game.at != 0;
        if (!already_sent) {
            r->end_game.at = sl_system_now();
            r->end_game.have_stamp = r->launch.have_stamp;
            r->end_game.stamp = r->launch.stamp;
            r->end_game.empty = 0;
        }
        pthread_mutex_unlock(&r->lock);
        if (!already_sent &&
            (!r->session || !r->first_reported || !IHS_SessionStopGame(r->session))) {
            stop_session(r);
            fail(r, sl_tr(SL_T_END_GAME_FAILED));
        } else if (!already_sent) {
            sl_log("user end game: reliable StopRequest queued; awaiting host completion");
        }
        return;
    }
    /* Cancel/join each request before changing its callback generation. Keep the
     * client socket alive so canceled launch IDs can reject late host responses. */
    if (r->client) {
        IHS_ClientStreamingCancel(r->client);
        IHS_ClientAuthorizationCancel(r->client);
    }
    stop_session(r);
    if (!sl_media_video_clean()) {
        pthread_mutex_lock(&r->lock);
        if (!r->request_pending) {
            r->pending = cmd;
            r->request_pending = true;
        }
        pthread_mutex_unlock(&r->lock);
        return;
    }
    r->waiting_video = false;
    r->request_at = 0;
    pthread_mutex_lock(&r->lock);
    r->facts.video_clean = true;
    if (cmd.type == SL_CMD_STREAM)
        r->facts = (sl_runtime_facts){.request_id = cmd.generation};
    r->active = cmd;
    r->launch = (sl_launch_watch){.target = cmd.game_id};
    r->launch_probe_at = 0;
    r->auth_ready = r->session_ready = false;
    r->auth_consumed = r->auth_persist_attempted = false;
    r->request_terminal = false;
    pthread_mutex_unlock(&r->lock);
    if (cmd.type == SL_CMD_EXIT) {
        r->quit = true;
        return;
    }
    if (!r->client && !start_client(r)) {
        fail(r, sl_tr(SL_T_NETWORK_UNAVAILABLE));
        return;
    }
    IHS_ClientStartDiscovery(r->client, 3000);
    if (cmd.type == SL_CMD_CANCEL || cmd.type == SL_CMD_STOP) {
        post(r, (sl_runtime_event){.type = SL_EVENT_STOPPED});
        return;
    }
    if (cmd.type == SL_CMD_MANUAL) {
        IHS_SocketAddress address = {.port = 27036};
        if (!IHS_IPAddressFromString(&address.ip, cmd.text)) {
            fail(r, sl_tr(SL_T_INVALID_IP));
            return;
        }
        CMsgRemoteClientBroadcastDiscovery msg = CMSG_REMOTE_CLIENT_BROADCAST_DISCOVERY__INIT;
        msg.has_seq_num = true;
        msg.seq_num = 1;
        if (!IHS_ClientSend(r->client, address, k_ERemoteClientBroadcastMsgDiscovery,
                            (ProtobufCMessage *)&msg))
            fail(r, sl_tr(SL_T_LOOKUP_FAILED));
        else
            r->request_at = sl_system_now();
        return;
    }
    IHS_HostInfo h;
    if (!host_info(r, &cmd.host, &h)) {
        fail(r, sl_tr(SL_T_ADDRESS_UNAVAILABLE));
        return;
    }
    r->request_at = sl_system_now();
    r->first_reported = false;
    if (cmd.type == SL_CMD_PAIR) {
        uint32_t random;
        do {
            if (!sl_system_random(&random, sizeof(random))) {
                fail(r, sl_tr(SL_T_CODE_FAILED));
                return;
            }
        } while (random % 10000 == 0); /* Official GenerateAuthorizationPin excludes 0000. */
        sl_runtime_event e = {.type = SL_EVENT_CODE};
        snprintf(e.text, sizeof(e.text), "%04u", random % 10000);
        post(r, e);
        /* Device token and escrow ticket are built from the installation key. */
        IHS_ClientSetSecretKey(r->client, r->store.secret);
        if (!IHS_ClientAuthorizationRequest(r->client, &h, e.text))
            fail(r, sl_tr(SL_T_REQUEST_PAIR_FAILED));
    } else if (cmd.type == SL_CMD_STREAM) {
        bool readable = !cmd.test_only && sl_network_stats_load(sl_system_data_dir(), NULL);
        unsigned action = sl_network_stats_connect_action(
            cmd.test_only ? 2 : 0, r->settings.config->enable_video_streaming, readable);
        r->test_active = action != 0;
        if (r->test_active)
            publish_test(r, (sl_network_test_view){.phase = SL_TEST_REQUESTING});
        if (!request_stream(r, r->test_active))
            fail(r, sl_tr(SL_T_REQUEST_STREAM_FAILED));
    }
}
static void sample(sl_runtime *r, uint64_t now) {
    stream_media_snapshot s;
    stream_media_get_snapshot(&s);
    pthread_mutex_lock(&r->lock);
    sl_launch_frame(&r->launch, s.displayed_frames);
    pthread_mutex_unlock(&r->lock);
#if NSL_DIAGNOSTICS
    if (r->session) {
        IHS_SessionGetReliabilityStats(r->session, &s.reliability);
        IHS_HIDSDLLastSubmitted sent = {0};
        IHS_HIDSDLGetLastSubmittedReport(r->session, &sent);
        sl_media_submitted(&sent);
    }
    sl_debug_snapshot d = {.sampled_at = now, .frames = s.displayed_frames};
    snprintf(d.title, sizeof(d.title), sl_tr(SL_T_DEBUG_TITLE), s.width, s.height, s.decoder);
    for (int i = 0; i < 6; ++i)
        strcpy(d.values[i], "—");
    if (s.session_id != r->previous.session_id || s.video_epoch != r->previous.video_epoch) {
        memset(&r->previous, 0, sizeof(r->previous));
        r->last_diag = 0;
    }
    stream_media_snapshot *p = &r->previous;
    if (r->last_diag && now > r->last_diag && s.displayed_frames >= p->displayed_frames)
        snprintf(d.values[0], 64, sl_tr(SL_T_FPS),
                 (s.displayed_frames - p->displayed_frames) * 1000.0 / (now - r->last_diag));
    if (s.render.samples > p->render.samples)
        snprintf(d.values[1], 64, sl_tr(SL_T_MS),
                 (s.render.age_us - p->render.age_us) / 1000.0 /
                     (s.render.samples - p->render.samples));
    if (s.decode_samples > p->decode_samples && s.render.samples > p->render.samples)
        snprintf(d.values[2], 64, sl_tr(SL_T_DECODE_MS),
                 (s.decode_us_total - p->decode_us_total) / 1000.0 /
                     (s.decode_samples - p->decode_samples),
                 (s.render.prep_us - p->render.prep_us) / 1000.0 /
                     (s.render.samples - p->render.samples));
    if (s.audio_active && s.audio_frequency && s.audio_channels)
        snprintf(d.values[3], 64, sl_tr(SL_T_AUDIO_MS),
                 s.audio_queued_bytes * 1000.0 / (s.audio_frequency * s.audio_channels * 2));
    snprintf(d.values[4], 64, "%u / %u", s.reliability.hidPending, s.reliability.hidInFlight);
    snprintf(d.values[5], 64, sl_tr(SL_T_ACK_MS),
             (unsigned long long)s.reliability.reliableMaxAckLatencyMs);
    pthread_mutex_lock(&r->lock);
    r->debug = d;
    pthread_mutex_unlock(&r->lock);
#endif
    if (r->session && s.session_id == r->session_id && s.render_failed) {
        fail(r, s.last_error);
        stop_session(r);
    }
    pthread_mutex_lock(&r->lock);
    if (s.session_id == r->facts.session_id && s.video_epoch == r->facts.epoch)
        r->facts.presented = s.first_frame_displayed;
    pthread_mutex_unlock(&r->lock);
    if (r->session && s.session_id == r->session_id && s.first_frame_displayed &&
        !r->first_reported) {
        pthread_mutex_lock(&r->lock);
        r->facts.presented = true;
        pthread_mutex_unlock(&r->lock);
        post(r, (sl_runtime_event){.type = SL_EVENT_FIRST_FRAME});
        r->first_reported = true;
    }
#if NSL_DIAGNOSTICS
    char line[224];
    snprintf(line, sizeof(line),
             "stats frames=%u fps=%.20s local=%.20s decode/prep=%.32s audio=%.20s hid=%.20s "
             "ackMax=%.20s",
             s.displayed_frames, d.values[0], d.values[1], d.values[2], d.values[3], d.values[4],
             d.values[5]);
    sl_log(line);
    /* Five short, non-blocking log writes once per second, never from rendering.
     * Cumulative values tolerate missing samples; id joins one coherent snapshot. */
    if (s.video_active && s.video_epoch && s.first_frame_displayed) {
#define U(value) ((unsigned long long)(value))
        const sl_render_metrics *m = &s.render;
        snprintf(line, sizeof(line),
                 "vp1 id=%llu s=%llu e=%llu b=%s hw=%u w=%d h=%d dec=%u show=%u repl=%u drop=%u",
                 U(now), U(s.session_id), U(s.video_epoch), NSL_GFX_DEKO ? "deko" : "sdl",
                 m->hardware, s.width, s.height, s.decoded_frames, s.displayed_frames,
                 s.replaced_frames, s.dropped_frames);
        sl_log(line);
        snprintf(line, sizeof(line), "vp2 id=%llu n=%llu prep=%llu age=%llu wait=%llu decode=%llu",
                 U(now), U(m->samples), U(m->prep_us), U(m->age_us), U(m->wait_us),
                 U(s.decode_us_total));
        sl_log(line);
        snprintf(line, sizeof(line),
                 "vp3 id=%llu draws=%llu redraw=%llu begin=%llu ui=%llu present=%llu", U(now),
                 U(m->draws), U(m->redraws), U(m->begin_us), U(m->ui_us), U(m->present_us));
        sl_log(line);
        snprintf(line, sizeof(line),
                 "vp4 id=%llu uploads=%llu bytes=%llu downloads=%llu imports=%llu", U(now),
                 U(m->uploads), U(m->upload_bytes), U(m->downloads), U(m->resources.imports));
        sl_log(line);
        snprintf(line, sizeof(line), "vp5 id=%llu maps=%u pools=%u busy=%u image=%llu mapped=%llu",
                 U(now), m->resources.maps, m->resources.pool_groups, m->resources.busy_batches,
                 U(m->resources.image_bytes), U(m->resources.imported_bytes));
        sl_log(line);
#if NSL_GFX_DEKO
        snprintf(line, sizeof(line),
                 "vq1 id=%llu attempts=%llu nobatch=%llu acquire=%llu acquire_us=%llu", U(now),
                 U(m->resources.begin_attempts), U(m->resources.no_free_batch),
                 U(m->resources.acquires), U(m->resources.acquire_us));
        sl_log(line);
        snprintf(line, sizeof(line),
                 "vq2 id=%llu polls=%llu timeout=%llu done=%llu residence_us=%llu", U(now),
                 U(m->resources.fence_polls), U(m->resources.fence_timeouts),
                 U(m->resources.completed_batches), U(m->resources.batch_residence_us));
        sl_log(line);
#endif
        snprintf(line, sizeof(line),
                 "vq3 id=%llu n=%llu bad=%llu wait_ns=%llu work_ns=%llu wmax=%llu xmax=%llu",
                 U(now), U(m->resources.gpu_samples), U(m->resources.gpu_invalid),
                 U(m->resources.gpu_wait_ns), U(m->resources.gpu_work_ns),
                 U(m->resources.gpu_wait_max_ns), U(m->resources.gpu_work_max_ns));
        sl_log(line);
        snprintf(
            line, sizeof(line),
            "vq4 id=%llu short=%llu long=%llu gapmax=%llu empty=%llu one=%llu many=%llu tmax=%llu",
            U(now), U(s.pacing.publish_short), U(s.pacing.publish_long),
            U(s.pacing.publish_gap_max_us), U(s.pacing.take_empty), U(s.pacing.take_one),
            U(s.pacing.take_many), U(s.pacing.take_gap_max_us));
        sl_log(line);
        snprintf(line, sizeof(line), "vq5 id=%llu submit=%llu bytes=%llu long=%llu gapmax=%llu",
                 U(now), U(s.pacing.submits), U(s.pacing.submit_bytes), U(s.pacing.submit_long),
                 U(s.pacing.submit_gap_max_us));
        sl_log(line);
        snprintf(line, sizeof(line),
                 "vq6 id=%llu loops=%llu control=%llu media=%llu tail=%llu sleep=%llu collect=%llu",
                 U(now), U(s.loop.loops), U(s.loop.control_us), U(s.loop.media_us),
                 U(s.loop.tail_us), U(s.loop.sleep_us), U(s.loop.collect_us));
        sl_log(line);
        snprintf(line, sizeof(line), "vq7 id=%llu cpu=%llu wall=%llu rc=%u", U(now),
                 U(s.loop.cpu_ticks), U(s.loop.cpu_wall_ticks), s.loop.cpu_result);
        sl_log(line);
        snprintf(line, sizeof(line),
                 "vq8 id=%llu epoch=%llu a=%llu p=%llu ca=%llu cp=%llu defer=%llu tv=%u ts=%u "
                 "active=%u unknown=%llu",
                 U(now), U(s.video_epoch), U(m->available_frames), U(m->submitted_frames),
                 U(m->cohort_frames), U(m->cohort_presented), U(m->deferred), m->input_period_us,
                 m->output_period_us, m->adaptive_active, U(m->unobserved));
        sl_log(line);
        snprintf(line, sizeof(line),
                 "vq9 id=%llu ready_us=%llu wait_us=%llu start_us=%llu hold=%llu", U(now),
                 U(m->adaptive_ready_us), U(m->adaptive_wait_us), U(m->adaptive_start_us),
                 U(m->adaptive_holdovers));
        sl_log(line);
#undef U
    }
    r->previous = s;
#endif
    r->last_diag = now;
}
#if NSL_DIAGNOSTICS
static void udp_poll(sl_runtime *r) {
    if (r->udp < 0)
        return;
    char cmd[128], reply[4096];
    struct sockaddr_in peer;
    socklen_t len = sizeof(peer);
    ssize_t n = recvfrom(r->udp, cmd, sizeof(cmd) - 1, 0, (struct sockaddr *)&peer, &len);
    if (n <= 0)
        return;
    cmd[n] = 0;
    cmd[strcspn(cmd, "\r\n")] = 0;
    if (!strcmp(cmd, "state") || !strcmp(cmd, "stats") || !strcmp(cmd, "perf") ||
        !strcmp(cmd, "ping")) {
        snprintf(reply, sizeof(reply),
                 "OK session=%d displayed=%u debug=%s fps=%s hid=%s ackMax=%s", r->session != NULL,
                 r->debug.frames, r->debug.title, r->debug.values[0], r->debug.values[4],
                 r->debug.values[5]);
    } else if (!strcmp(cmd, "audio")) {
        stream_media_snapshot *s = &r->previous;
        snprintf(
            reply, sizeof(reply),
            "OK active=%d frequency=%d channels=%d frames=%u queuedBytes=%u drops=%u errors=%u",
            s->audio_active, s->audio_frequency, s->audio_channels, s->audio_frames,
            s->audio_queued_bytes, s->audio_queue_drops, s->audio_decode_errors);
    } else if (!strcmp(cmd, "hid")) {
        IHS_SessionReliabilityStats *s = &r->previous.reliability;
        snprintf(reply, sizeof(reply),
                 "OK submitted=%llu sent=%llu acked=%llu pending=%u inFlight=%u retries=%llu "
                 "ackMax=%llu",
                 (unsigned long long)s->hidSubmitted, (unsigned long long)s->hidSent,
                 (unsigned long long)s->hidAcknowledged, s->hidPending, s->hidInFlight,
                 (unsigned long long)s->reliableRetries,
                 (unsigned long long)s->reliableMaxAckLatencyMs);
    } else if (!strncmp(cmd, "diag", 4)) {
        if (atomic_load(&log_ready)) {
            pthread_mutex_lock(&log_lock);
            snprintf(reply, sizeof(reply), "OK %s",
                     strstr(cmd, "prev") ? log_previous_text : log_tail_text);
            pthread_mutex_unlock(&log_lock);
        } else
            strcpy(reply, "ERR diagnostic log unavailable");
    } else if (!strcmp(cmd, "hid-history") || !strncmp(cmd, "hidlog", 6)) {
        stream_media_format_hid_history(reply, sizeof(reply), 16);
    } else {
        snprintf(reply, sizeof(reply),
                 "ERR supported: ping state stats perf audio hid hidlog diag [current|prev]");
    }
    sendto(r->udp, reply, strlen(reply), MSG_DONTWAIT, (struct sockaddr *)&peer, len);
}
#endif
static void *worker_main(void *ctx) {
    sl_runtime *r = ctx;
    sl_log("runtime: worker entered; initializing IHS");
    char legacy_address[64] = {0};
    sl_auth_discovery_hint(&r->store, sl_system_data_dir(), legacy_address, sizeof(legacy_address));
    uint64_t last_probe = 0;
    uint32_t discovery_seq = 0;
    IHS_Init();
    sl_log("runtime: IHS initialized");
    if (sl_stream_settings_load(&r->settings, sl_system_data_dir()) < 0)
        sl_log("settings: load failed, retaining the previous complete value");
    sync_stream_settings(r, true);
    if (!start_client(r))
        fail(r, sl_tr(SL_T_NETWORK_UNAVAILABLE));
    while (!r->quit) {
        if (r->waiting_video) {
            if (!sl_media_video_clean()) {
                struct timespec pause = {0, 1000000};
                nanosleep(&pause, NULL);
                continue;
            }
            r->waiting_video = false;
            pthread_mutex_lock(&r->lock);
            r->facts.video_clean = true;
            pthread_mutex_unlock(&r->lock);
        }
        if (atomic_load_explicit(&r->exit_requested, memory_order_acquire)) {
            execute(r, (sl_command){.type = SL_CMD_EXIT});
            continue;
        }
        if (r->client)
            IHS_ClientPumpAuthorization(r->client, 32);
        sl_command cmd = {0};
        sl_auth_store save;
        bool save_pending, snapshot_pending;
        sl_language save_language;
        bool save_update_check;
        pthread_mutex_lock(&r->lock);
        if (r->request_pending) {
            cmd = r->pending;
            r->request_pending = false;
        }
        save_pending = r->save_pending;
        save_language = r->save_language;
        save_update_check = r->save_update_check;
        snapshot_pending = r->snapshot_pending;
        if (snapshot_pending) {
            save = r->save;
            r->snapshot_pending = false;
        }
        r->save_pending = false;
        if (r->request_terminal) {
            r->request_at = 0;
            r->request_terminal = false;
        }
        bool ready = r->session_ready;
        r->session_ready = false;
        IHS_SessionInfo info = r->session_info;
        bool conn = r->connected;
        r->connected = false;
        bool finished = r->finished;
        bool host_stopped = r->host_stopped;
        bool auth = r->auth_ready;
        r->auth_ready = false;
        uint64_t account = r->auth_account;
        uint8_t auth_secret[32];
        memcpy(auth_secret, r->auth_secret, sizeof(auth_secret));
        memset(r->auth_secret, 0, sizeof(r->auth_secret));
        pthread_mutex_unlock(&r->lock);
        if (snapshot_pending) {
            /* A UI snapshot queued before authorization completed must not
             * undo the just-accepted host facts. An explicitly removed host
             * stays absent; the actor will honor its queued command below. */
            if (r->auth_persist_attempted) {
                const sl_host *known = sl_host_find(&r->store.registry, r->active.host.id);
                sl_host *incoming = sl_host_find(&save.registry, r->active.host.id);
                if (known && incoming && known->client_id == incoming->client_id) {
                    incoming->paired = known->paired;
                    incoming->account = known->account;
                    incoming->has_secret = known->has_secret;
                    memcpy(incoming->secret, known->secret, sizeof(incoming->secret));
                }
            }
            sl_host_registry_keep_secrets(&save.registry, &r->store.registry);
            r->store = save;
        }
        sync_stream_settings(r, snapshot_pending);
        if (save_pending) {
            bool profile_saved = sl_auth_save(&r->store, sl_system_data_dir());
            bool language_saved = sl_i18n_save(sl_system_data_dir(), save_language);
            bool update_saved = sl_update_config_save(sl_system_data_dir(), save_update_check);
            if (!profile_saved || !language_saved || !update_saved)
                fail(r, sl_tr(SL_T_SAVE_SETTINGS_FAILED));
        }
        if (cmd.type) {
            execute(r, cmd);
            continue;
        }
        if (auth && account) {
            if (!r->auth_persist_attempted)
                post(r, (sl_runtime_event){.type = SL_EVENT_SAVING});
            sl_host *h = sl_host_find(&r->store.registry, r->active.host.id);
            if (!h && r->store.registry.count < SL_HOST_LIMIT) {
                h = &r->store.registry.hosts[r->store.registry.count++];
                *h = r->active.host;
            }
            if (h) {
                h->paired = true;
                h->account = account;
                h->has_secret = memcmp(auth_secret, r->store.secret, sizeof(auth_secret)) != 0;
                if (h->has_secret)
                    memcpy(h->secret, auth_secret, sizeof(h->secret));
                else
                    memset(h->secret, 0, sizeof(h->secret));
                sl_log(h->has_secret ? "pair: key exchange, host-specific key stored"
                                     : "pair: legacy pairing, installation key kept");
            }
            if (!h)
                fail(r, sl_tr(SL_T_SAVE_PAIR_FAILED));
            else {
                if (!r->auth_persist_attempted && !sl_auth_save(&r->store, sl_system_data_dir()))
                    sl_log("pair: legacy profile save failed; authorization continues");
                post(r, (sl_runtime_event){
                            .type = SL_EVENT_AUTHORIZED, .account = account, .host = *h});
            }
            r->request_at = 0;
        }
        memset(auth_secret, 0, sizeof(auth_secret));
        if (ready && !r->session && !r->test_session) {
            bool testing = r->test_active;
            if (!(testing ? launch_network_test(r, info) : launch_session(r, info))) {
                if (testing)
                    fail_network_test(r);
                else {
                    stop_session(r);
                    fail(r, sl_tr(SL_T_SESSION_FAILED));
                }
            }
        }
        if (conn && r->session) {
            stream_media_set_hid_session(r->session, true);
            IHS_SessionHIDNotifyDeviceChange(r->session);
        }
        if (finished && r->session) {
            bool had_video = r->first_reported;
            bool normal = (stop_session(r) || host_stopped) && had_video;
            post(r, (sl_runtime_event){.type = SL_EVENT_STOPPED, .account = normal ? 0 : 1});
            IHS_ClientStartDiscovery(r->client, 3000);
        }
        uint64_t now = sl_system_now();
        sample_network_test(r, now);
        if (r->client && !r->session && !r->test_active && !r->request_at &&
            now - last_probe >= 3000) {
            last_probe = now;
            CMsgRemoteClientBroadcastDiscovery probe = CMSG_REMOTE_CLIENT_BROADCAST_DISCOVERY__INIT;
            probe.has_seq_num = true;
            probe.seq_num = ++discovery_seq;
            for (int i = -1; i < r->store.registry.count; ++i) {
                const char *ip = i < 0 ? legacy_address : r->store.registry.hosts[i].address;
                IHS_SocketAddress address = {.port = 27036};
                if (!ip[0] || !IHS_IPAddressFromString(&address.ip, ip))
                    continue;
                bool sent = IHS_ClientSend(r->client, address, k_ERemoteClientBroadcastMsgDiscovery,
                                           (ProtobufCMessage *)&probe);
                if (discovery_seq <= 2) {
                    char line[160];
                    snprintf(line, sizeof(line), "discovery: saved address %s sent=%d", ip, sent);
                    sl_log(line);
                }
            }
        }
        if (now - r->last_diag >= 1000)
            sample(r, now);
        pthread_mutex_lock(&r->lock);
        bool launch_done = sl_launch_finished(&r->launch);
        bool ending_game = r->end_game.at != 0;
        sl_end_game_result end_result = sl_end_game_poll(
            &r->end_game, now, r->session && IHS_SessionHostRequestedStop(r->session));
        bool end_game_done = end_result == SL_END_GAME_DONE;
        bool end_game_timeout = end_result == SL_END_GAME_TIMEOUT;
        bool probe_launch =
            r->session && (r->launch.target || ending_game) && now - r->launch_probe_at >= 1000;
        if (probe_launch)
            r->launch_probe_at = now;
        pthread_mutex_unlock(&r->lock);
        if (end_game_timeout && !launch_done && r->session) {
            /* The callback may arrive after poll above, even during join.
             * Do not destroy/reset the completion evidence before checking it. */
            if (stop_session(r)) {
                sl_log("user end game: host completion during timeout cleanup");
                post(r, (sl_runtime_event){.type = SL_EVENT_STOPPED});
                IHS_ClientStartDiscovery(r->client, 3000);
            } else {
                fail(r, sl_tr(SL_T_END_GAME_FAILED));
            }
            continue;
        }
        if ((launch_done || end_game_done) && r->session) {
            sl_log(
                end_game_done
                    ? "user end game: host stop or fresh no-games reports; normal return"
                    : "launch: target played, Desktop, fresh host reports no games; normal return");
            stop_session(r);
            post(r, (sl_runtime_event){.type = SL_EVENT_STOPPED});
            IHS_ClientStartDiscovery(r->client, 3000);
            continue;
        }
        if (probe_launch) {
            IHS_HostInfo host;
            if (host_info(r, &r->active.host, &host)) {
                CMsgRemoteClientBroadcastDiscovery probe =
                    CMSG_REMOTE_CLIENT_BROADCAST_DISCOVERY__INIT;
                probe.has_seq_num = true;
                probe.seq_num = ++discovery_seq;
                IHS_ClientSend(r->client, host.address, k_ERemoteClientBroadcastMsgDiscovery,
                               (ProtobufCMessage *)&probe);
            }
        }
        unsigned foreground_requested = atomic_load(&r->foreground_generation);
        for (unsigned count = 0; count < 32 && r->foreground_applied != foreground_requested;
             ++count) {
            unsigned edge = ++r->foreground_applied;
            if (r->session)
                IHS_SessionSetForeground(r->session, !(edge & 1u));
        }
        if (r->session &&
            sl_connection_wait_expired(IHS_SessionIsConnectionPending(r->session),
                                       r->connect_wait_tick, sl_connection_wait_tick(now))) {
            stop_session(r);
            fail(r, sl_tr(SL_T_SESSION_FAILED));
        }
#if NSL_DIAGNOSTICS
        udp_poll(r);
#endif
        pthread_mutex_lock(&r->lock);
        if (!r->request_pending && !r->quit) {
            struct timespec t;
            clock_gettime(CLOCK_REALTIME, &t);
            t.tv_nsec += 20000000;
            if (t.tv_nsec >= 1000000000) {
                t.tv_sec++;
                t.tv_nsec -= 1000000000;
            }
            pthread_cond_timedwait(&r->wake, &r->lock, &t);
        }
        pthread_mutex_unlock(&r->lock);
    }
    stop_session(r);
    sync_stream_settings(r, true); /* Producers joined; include the final callback/edit. */
    while (!sl_media_video_clean()) {
        struct timespec pause = {0, 1000000};
        nanosleep(&pause, NULL);
    }
    pthread_mutex_lock(&r->lock);
    r->facts.video_clean = true;
    pthread_mutex_unlock(&r->lock);
    stop_client(r);
    if (r->provider) {
        stream_media_destroy_hid_provider(r->provider);
        r->provider = NULL;
    }
    sl_log("cleanup: IHS_Quit");
    IHS_Quit();
    post(r, (sl_runtime_event){.type = SL_EVENT_CLOSED});
    atomic_store_explicit(&r->worker_finished, true, memory_order_release);
    return NULL;
}

bool sl_runtime_network_test(sl_runtime *r, sl_network_test_view *view) {
    if (!r || !view)
        return false;
    pthread_mutex_lock(&r->lock);
    *view = r->test_view;
    pthread_mutex_unlock(&r->lock);
    return view->generation != 0;
}
sl_runtime *sl_runtime_create(const sl_auth_store *store) {
    sl_runtime *r = calloc(1, sizeof(*r));
    if (!r)
        return NULL;
    r->store = *store;
    r->udp = -1;
    atomic_init(&r->exit_requested, false);
    atomic_init(&r->foreground_generation, 0);
    atomic_init(&r->player_input_focus, true);
    atomic_init(&r->worker_finished, false);
    pthread_mutex_init(&r->lock, NULL);
    pthread_cond_init(&r->wake, NULL);
    if (!sl_stream_settings_init(&r->settings, store)) {
        pthread_cond_destroy(&r->wake);
        pthread_mutex_destroy(&r->lock);
        free(r);
        return NULL;
    }
    r->config = (IHS_ClientConfig){.deviceId = r->store.device_id,
                                   .secretKey = r->store.secret,
                                   .deviceName = r->store.device_name};
    r->provider = stream_media_create_hid_provider();
#if NSL_DIAGNOSTICS
    r->udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (r->udp >= 0) {
        fcntl(r->udp, F_SETFL, O_NONBLOCK);
        struct sockaddr_in a = {.sin_family = AF_INET,
                                .sin_port = htons(28772),
                                .sin_addr = {.s_addr = htonl(INADDR_ANY)}};
        if (bind(r->udp, (struct sockaddr *)&a, sizeof(a))) {
            close(r->udp);
            r->udp = -1;
        }
    }
    char udp_status[96];
    snprintf(udp_status, sizeof(udp_status), "runtime: debug UDP fd=%d errno=%d", r->udp, errno);
    sl_log(udp_status);
#endif
    r->started = pthread_create(&r->worker, NULL, worker_main, r) == 0;
    if (!r->started) {
        sl_runtime_destroy(r);
        return NULL;
    }
    return r;
}
bool sl_runtime_submit(sl_runtime *r, const sl_command *cmd, const sl_auth_store *store) {
    pthread_mutex_lock(&r->lock);
    if (cmd->type == SL_CMD_STOP || cmd->type == SL_CMD_CANCEL || cmd->type == SL_CMD_EXIT)
        sl_media_close_video();
    if (cmd->type == SL_CMD_SAVE) {
        r->save = *store;
        r->snapshot_pending = true;
        r->save_pending = true;
        r->save_language = cmd->language;
        r->save_update_check = cmd->update_check;
    } else {
        if (r->request_pending && cmd->type != SL_CMD_EXIT && cmd->type != SL_CMD_CANCEL &&
            cmd->type != SL_CMD_STOP) {
            pthread_mutex_unlock(&r->lock);
            return false;
        }
        r->pending = *cmd;
        r->request_pending = true;
        /* A command needs a snapshot, not an unrelated pre-command disk write. */
        r->save = *store;
        r->snapshot_pending = true;
    }
    sl_stream_settings_note_ui(&r->settings, store);
    pthread_cond_signal(&r->wake);
    pthread_mutex_unlock(&r->lock);
    return true;
}
bool sl_runtime_poll(sl_runtime *r, sl_runtime_event *e) {
    if (pthread_mutex_trylock(&r->lock))
        return false;
    bool found = r->count > 0;
    if (found) {
        *e = r->events[0];
        memmove(r->events, &r->events[1], --r->count * sizeof(*e));
    }
    pthread_mutex_unlock(&r->lock);
    return found;
}
void sl_runtime_debug(sl_runtime *r, sl_debug_snapshot *d) {
#if NSL_DIAGNOSTICS
    if (!pthread_mutex_trylock(&r->lock)) {
        *d = r->debug;
        pthread_mutex_unlock(&r->lock);
    }
#else
    (void)r;
    memset(d, 0, sizeof(*d));
#endif
}
void sl_runtime_request_exit(sl_runtime *r) {
    if (!r)
        return;
    atomic_store_explicit(&r->exit_requested, true, memory_order_release);
    pthread_mutex_lock(&r->lock);
    sl_media_close_video();
    pthread_cond_signal(&r->wake);
    pthread_mutex_unlock(&r->lock);
}
bool sl_runtime_finished(sl_runtime *r) {
    return !r || !r->started || atomic_load_explicit(&r->worker_finished, memory_order_acquire);
}
void sl_runtime_destroy(sl_runtime *r) {
    sl_runtime_request_exit(r);
    if (!r)
        return;
    if (r->started) {
        pthread_mutex_lock(&r->lock);
        r->pending = (sl_command){.type = SL_CMD_EXIT};
        r->request_pending = true;
        pthread_cond_signal(&r->wake);
        pthread_mutex_unlock(&r->lock);
        pthread_join(r->worker, NULL);
    }
    if (r->provider)
        stream_media_destroy_hid_provider(r->provider);
    if (r->udp >= 0)
        close(r->udp);
    sl_log("cleanup: runtime worker joined");
    sl_stream_settings_destroy(&r->settings);
    pthread_cond_destroy(&r->wake);
    pthread_mutex_destroy(&r->lock);
    free(r);
}

void sl_runtime_player_focus(sl_runtime *r, bool focused) {
    if (r)
        atomic_store(&r->player_input_focus, focused);
}

void sl_runtime_foreground(sl_runtime *r, bool foreground) {
    if (!r)
        return;
    unsigned generation = atomic_load(&r->foreground_generation);
    while ((generation & 1u) != (unsigned)!foreground) {
        if (atomic_compare_exchange_weak(&r->foreground_generation, &generation, generation + 1u))
            break;
    }
}

bool sl_runtime_read_facts(sl_runtime *r, sl_runtime_facts *facts) {
    if (!r || pthread_mutex_trylock(&r->lock))
        return false;
    *facts = r->facts;
    pthread_mutex_unlock(&r->lock);
    return true;
}

bool sl_runtime_stream_settings(sl_runtime *r, sl_stream_preferences *view, uint64_t *revision) {
    if (!r || pthread_mutex_trylock(&r->lock))
        return false;
    bool ready = r->settings_view_ready;
    if (ready) {
        *view = r->settings_view;
        *revision = r->settings_view_revision;
    }
    pthread_mutex_unlock(&r->lock);
    return ready;
}
uint64_t sl_runtime_settings_revision(sl_runtime *r) {
    return r ? sl_stream_settings_revision(&r->settings) : 0;
}

void sl_runtime_ack_stream_settings(sl_runtime *r, const sl_stream_preferences *view,
                                    uint64_t revision) {
    if (r)
        sl_stream_settings_ack_ui(&r->settings, view, revision);
}
