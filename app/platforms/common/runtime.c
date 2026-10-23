#include "platform/runtime.h"
#ifndef NSL_HAVE_SNS
#define NSL_HAVE_SNS 0
#endif
#include "client_pri.h"
#include "diagnostic_log.h"
#include "discovery.pb-c.h"
#include "media.h"
#include "packet_diagnostics.h"
#include "platform/shortcut.h"
#include "platform/system.h"
#include "remote_connection.h"
#if NSL_DIAGNOSTICS
#include "endianness.h"
#include "remote_wire.h"
#include "session/session_pri.h"
#endif
#include "host_directory.h"
#if NSL_HAVE_SNS
#include "sns_backend.h"
#include "sns_config_cache.h"
#endif
#include "connection_wait.h"
#include "control_udp.h"
#include "network_stats_file.h"
#include "protobuf/remoteplay.pb-c.h"
#include "services/i18n.h"
#include "services/host_key_store.h"
#include "services/launch_watch.h"
#include "services/update_config.h"
#include "stream_settings.h"
#include <arpa/inet.h>
#include <dirent.h>
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
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef struct sl_control_frame {
    struct sl_control_frame *next;
    uint64_t epoch, account;
    size_t size;
    uint8_t wire[];
} sl_control_frame;
static void accepted_connection(IHS_Client *, const IHS_HostInfo *, const IHS_StreamingConnection *,
                                void *);
static bool cloud_save_key(const sl_remote_peer *, void *);
static void cloud_paired(const sl_remote_peer *, void *);
static void free_session_material(sl_remote_material *);
#if NSL_DIAGNOSTICS
typedef struct {
    uint64_t direct_lookup, remote_lookup, queued, rejected, forwarded, failed, stale, received;
    unsigned reject_reason, received_tag, received_id;
    int received_result;
} sl_control_diagnostics;
#endif
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
    bool service_unavailable; /* Owner-only callback context, not an auth wire result. */
    sl_language save_language;
    bool save_update_check;
    sl_resolution resolution, save_resolution;
    sl_stream_request_limits stream_limits; /* Frozen from ticket through negotiation. */
    sl_command pending, active;
    sl_auth_store store, save;
    uint64_t credential_revision, save_credential_revision; /* UI snapshot fence, not wire state. */
    sl_stream_settings settings;
    sl_stream_preferences settings_view;
    uint64_t settings_view_revision;
    bool settings_view_ready;
    sl_runtime_event events[48];
    int count;
    IHS_Client *client;
    sl_remote_connection *remote;
    bool control_cloud_ready; /* Protected by lock; never read CM state on a timer. */
    uint64_t control_epoch;
    sl_control_frame *control_head, *control_tail;
    size_t control_count, control_bytes;
    uint64_t control_next_update;
    sl_account_list paired_accounts; /* Actor-owned, separate from UI profiles. */
    bool accounts_initialized;
#if NSL_HAVE_SNS
    sl_sns *sns;
    sl_sns_config_cache *sns_config; /* Worker-owned, survives individual streams. */
    bool sns_waiting;
    IHS_SessionInfo sns_info; /* Frozen backend material; a PIN retry may replace the ticket. */
    atomic_bool session_finalized;
#endif
    sl_directory_host *directory; /* Both producers serialize under lock. */
    uint64_t cloud_refresh; /* UI heartbeat; never updates last_status. */
    bool discovery_subscription;
    char discovery_hint[64];
    IHS_DiscoveryTarget *discovery_targets;
    size_t discovery_target_count;
    uint64_t discovery_ids[SL_HOST_LIMIT];
    size_t discovery_id_count;
    /* Discovery metadata is transient; keep it out of the profile ABI. */
    IHS_HostInfo discovered_hosts[SL_HOST_LIMIT];
    unsigned discovered_count, discovered_next;
    IHS_Session *session;
    IHS_Session *test_session; /* Dedicated protocol owner; never a video player. */
    bool test_active, test_joined, test_waiting_pin;
    bool test_retry_pending, test_retry_ticket, test_startup_failed;
    uint64_t test_sample_at;
    sl_network_test_view test_view;
    IHS_HIDProvider *provider;
    IHS_ClientConfig config;
    IHS_SessionInfo session_info;
    sl_remote_material *session_material; /* Owned until the actor consumes/discards the ticket. */
    bool player_hardware_decoding; /* Player cache, distinct from silent EIO config changes. */
    sl_launch_watch launch;
    uint64_t launch_probe_at;
    sl_end_game_watch end_game;
    bool session_ready, connected, finished, host_stopped, first_reported, auth_ready,
        auth_consumed, auth_persist_attempted, request_terminal;
    uint64_t auth_account, request_at, last_diag;
    uint32_t connect_wait_tick;
#if NSL_DIAGNOSTICS
    uint64_t cloud_stall_at, frame_at;
    sl_control_diagnostics control_diag; /* Counters under lock; no packet/identity storage. */
#endif
    uint8_t auth_secret[32];
    sl_debug_snapshot debug;
    stream_media_snapshot previous;
    int udp;
};

#if NSL_DIAGNOSTICS
static bool hid_lifecycle_log(const char *tag, const char *message) {
    if (strcmp(tag, "HID"))
        return false;
    bool selected = !strncmp(message, "Start enumerate device.", 23) ||
                    !strncmp(message, "Device found:", 13);
    if (!selected && !strncmp(message, "Message ", 8)) {
        const char *operation = message + 8;
        const char *digits = operation;
        while (*operation >= '0' && *operation <= '9') ++operation;
        selected = operation != digits &&
                   (!strncmp(operation, ": Open(", 7) || !strncmp(operation, ": Close(", 8) ||
                    !strncmp(operation, ": StartInputReports(", 20) ||
                    !strncmp(operation, ": RequestFullReport(", 20));
    }
    if (!selected)
        return false;
    /* Shared receive/runtime callback: no I/O, locks, payloads or report dumps.
     * Bound even repeated lifecycle requests to eight records per second. */
    static atomic_uint_fast64_t budget;
    uint_fast64_t second = sl_system_now() / 1000;
    uint_fast64_t old = atomic_load(&budget);
    for (;;) {
        unsigned used = old >> 8 == second ? old & 255u : 0;
        if (used >= 8)
            return false;
        uint_fast64_t next = (second << 8) | (used + 1);
        if (atomic_compare_exchange_weak(&budget, &old, next))
            return true;
    }
}
static void ihs_log(IHS_LogLevel level, const char *tag, const char *message) {
    if (level > IHS_LogLevelWarn && strcmp(tag, "Activity") && strcmp(tag, "StreamState") &&
        !(level == IHS_LogLevelInfo && !strcmp(tag, "Session")) &&
        !hid_lifecycle_log(tag, message))
        return;
    char s[224];
    snprintf(s, sizeof(s), "%.24s: %.190s", tag, message);
    sl_log(s);
}
#else
#define ihs_log NULL
#endif
#if NSL_DIAGNOSTICS
/* Owner-thread snapshots: no packet dumps, secret material, disk or network I/O. */
static void diagnostic_state(sl_runtime *r, const char *phase) {
    stream_media_snapshot s;
    stream_media_get_snapshot(&s);
    IHS_SessionReliabilityStats rel = {0};
    if (r->session)
        IHS_SessionGetReliabilityStats(r->session, &rel);
    const char *route = r->session ? "lan_udp" : "none";
    int sdk = 0, end_reason = 0, terminal = 0, detail = 0, relayed = 0;
    uint64_t tx = 0, rx = 0;
#if NSL_HAVE_SNS
    if (r->sns) {
        sl_sns_stats stats;
        sl_sns_get_stats(r->sns, &stats);
        sdk = stats.sdk_state;
        end_reason = sl_sns_end_reason(r->sns);
        relayed = stats.relayed;
        terminal = stats.terminal_source;
        detail = stats.terminal_detail;
        tx = stats.datagrams_sent;
        rx = stats.datagrams_received;
        route = sl_sns_get_state(r->sns) != SL_SNS_CONNECTED ? "sns_pending_or_closed"
                : relayed                                    ? "sns_relay"
                                                             : "sns_direct";
    }
#endif
    char line[224];
    pthread_mutex_lock(&r->lock);
    sl_control_diagnostics control = r->control_diag;
    size_t queued = r->control_count;
    pthread_mutex_unlock(&r->lock);
    snprintf(line, sizeof(line),
             "control_tx phase=%s state=%u direct_lookup=%llu remote_lookup=%llu queued=%llu "
             "rejected=%llu reason=%u forwarded=%llu failed=%llu stale=%llu pending=%zu",
             phase, r->client ? IHS_ClientHandshakePhase(r->client) : 0,
             (unsigned long long)control.direct_lookup, (unsigned long long)control.remote_lookup,
             (unsigned long long)control.queued, (unsigned long long)control.rejected,
             control.reject_reason, (unsigned long long)control.forwarded,
             (unsigned long long)control.failed, (unsigned long long)control.stale, queued);
    sl_log(line);
    snprintf(line, sizeof(line), "control_rx phase=%s received=%llu tag=%u id=%u result=%d",
             phase, (unsigned long long)control.received, control.received_tag,
             control.received_id, control.received_result);
    sl_log(line);
    snprintf(line, sizeof(line),
             "connection phase=%s req=%llu session=%llu route=%s sdk=%d relay=%d end=%d "
             "origin=%d/%d tx=%llu rx=%llu",
             phase, (unsigned long long)r->active.generation, (unsigned long long)r->session_id,
             route, sdk, relayed, end_reason, terminal, detail, (unsigned long long)tx,
             (unsigned long long)rx);
    sl_log(line);
    if (r->session) {
        sl_packet_snapshot packets;
        sl_packet_diagnostics_read(&packets);
        snprintf(line, sizeof(line), "udp_rx observer=%d total=%llu", packets.active,
                 (unsigned long long)packets.raw_total);
        sl_log(line);
        for (unsigned channel = 0; channel < 32; ++channel) {
            if (!packets.raw_media[channel] && !packets.admitted[channel] &&
                !packets.recovery[channel])
                continue;
            snprintf(line, sizeof(line), "media_rx ch=%u raw=%llu admitted=%llu recovery=%llu",
                     channel, (unsigned long long)packets.raw_media[channel],
                     (unsigned long long)packets.admitted[channel],
                     (unsigned long long)packets.recovery[channel]);
            sl_log(line);
        }
    }
    snprintf(line, sizeof(line),
             "pipeline phase=%s session=%llu epoch=%llu active=%d submit=%llu decode=%u show=%u "
             "audio=%u audio_err=%u first=%d frame_idle_ms=%llu log_drop=%u",
             phase, (unsigned long long)s.session_id, (unsigned long long)s.video_epoch,
             s.video_active, (unsigned long long)s.pacing.submits, s.decoded_frames,
             s.displayed_frames, s.audio_frames, s.audio_decode_errors, r->first_reported,
             (unsigned long long)(r->request_at ? sl_system_now() - r->frame_at : 0),
             sl_log_drop_count());
    sl_log(line);
    snprintf(line, sizeof(line),
             "reliable phase=%s tracked=%llu ack=%llu retry=%llu nack=%llu fail=%llu giveup=%llu "
             "pending=%u oldest_ms=%llu channel=%u packet=%u",
             phase, (unsigned long long)rel.reliableTracked,
             (unsigned long long)rel.reliableAcknowledged, (unsigned long long)rel.reliableRetries,
             (unsigned long long)rel.reliableNacks, (unsigned long long)rel.reliableSendFailures,
             (unsigned long long)rel.reliableGiveUps, rel.reliableOutstanding,
             (unsigned long long)rel.reliableOldestOutstandingMs, rel.reliableOldestChannelId,
             rel.reliableOldestPacketId);
    sl_log(line);
    if (r->session) {
        IHS_HIDSDLLastSubmitted last = {0};
        bool submitted = IHS_HIDSDLGetLastSubmittedReport(r->session, &last);
        snprintf(line, sizeof(line),
                 "hid_transport phase=%s submitted=%llu sent=%llu ack=%llu pending=%u flight=%u",
                 phase, (unsigned long long)rel.hidSubmitted, (unsigned long long)rel.hidSent,
                 (unsigned long long)rel.hidAcknowledged, rel.hidPending, rel.hidInFlight);
        sl_log(line);
        snprintf(line, sizeof(line),
                 "hid_capture phase=%s provider=%d attached=%d gate=%d input=%d events=%u "
                 "raw_btn=%u valid=%d seq=%llu buttons=%u",
                 phase, s.hid_provider_devices, s.hid_session_enabled, s.hid_input_gate,
                 IHS_SessionInputEnabled(r->session), s.hid_events, s.hid_raw_btn_total, submitted,
                 (unsigned long long)last.seq, last.buttons);
        sl_log(line);
    }
}
static void diagnostic_phase(const char *phase, int value) {
    char line[128];
    snprintf(line, sizeof(line), "connection_event phase=%s value=%d", phase, value);
    sl_log(line);
}
#else
#define diagnostic_state(r, phase)     ((void)0)
#define diagnostic_phase(phase, value) ((void)0)
#endif
static void post_locked(sl_runtime *r, sl_runtime_event e) {
    if (e.type != SL_EVENT_HOST && e.type != SL_EVENT_NETWORK)
        e.generation = r->active.generation;
    /* Discovery is coalesced and capped below the reserved terminal capacity. */
    if (e.type == SL_EVENT_HOST) {
        for (int i = r->count - 1; i >= 0; --i) {
            /* An Offline between two statuses is an ordering boundary. Do
             * not overwrite a pre-Offline HOST with a later status: the UI
             * would consume the new status first, then the older Offline. */
            if (r->events[i].type == SL_EVENT_HOST_OFFLINE &&
                r->events[i].host.client_id == e.host.client_id)
                break;
            if (r->events[i].type == SL_EVENT_HOST &&
                r->events[i].host.client_id == e.host.client_id &&
                r->events[i].host.instance_id == e.host.instance_id) {
                r->events[i] = e;
                return;
            }
        }
        if (r->count >= 32) {
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
}
static void post(sl_runtime *r, sl_runtime_event e) {
    pthread_mutex_lock(&r->lock);
    post_locked(r, e);
    pthread_mutex_unlock(&r->lock);
}
static bool account_path(uint64_t client, bool paired, char path[512], bool create) {
    const char *root = sl_system_data_dir();
    if (create && mkdir(root, 0700) && errno != EEXIST) return false;
    if (paired)
        return snprintf(path, 512, "%s/paired_steamid.txt", root) < 512;
    char hex[17], dir[512];
    sl_account_hex(client, hex);
    if (snprintf(dir, sizeof(dir), "%s/%s", root, hex) >= (int)sizeof(dir)) return false;
    if (create && mkdir(dir, 0700) && errno != EEXIST) return false;
    return snprintf(path, 512, "%s/steamid.txt", dir) < 512;
}
/* Actor-only disk access, before RX starts. The directory is still serialized
 * because fixtures and later request initialization share these helpers. */
static bool load_client_accounts(sl_runtime *r, uint64_t client, uint64_t seed, bool migrate) {
    pthread_mutex_lock(&r->lock);
    sl_directory_host *h = sl_directory_ensure(&r->directory, client);
    bool loaded = h && h->accounts_loaded;
    if (loaded && h->accounts_absent && migrate) {
        bool added = false;
        bool ok = sl_accounts_pair(&h->accounts, seed, &added);
        h->accounts_dirty |= added;
        h->accounts_absent = !ok;
        pthread_mutex_unlock(&r->lock);
        return ok;
    }
    pthread_mutex_unlock(&r->lock);
    if (loaded) return true;
    if (!h) return false;
    char path[512];
    sl_account_list list = {0};
    int result = account_path(client, false, path, false) ? sl_accounts_load(&list, path) : -1;
    bool added = false;
    if (result == 1 && migrate && !sl_accounts_pair(&list, seed, &added)) result = -1;
    pthread_mutex_lock(&r->lock);
    sl_accounts_destroy(&h->accounts);
    h->accounts = list;
    h->accounts_loaded = true;
    h->accounts_absent = result == 1 && !migrate;
    h->accounts_dirty = added;
    pthread_mutex_unlock(&r->lock);
    if (result < 0) sl_log("identity: client accounts could not be loaded; UI mirror not substituted");
    return result >= 0;
}
static void initialize_accounts(sl_runtime *r) {
    if (r->accounts_initialized) return;
    char path[512];
    int paired = account_path(0, true, path, false) ? sl_accounts_load(&r->paired_accounts, path) : -1;
    /* Include metadata for valid peers that are not represented by a UI card. */
    DIR *dir = opendir(sl_system_data_dir());
    struct dirent *entry;
    while (dir && (entry = readdir(dir))) {
        if (strlen(entry->d_name) != 16) continue;
        uint64_t client = 0;
        bool valid = true;
        for (unsigned i = 0; i < 8; ++i) {
            unsigned byte = 0;
            for (unsigned j = 0; j < 2; ++j) {
                char c = entry->d_name[i*2+j];
                int nibble = c >= '0' && c <= '9' ? c-'0' : c >= 'a' && c <= 'f' ? c-'a'+10 : -1;
                if (nibble < 0) { valid = false; break; }
                byte = byte*16 + (unsigned)nibble;
            }
            client |= (uint64_t)byte << (8*i);
        }
        if (valid && client) load_client_accounts(r, client, 0, false);
    }
    if (dir) closedir(dir);
    bool paired_added = false;
    for (int i = 0; i < r->store.registry.count; ++i) {
        const sl_host *h = &r->store.registry.hosts[i];
        if (!h->client_id) continue;
        load_client_accounts(r, h->client_id, h->account, h->paired);
        if (paired == 1 && h->paired) {
            bool added;
            if (sl_accounts_pair(&r->paired_accounts, h->account, &added)) paired_added |= added;
        }
    }
    if (paired < 0) sl_log("identity: paired accounts could not be loaded; UI subscriptions not substituted");
    if (paired_added && (!account_path(0, true, path, true) ||
                         !sl_accounts_save(&r->paired_accounts, path)))
        sl_log("identity: migrated paired accounts save failed");
    r->accounts_initialized = true;
}
/* Snapshot under lock, write outside it. RX never waits for disk publication.
 * Original save failure is nonfatal and is not a new retry timer policy. */
static void save_client_accounts(sl_runtime *r, uint64_t client) {
    sl_account_list copy = {0};
    pthread_mutex_lock(&r->lock);
    sl_directory_host *h = sl_directory_find(r->directory, client);
    bool dirty = h && h->accounts_dirty;
    bool copied = dirty && sl_accounts_reserve(&copy, h->accounts.count);
    if (copied) {
        copy.count = h->accounts.count;
        if (copy.count) memcpy(copy.ids, h->accounts.ids, copy.count * sizeof(*copy.ids));
        h->accounts_dirty = false;
    }
    pthread_mutex_unlock(&r->lock);
    char path[512];
    if (dirty && (!copied || !account_path(client, false, path, true) ||
                   !sl_accounts_save(&copy, path)))
        sl_log("identity: client accounts save failed; protocol continues");
    sl_accounts_destroy(&copy);
}
static void flush_accounts(sl_runtime *r) {
    pthread_mutex_lock(&r->lock);
    sl_directory_host *h = r->directory;
    while (h) {
        uint64_t client = h->client_id;
        pthread_mutex_unlock(&r->lock);
        save_client_accounts(r, client);
        pthread_mutex_lock(&r->lock);
        h = h->next; /* Records are destroyed only after all producers join. */
    }
    pthread_mutex_unlock(&r->lock);
}
static bool current_account(sl_runtime *r, uint64_t client, uint64_t *account) {
    pthread_mutex_lock(&r->lock);
    const sl_directory_host *h = sl_directory_find(r->directory, client);
    bool found = h && h->accounts.count;
    if (found) *account = h->accounts.ids[0];
    pthread_mutex_unlock(&r->lock);
    return found;
}
static void authorization_identity(IHS_Client *client, uint64_t peer, uint64_t account, void *ctx) {
    (void)client;
    sl_runtime *r = ctx;
    pthread_mutex_lock(&r->lock);
    sl_directory_host *h = sl_directory_ensure(&r->directory, peer);
    bool changed = false;
    bool ok = h && sl_accounts_authorize(&h->accounts, account, &changed);
    if (ok && changed) h->accounts_dirty = true;
    pthread_mutex_unlock(&r->lock);
    if (!ok) sl_log("identity: authorization account allocation failed");
    if (changed) save_client_accounts(r, peer); /* Before key validation/cache/confirm. */
}
static void authorization_subscribe(IHS_Client *client, uint64_t account, void *ctx) {
    (void)client;
    sl_runtime *r = ctx;
    if (r->remote) sl_remote_register_status(sl_remote_connection_protocol(r->remote), account);
}
static void save_paired_account(sl_runtime *r, uint64_t account) {
    bool added;
    if (!sl_accounts_pair(&r->paired_accounts, account, &added)) {
        sl_log("identity: paired account allocation failed");
        return;
    }
    char path[512];
    if (added && (!account_path(0, true, path, true) ||
                  !sl_accounts_save(&r->paired_accounts, path)))
        sl_log("identity: paired accounts save failed; protocol continues");
    if (added && r->remote &&
        !sl_remote_set_paired_accounts(sl_remote_connection_protocol(r->remote),
                                       r->paired_accounts.ids, r->paired_accounts.count))
        sl_log("identity: reconnect account snapshot allocation failed");
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
static void publish_test(sl_runtime *, sl_network_test_view);
static void fail_network_test(sl_runtime *);
static bool test_error_pending(sl_runtime *r) {
    pthread_mutex_lock(&r->lock);
    bool pending = r->facts.test_failure_pending;
    pthread_mutex_unlock(&r->lock);
    return pending;
}
/* Active Qt Test errors change the panel, not the Test owner. Keep its workers
 * until finished(int)->OnActionCancel. Do not enqueue a generic retry/STOP
 * event before the persistent failed snapshot reaches the UI (RE §11.3). */
static void fail_control(sl_runtime *r, const char *message) {
    if (!r->test_active && !test_error_pending(r)) {
        fail(r, message);
        return;
    }
    pthread_mutex_lock(&r->lock);
    r->facts.failed = r->facts.test_failure_pending = true;
    pthread_mutex_unlock(&r->lock);
    /* Original ShowDialog hides/replaces the old Test error, even after its
     * media has failed. This remains a close-only error for the same owner. */
    sl_network_test_view view = {.phase = SL_TEST_FAILED, .control_error = true};
    snprintf(view.error, sizeof(view.error), "%s", message);
    sl_log(message);
    publish_test(r, view);
}
static bool test_owns_display(sl_runtime *r) {
    /* PIN retry's old worker survives behind Connecting/EnteringPIN. In that
     * state Unauthorized belongs to the new request's authorization panel. */
    if (r->test_retry_pending)
        return test_error_pending(r);
    return r->test_session || test_error_pending(r)
#if NSL_HAVE_SNS
           || (r->test_active && r->sns)
#endif
        ;
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
static void publish_host_locked(sl_runtime *r, const sl_directory_host *host) {
    IHS_HostInfo direct;
    bool verified = sl_directory_direct(host, &direct);
    sl_host h = host_from(verified ? &direct : &host->info);
    post_locked(r, (sl_runtime_event){.type = SL_EVENT_HOST, .host = h,
        .discovery_source = verified ? SL_DISCOVERY_LAN
                            : host->cloud ? SL_DISCOVERY_INTERNET : SL_DISCOVERY_UNKNOWN});
}
static void discovery_offline(IHS_Client *, uint64_t, void *);
/* Same status protobuf over UDP or the authenticated CM connection. A private
 * IP is not the identity of an internet stream; preserve client/instance and
 * timestamp freshness checks for both (D-A100). Caller holds runtime.lock. */
static void observe_launch_status_locked(sl_runtime *r, const IHS_HostInfo *h, bool cloud) {
    if (r->active.type != SL_CMD_STREAM || h->clientId != r->active.host.client_id ||
        h->instanceId != r->active.host.instance_id) return;
    if (!cloud) {
        char *ip = IHS_IPAddressToString(&h->address.ip);
        bool match = h->address.port == 27036 && ip && !strcmp(ip, r->active.host.address);
        free(ip);
        if (!match) return;
    }
    sl_launch_status(&r->launch, h->hasGamesRunning, h->gamesRunning, h->hasTimestamp, h->timestamp);
    unsigned before = r->end_game.empty;
    uint32_t stamp = r->end_game.stamp;
    sl_end_game_status(&r->end_game, h->hasGamesRunning, h->gamesRunning, h->hasTimestamp, h->timestamp);
#if NSL_DIAGNOSTICS
    if (r->end_game.at && (before != r->end_game.empty || stamp != r->end_game.stamp)) {
        char line[192];
        snprintf(line, sizeof(line), "end_game_status source=%s present=%d running=%d timestamp=%d stamp=%u empty=%u",
                 cloud ? "cloud" : "lan", h->hasGamesRunning, h->gamesRunning,
                 h->hasTimestamp, h->timestamp, r->end_game.empty);
        sl_log(line);
    }
#else
    (void)before; (void)stamp;
#endif
}
static void discovered_status(IHS_Client *client, const IHS_HostInfo *h,
                              const IHS_DiscoveryAddressHints *hints, void *ctx) {
    (void)client;
    sl_runtime *r = ctx;
    pthread_mutex_lock(&r->lock);
    if (!sl_directory_status(&r->directory, h, hints, false, &h->address, (int64_t)time(NULL))) {
        pthread_mutex_unlock(&r->lock);
        return;
    }
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
    observe_launch_status_locked(r, h, false);
    publish_host_locked(r, sl_directory_find(r->directory, h->clientId));
    pthread_mutex_unlock(&r->lock);
    sl_host observed = host_from(h);
    char line[192];
    snprintf(line, sizeof(line), "discovery: response %.63s %.63s", observed.name,
             observed.address);
    sl_log(line);
}
static void discovered(IHS_Client *client, const IHS_HostInfo *h, void *ctx) {
    discovered_status(client, h, NULL, ctx);
}
/* Deferred authorization dispatch runs on this runtime worker, which owns
 * store. Attempt persistence before the library emits Confirmed; source ignores
 * filesystem failure for protocol progression (protocol RE §129). */
static void persist_authorization(IHS_Client *client, const IHS_HostInfo *host, uint64_t account,
                                  const uint8_t secret[32], void *ctx) {
    (void)client;
    sl_runtime *r = ctx;
    if (r->active.type == SL_CMD_REMOTE_PAIR) {
        sl_remote_peer peer = {.client_id = host->clientId, .steam_id = account};
        memcpy(peer.secret, secret, sizeof(peer.secret));
        cloud_save_key(&peer, r); /* Storage failure never changes the crypto result. */
        memset(&peer, 0, sizeof(peer));
        return;
    }
    if (r->active.type != SL_CMD_PAIR && r->active.type != SL_CMD_STREAM)
        return;
    if (!sl_host_key_save(sl_system_data_dir(), host->clientId, account, secret))
        sl_log("pair: identity key save failed; authorization continues");
    save_paired_account(r, account); /* Original runs even if key-file save failed. */
    if (host->clientId != r->active.host.client_id) {
        /* Successful key validation precedes the manager's target check. Its
         * key belongs to the reply identity, never to active.host. A profile
         * is only a selected-account mirror; other accounts remain namespaced
         * key files until their own metadata/subscription path selects them. */
        bool mirrored = false;
        for (int i = 0; i < r->store.registry.count; ++i) {
            sl_host *peer = &r->store.registry.hosts[i];
            if (!peer->paired || peer->client_id != host->clientId || peer->account != account)
                continue;
            peer->has_secret = memcmp(secret, r->store.secret, 32) != 0;
            if (peer->has_secret)
                memcpy(peer->secret, secret, 32);
            else
                memset(peer->secret, 0, 32);
            mirrored = true;
            post(r, (sl_runtime_event){.type = SL_EVENT_KEY_UPDATED, .host = *peer});
        }
        if (mirrored && !sl_auth_save(&r->store, sl_system_data_dir()))
            sl_log("pair: reply identity profile save failed; authorization continues");
        return;
    }
    if (r->active.type == SL_CMD_PAIR)
        post(r, (sl_runtime_event){.type = SL_EVENT_SAVING});
    sl_host *h = sl_host_find(&r->store.registry, r->active.host.id);
    if (h && h->client_id != host->clientId)
        return;
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

/* Proof persistence uses the request's selected account, which authorization
 * may subsequently differ from. Never replace that other account's mirror. */
static void persist_proof(IHS_Client *client, const IHS_HostInfo *host, uint64_t account,
                          const uint8_t secret[32], void *ctx) {
    (void)client;
    sl_runtime *r = ctx;
    if (!sl_host_key_save(sl_system_data_dir(), host->clientId, account, secret))
        sl_log("proof: identity key save failed; response continues");
    sl_host *h = sl_host_find(&r->store.registry, r->active.host.id);
    if (!h || h->client_id != host->clientId || h->account != account)
        return;
    h->has_secret = memcmp(secret, r->store.secret, 32) != 0;
    if (h->has_secret)
        memcpy(h->secret, secret, 32);
    else
        memset(h->secret, 0, sizeof(h->secret));
    r->auth_persist_attempted = true;
    if (!sl_auth_save(&r->store, sl_system_data_dir()))
        sl_log("proof: profile save failed; response continues");
    pthread_mutex_lock(&r->lock);
    r->active.host = *h;
    pthread_mutex_unlock(&r->lock);
    post(r, (sl_runtime_event){.type = SL_EVENT_HOST_KEY, .host = *h});
}

static void stream_authorization(IHS_Client *client, const IHS_HostInfo *host, const char *pin,
                                 uint64_t account, void *ctx) {
    (void)client;
    (void)host;
    sl_runtime *r = ctx;
    if (r->active.type != SL_CMD_STREAM)
        return;
    if (pin) {
        /* Matching Unauthorized retracts an unconsumed ticket, even when the
         * existing Test owns the display. Its old SDK/session remains owned by
         * that Test; only pending admission material belongs to this request. */
        pthread_mutex_lock(&r->lock);
        r->session_ready = r->test_retry_ticket = false;
        free_session_material(r->session_material);
        r->session_material = NULL;
        pthread_mutex_unlock(&r->lock);
        if (test_owns_display(r))
            return;
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
        if (test_owns_display(r))
            return;
        post(r, (sl_runtime_event){.type = SL_EVENT_STREAM_RESUMED,
                                   .account = r->test_active,
                                   .host = r->active.host});
    }
}

static void authorized(IHS_Client *client, const IHS_HostInfo *h, uint64_t account, void *ctx) {
    (void)h;
    sl_runtime *r = ctx;
    if (r->active.type == SL_CMD_REMOTE_PAIR) {
        sl_remote_peer peer = {.client_id = h->clientId, .steam_id = account};
        IHS_ClientGetSecretKey(client, peer.secret);
        if (r->remote)
            sl_remote_pairing_finished(sl_remote_connection_protocol(r->remote));
        cloud_paired(&peer, r);
        memset(&peer, 0, sizeof(peer));
        return;
    }
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
    if (r->active.type == SL_CMD_REMOTE_PAIR && r->remote)
        sl_remote_pairing_finished(sl_remote_connection_protocol(r->remote));
    pthread_mutex_lock(&r->lock);
    r->request_terminal = true;
    pthread_mutex_unlock(&r->lock);
    fail_control(r, r->service_unavailable                   ? sl_tr(SL_T_CLOUD_UNAVAILABLE)
                    : result == IHS_AuthorizationDenied      ? sl_tr(SL_T_PAIR_DENIED)
                    : result == IHS_AuthorizationTimedOut    ? sl_tr(SL_T_PAIR_TIMEOUT)
                    : result == IHS_AuthorizationNotLoggedIn ? sl_tr(SL_T_LOGIN_STEAM)
                                                             : sl_tr(SL_T_PAIR_FAILED));
}
static void free_session_material(sl_remote_material *material) {
    if (!material) return;
    free((void *)material->cert);
    free((void *)material->stun_servers);
    memset(material, 0, sizeof(*material));
    free(material);
}
static void accept_session(sl_runtime *r, const IHS_SocketAddress *address, const uint8_t *key,
                           size_t len, uint64_t account) {
    diagnostic_phase("stream_request_accepted", address->port);
    if (len > 32) {
        fail(r, sl_tr(SL_T_INVALID_RESPONSE));
        return;
    }
    pthread_mutex_lock(&r->lock);
    free_session_material(r->session_material);
    r->session_material = NULL;
    r->session_info =
        (IHS_SessionInfo){.address = *address, .sessionKeyLen = len, .steamId = account};
    memcpy(r->session_info.sessionKey, key, len);
    r->session_ready = true;
    pthread_mutex_unlock(&r->lock);
}
static void accepted(IHS_Client *c, const IHS_HostInfo *h, const IHS_SocketAddress *address,
                     const uint8_t *key, size_t len, void *ctx) {
    (void)c;
    (void)h;
    sl_runtime *r = ctx;
    accept_session(r, address, key, len, r->active.host.account);
}
static void rejected(IHS_Client *c, const IHS_HostInfo *h, IHS_StreamingResult result, void *ctx) {
    (void)c;
    (void)h;
    sl_runtime *r = ctx;
    diagnostic_phase("stream_request_rejected", result);
    pthread_mutex_lock(&r->lock);
    r->request_terminal = true;
    pthread_mutex_unlock(&r->lock);
    if (result == IHS_StreamingPINRequired) {
        r->test_waiting_pin = r->test_active;
        post(r, (sl_runtime_event){.type = SL_EVENT_PIN});
    } else
        fail_control(r, result == IHS_StreamingScreenLocked       ? sl_tr(SL_T_UNLOCK_PC)
                        : result == IHS_StreamingBusy             ? sl_tr(SL_T_PC_BUSY)
                        : result == IHS_StreamingGameLaunchFailed ? sl_tr(SL_T_GAME_FAILED)
                        : result == IHS_StreamingDisabled         ? sl_tr(SL_T_ENABLE_REMOTE_PLAY)
                                                                  : sl_tr(SL_T_CANNOT_CONNECT));
}
static void configuring(IHS_Session *s, IHS_SessionConfig *c, void *ctx) {
    (void)s;
    sl_runtime *r = ctx;
    diagnostic_phase("ihs_configuring", 0);
    /* The full saved config supplies preferences. Only apply actual platform
     * limits here; copying legacy command defaults would erase saved fields. */
    c->enableHevc = false;
    if (!c->maxWidth || c->maxWidth > r->stream_limits.width)
        c->maxWidth = r->stream_limits.width;
    if (!c->maxHeight || c->maxHeight > r->stream_limits.height)
        c->maxHeight = r->stream_limits.height;
    if (!c->maxFps || c->maxFps > 60)
        c->maxFps = 60;
}
static void connected(IHS_Session *s, void *ctx) {
    (void)s;
    sl_runtime *r = ctx;
    diagnostic_phase("ihs_connected", 0);
    pthread_mutex_lock(&r->lock);
    r->connected = true;
    r->facts.connected = true;
    pthread_mutex_unlock(&r->lock);
}
static void disconnected(IHS_Session *s, void *ctx) {
    sl_runtime *r = ctx;
    diagnostic_phase("ihs_disconnected", IHS_SessionHostRequestedStop(s));
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
static const IHS_ClientDiscoveryCallbacks discovery_cb = {
    .discovered = discovered, .status = discovered_status, .offline = discovery_offline};
static const IHS_ClientAuthorizationCallbacks auth_cb = {
    .persist = persist_authorization, .success = authorized, .failed = auth_failed,
    .identity = authorization_identity, .subscribe = authorization_subscribe};
static const IHS_ClientStreamingCallbacks stream_cb = {.success = accepted,
                                                       .failed = rejected,
                                                       .authorization = stream_authorization,
                                                       .authorizationFailed = auth_failed,
                                                       .persistProof = persist_proof,
                                                       .connection = accepted_connection};
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
#if NSL_HAVE_SNS
static void session_finalized(IHS_Session *session, void *ctx) {
    (void)session;
    atomic_store(&((sl_runtime *)ctx)->session_finalized, true);
}
#endif
static const IHS_StreamSessionCallbacks session_cb = {.configuring = configuring,
                                                      .connected = connected,
                                                      .disconnected = disconnected,
                                                      .saveClientConfig = client_config_saved,
#if NSL_HAVE_SNS
                                                      .finalized = session_finalized,
#endif
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
    if (r->facts.test_failure_pending && view.phase != SL_TEST_FAILED &&
        view.phase != SL_TEST_IDLE) {
        pthread_mutex_unlock(&r->lock);
        return;
    }
    view.generation = r->active.generation;
    view.revision = r->test_view.revision + 1;
    view.test_only = r->active.test_only;
    r->test_view = view;
    pthread_mutex_unlock(&r->lock);
}
static void release_network_test(sl_runtime *r, bool cancel) {
#if NSL_HAVE_SNS
    bool owns_backend = r->test_active || r->test_session;
    bool had_session = r->test_session != NULL;
#endif
    if (r->test_session) {
        if (cancel)
            IHS_SessionDisconnect(r->test_session);
        if (!r->test_joined)
            IHS_SessionThreadedJoin(r->test_session);
        IHS_SessionDestroy(r->test_session);
        r->test_session = NULL;
        sl_log("network test: workers joined, session destroyed");
    }
#if NSL_HAVE_SNS
    /* An asynchronous BInit can fail before IHS exists. Release that Test
     * backend too, without polling a canceled initialization into a new route.
     * Ordinary player backends remain alive until their own IHS join. */
    if (owns_backend && r->sns) {
        if (had_session)
            sl_sns_update(r->sns, sl_system_now());
        sl_sns_destroy(r->sns);
        r->sns = NULL;
        r->sns_waiting = false;
        memset(&r->sns_info, 0, sizeof(r->sns_info));
    }
#endif
    r->test_active = r->test_joined = r->test_waiting_pin = false;
    r->test_retry_pending = r->test_retry_ticket = r->test_startup_failed = false;
    r->test_sample_at = 0;
    if (cancel)
        publish_test(r, (sl_network_test_view){.phase = SL_TEST_IDLE});
}
static void stop_network_test(sl_runtime *r) {
    release_network_test(r, true);
}
/* Original Test::Start joins the live old worker without Cancel. Poll its
 * terminal result here so local cancel/exit and the old SDK bridge stay live.
 * No old result, statistics or recommendation belongs to the replacement. */
static bool finish_test_retry(sl_runtime *r) {
#if NSL_HAVE_SNS
    if (r->sns_waiting)
        return false;
#endif
    if (r->test_session && !r->test_joined) {
        IHS_NetworkTestResult result;
        IHS_SessionGetNetworkTestResult(r->test_session, &result);
        if (!r->test_startup_failed && (result.status == IHS_NetworkTestRunning ||
                                       result.status == IHS_NetworkTestIdle))
            return false;
        IHS_SessionThreadedJoin(r->test_session);
        r->test_joined = true;
    }
    release_network_test(r, false);
    r->test_active = true;
    return true;
}
/* Runtime actor publishes a complete saved-address snapshot; the IHS timer
 * owns all scheduled discovery sends and their shared round sequence. */
static bool sync_discovery_targets(sl_runtime *r) {
    pthread_mutex_lock(&r->lock);
    uint64_t ids[SL_HOST_LIMIT];
    size_t idCount = 0;
    for (int i = 0; i < r->store.registry.count; ++i) {
        uint64_t id = r->store.registry.hosts[i].client_id;
        bool duplicate = !id;
        for (size_t j = 0; j < idCount; ++j) duplicate |= ids[j] == id;
        if (!duplicate) ids[idCount++] = id;
    }
    bool seeded = sl_directory_seed(&r->directory, 0, r->discovery_hint);
    for (int i = 0; seeded && i < r->store.registry.count; ++i)
        seeded = sl_directory_seed(&r->directory, r->store.registry.hosts[i].client_id,
                                    r->store.registry.hosts[i].address);
    size_t count = 0;
    for (size_t i = 0; seeded && i <= idCount; ++i) {
        sl_directory_host *h = sl_directory_find(r->directory, i ? ids[i-1] : 0);
        if (!h) continue;
        if (h->addresses.count > SIZE_MAX/sizeof(IHS_DiscoveryTarget)-count) seeded = false;
        else count += h->addresses.count;
    }
    IHS_DiscoveryTarget *targets = seeded && count ? calloc(count, sizeof(*targets)) : NULL;
    if (!seeded || (count && !targets)) {
        pthread_mutex_unlock(&r->lock);
        return false;
    }
    size_t n = 0;
    for (size_t watched = 0; watched <= idCount; ++watched) {
        sl_directory_host *h = sl_directory_find(r->directory, watched ? ids[watched-1] : 0);
        if (!h) continue;
        for (size_t i = 0; i < h->addresses.count; ++i)
            targets[n++] = (IHS_DiscoveryTarget){.clientId = h->client_id,
                                                 .ip = h->addresses.entries[i].address.ip};
    }
    pthread_mutex_unlock(&r->lock);
    bool same = count == r->discovery_target_count && idCount == r->discovery_id_count &&
                (!idCount || !memcmp(ids, r->discovery_ids, idCount*sizeof(*ids)));
    for (size_t i = 0; same && i < count; ++i)
        same = targets[i].clientId == r->discovery_targets[i].clientId &&
               IHS_IPAddressCompare(&targets[i].ip, &r->discovery_targets[i].ip) == 0;
    /* Do not hold the app mutex while entering the IHS operation queue. A
     * concurrent receive can publish a newer directory for the next update. */
    if (same) { free(targets); return true; }
    if (!IHS_ClientSetDiscoveryDirectory(r->client, targets, count, ids, idCount)) {
        free(targets);
        return false;
    }
    free(r->discovery_targets);
    r->discovery_targets = targets;
    r->discovery_target_count = count;
    memcpy(r->discovery_ids, ids, idCount*sizeof(*ids));
    r->discovery_id_count = idCount;
    return true;
}
static bool start_discovery(sl_runtime *r) {
    if (r->discovery_subscription) return IHS_ClientTriggerDiscovery(r->client);
    r->discovery_subscription = IHS_ClientEnableDiscovery(r->client);
    return r->discovery_subscription;
}
static bool pause_discovery(sl_runtime *r) {
    if (r->discovery_subscription && !IHS_ClientDisableDiscovery(r->client)) return false;
    r->discovery_subscription = false;
    return true;
}

static sl_host *saved_host(sl_runtime *r, uint64_t id) {
    for (int i = 0; i < r->store.registry.count; ++i)
        if (r->store.registry.hosts[i].client_id == id)
            return &r->store.registry.hosts[i];
    return NULL;
}
static void cloud_watch(sl_runtime *r) {
    if (!r->remote)
        return;
    initialize_accounts(r);
    sl_remote_peer peers[SL_REMOTE_PEERS];
    size_t count = 0;
    for (int i = 0; i < r->store.registry.count; ++i) {
        const sl_host *h = &r->store.registry.hosts[i];
        if (!h->paired || !h->account || !h->client_id)
            continue;
        peers[count] = (sl_remote_peer){.client_id = h->client_id, .steam_id = h->account};
        memcpy(peers[count++].secret, h->has_secret ? h->secret : r->store.secret, 32);
    }
    sl_remote *protocol = sl_remote_connection_protocol(r->remote);
    bool watching = sl_remote_set_paired_accounts(protocol, r->paired_accounts.ids,
                                                  r->paired_accounts.count) &&
                    sl_remote_watch(protocol, peers, count);
#if NSL_DIAGNOSTICS
    char line[128];
    snprintf(line, sizeof(line), "cloud_watch saved=%d eligible=%zu accepted=%d",
             r->store.registry.count, count, watching);
    sl_log(line);
#else
    (void)watching;
#endif
    memset(peers, 0, sizeof(peers));
}
static bool local_host(sl_runtime *r, uint64_t id, IHS_HostInfo *out) {
    pthread_mutex_lock(&r->lock);
    bool found = sl_directory_direct(sl_directory_find(r->directory, id), out);
    pthread_mutex_unlock(&r->lock);
    return found;
}
static bool control_host(IHS_Client *client, uint64_t id, IHS_HostInfo *out, void *ctx) {
    (void)client;
    sl_runtime *r = ctx;
    pthread_mutex_lock(&r->lock);
    const sl_directory_host *host = sl_directory_find(r->directory, id);
    /* Original GetServerInfo reads the committed visible map. Expiry belongs
     * to Update after CM/UDP dispatch, not to a lookup inside those callbacks. */
    bool visible = host && host->visible;
    if (visible)
        *out = host->info;
    pthread_mutex_unlock(&r->lock);
    return visible;
}
static void control_resolve(IHS_Client *client, uint64_t id, IHS_SocketAddress *out, void *ctx) {
    (void)client;
    IHS_HostInfo host;
    *out = (IHS_SocketAddress){0};
    if (local_host(ctx, id, &host))
        *out = host.address;
#if NSL_DIAGNOSTICS
    sl_runtime *r = ctx;
    pthread_mutex_lock(&r->lock);
    if (IHS_ClientAddressHasIP(&out->ip) && out->port) ++r->control_diag.direct_lookup;
    else ++r->control_diag.remote_lookup;
    pthread_mutex_unlock(&r->lock);
#endif
}
static size_t control_addresses(IHS_Client *client, uint64_t id, IHS_IPAddress **out, void *ctx) {
    (void)client;
    sl_runtime *r = ctx;
    *out = NULL;
    pthread_mutex_lock(&r->lock);
    const sl_directory_host *host = sl_directory_find(r->directory, id);
    size_t count = host ? host->addresses.count : 0;
    IHS_IPAddress *ips = count ? malloc(count * sizeof(*ips)) : NULL;
    if (ips)
        for (size_t i = 0; i < count; ++i)
            ips[i] = host->addresses.entries[i].address.ip;
    pthread_mutex_unlock(&r->lock);
    *out = ips;
    return ips ? count : 0;
}
static void clear_control_locked(sl_runtime *r) {
    while (r->control_head) {
        sl_control_frame *frame = r->control_head;
        r->control_head = frame->next;
#if NSL_DIAGNOSTICS
        ++r->control_diag.stale;
#endif
        memset(frame->wire, 0, frame->size);
        free(frame);
    }
    r->control_tail = NULL;
    r->control_count = r->control_bytes = 0;
}
static bool control_remote_send(IHS_Client *client, uint64_t id, const uint8_t *wire, size_t size,
                                void *ctx) {
    (void)client;
    sl_runtime *r = ctx;
    /* Local copied-frame budget, not a Steam message/retry limit. Producers
     * retain the transaction and can retry; existing frames are never replaced. */
    if (size > 65536) {
#if NSL_DIAGNOSTICS
        pthread_mutex_lock(&r->lock);
        ++r->control_diag.rejected;
        r->control_diag.reject_reason = 3;
        pthread_mutex_unlock(&r->lock);
#endif
        return false;
    }
    pthread_mutex_lock(&r->lock);
    uint64_t account = 0;
    const sl_directory_host *peer = sl_directory_find(r->directory, id);
    bool have_account = peer && peer->accounts.count;
    if (have_account) account = peer->accounts.ids[0];
    sl_control_frame *frame = r->control_cloud_ready && have_account && r->control_count < 64 &&
                                      size <= 256 * 1024 - r->control_bytes
                                  ? malloc(sizeof(*frame) + size)
                                  : NULL;
    if (frame) {
        *frame = (sl_control_frame){.epoch = r->control_epoch, .account = account, .size = size};
        memcpy(frame->wire, wire, size);
        if (r->control_tail)
            r->control_tail->next = frame;
        else
            r->control_head = frame;
        r->control_tail = frame;
        ++r->control_count;
        r->control_bytes += size;
        pthread_cond_signal(&r->wake);
    }
    bool accepted = frame != NULL;
#if NSL_DIAGNOSTICS
    if (accepted) ++r->control_diag.queued;
    else {
        ++r->control_diag.rejected;
        r->control_diag.reject_reason = !r->control_cloud_ready ? 1 : !have_account ? 2
            : r->control_count >= 64 || size > 256 * 1024 - r->control_bytes ? 3 : 4;
    }
#endif
    pthread_mutex_unlock(&r->lock);
    return accepted;
}
static void flush_control(sl_runtime *r) {
    for (;;) {
        pthread_mutex_lock(&r->lock);
        sl_control_frame *frame = r->control_head;
        bool send = frame && r->control_cloud_ready && frame->epoch == r->control_epoch;
        if (frame) {
            r->control_head = frame->next;
            if (!r->control_head)
                r->control_tail = NULL;
            --r->control_count;
            r->control_bytes -= frame->size;
        }
        pthread_mutex_unlock(&r->lock);
        if (!frame)
            return;
        bool forwarded = send && r->remote &&
            sl_remote_packet(sl_remote_connection_protocol(r->remote), frame->account, frame->wire,
                             frame->size);
#if NSL_DIAGNOSTICS
        pthread_mutex_lock(&r->lock);
        if (forwarded) ++r->control_diag.forwarded;
        else if (send && r->remote) ++r->control_diag.failed;
        else ++r->control_diag.stale;
        pthread_mutex_unlock(&r->lock);
#else
        (void)forwarded;
#endif
        memset(frame->wire, 0, frame->size);
        free(frame);
    }
}
static void control_request_failed(IHS_Client *client, IHS_ClientRequestFailure error, void *ctx) {
    (void)client;
    sl_runtime *r = ctx;
    diagnostic_phase("request_local_failure", error);
    pthread_mutex_lock(&r->lock);
    r->request_terminal = true;
    pthread_mutex_unlock(&r->lock);
    fail_control(r, sl_tr(error == IHS_ClientRequestFailureUnavailable ? SL_T_HOST_OFFLINE
                                                                       : SL_T_CANNOT_CONNECT));
}
static const IHS_ClientRoutingCallbacks control_cb = {.host = control_host,
                                                      .resolve = control_resolve,
                                                      .addresses = control_addresses,
                                                      .sendRemote = control_remote_send,
                                                      .requestFailed = control_request_failed};
static void cloud_disconnecting(void *ctx) {
    sl_runtime *r = ctx;
    pthread_mutex_lock(&r->lock);
    sl_directory_disconnect(r->directory);
    pthread_mutex_unlock(&r->lock);
}
static void cloud_connected(bool connected, void *ctx) {
    sl_runtime *r = ctx;
    pthread_mutex_lock(&r->lock);
    ++r->control_epoch;
    r->control_cloud_ready = connected;
    clear_control_locked(r);
    if (!connected) {
        sl_directory_disconnect(r->directory);
    }
    pthread_mutex_unlock(&r->lock);
    sl_log(connected ? "cloud: anonymous session connected" : "cloud: disconnected");
}
static void cloud_diagnostic(const char *message, void *ctx) {
    (void)ctx;
    sl_log(message);
}
static void cloud_code(const char *pin, void *ctx) {
    sl_runtime *r = ctx;
    if (r->active.type != SL_CMD_REMOTE_PAIR)
        return;
    sl_runtime_event event = {.type = SL_EVENT_CODE};
    snprintf(event.text, sizeof(event.text), "%.4s", pin);
    post(r, event);
}
static bool cloud_save_key(const sl_remote_peer *peer, void *ctx) {
    sl_runtime *r = ctx;
    /* The shared IHS owner already admitted metadata before crypto. Do not
     * perform this operation again here: absent steamid must remain absent. */
    bool key_saved =
        sl_host_key_save(sl_system_data_dir(), peer->client_id, peer->steam_id, peer->secret);
    save_paired_account(r, peer->steam_id);
    if (!key_saved)
        sl_log("pair: service identity key save failed; authorization continues");
    sl_host *h = saved_host(r, peer->client_id);
    if (!h) {
        if (r->store.registry.count == SL_HOST_LIMIT)
            return false;
        h = &r->store.registry.hosts[r->store.registry.count++];
        *h = (sl_host){.id = r->store.registry.next_id++, .client_id = peer->client_id};
        snprintf(h->name, sizeof(h->name), "Steam");
        if (r->store.registry.selected < 0)
            r->store.registry.selected = (int)(h - r->store.registry.hosts);
    }
    if (h->account != peer->steam_id)
        memset(h->games, 0, sizeof(h->games));
    h->account = peer->steam_id;
    h->paired = h->has_secret = true;
    memcpy(h->secret, peer->secret, 32);
    if (!sl_auth_save(&r->store, sl_system_data_dir()))
        sl_log("pair: service profile save failed; authorization continues");
    pthread_mutex_lock(&r->lock);
    ++r->credential_revision;
    r->active.host = *h;
    r->auth_persist_attempted = true;
    pthread_mutex_unlock(&r->lock);
    post(r, (sl_runtime_event){.type = SL_EVENT_KEY_UPDATED, .host = *h});
    return true;
}
static void cloud_paired(const sl_remote_peer *peer, void *ctx) {
    sl_runtime *r = ctx;
    sl_host *h = saved_host(r, peer->client_id);
    if (h && r->active.type == SL_CMD_REMOTE_PAIR)
        post(r, (sl_runtime_event){.type = SL_EVENT_AUTHORIZED, .host = *h, .account = h->account});
    else if (r->active.type == SL_CMD_REMOTE_PAIR)
        fail(r, sl_tr(SL_T_SAVE_SETTINGS_FAILED));
    r->request_at = 0;
}
static void cloud_pair_failed(IHS_AuthorizationResult result, void *ctx) {
    sl_runtime *r = ctx;
    if (r->client) {
        r->request_at = 0;
        r->service_unavailable = result == IHS_AuthorizationOffline;
        IHS_ClientHandshakeFail(r->client, result);
        r->service_unavailable = false;
    }
}
static bool cloud_begin_pairing(void *ctx) {
    sl_runtime *r = ctx;
    return r->client && IHS_ClientAuthorizationAwaitService(r->client);
}
static bool cloud_prepare_pairing(IHS_SteamUniverse universe, const char *pin, uint8_t **body,
                                  size_t *size, void *ctx) {
    sl_runtime *r = ctx;
    return r->client && r->active.type == SL_CMD_REMOTE_PAIR &&
           IHS_ClientAuthorizationPrepareService(r->client, universe, pin, body, size);
}
static void cloud_abort_pairing(void *ctx) {
    sl_runtime *r = ctx;
    if (r->client && IHS_ClientAuthorizationServiceActive(r->client))
        IHS_ClientAuthorizationCancel(r->client);
}
static void cloud_observed(const sl_remote_host *host, void *ctx) {
    sl_runtime *r = ctx;
    IHS_DiscoveryAddressHints hints = {.publicAddress = host->public_address,
        .addresses = host->addresses, .addressCount = host->address_count,
        .steamIds = host->steam_ids, .steamIdCount = host->steam_id_count};
    pthread_mutex_lock(&r->lock);
    bool accepted = sl_directory_status(&r->directory, &host->info, &hints, true, NULL,
                                         (int64_t)time(NULL));
    if (accepted) {
        observe_launch_status_locked(r, &host->info, true);
        publish_host_locked(r, sl_directory_find(r->directory, host->info.clientId));
    }
    pthread_mutex_unlock(&r->lock);
#if NSL_DIAGNOSTICS
    char line[224];
    snprintf(line, sizeof(line), "cloud_host event=online addresses=%zu accepted=%d games_present=%d running=%d timestamp=%d stamp=%u",
             host->address_count, accepted, host->info.hasGamesRunning, host->info.gamesRunning,
             host->info.hasTimestamp, host->info.timestamp);
    sl_log(line);
#endif
}
static void cloud_offline(uint64_t id, void *ctx) {
    sl_runtime *r = ctx;
    pthread_mutex_lock(&r->lock);
    bool removed = sl_directory_offline(r->directory, id);
    if (removed)
        post_locked(r, (sl_runtime_event){.type = SL_EVENT_HOST_OFFLINE, .host = {.client_id = id}});
    pthread_mutex_unlock(&r->lock);
    sl_log("cloud_host event=offline");
}
static void discovery_offline(IHS_Client *client, uint64_t id, void *ctx) {
    (void)client;
    cloud_offline(id, ctx); /* Same parsed type2 presence semantics; no key/address deletion. */
}
static void refresh_presence(sl_runtime *r, uint64_t now, int64_t wall) {
    bool publish = now-r->cloud_refresh >= 5000;
    if (publish) r->cloud_refresh = now;
    pthread_mutex_lock(&r->lock);
    for (sl_directory_host *h = r->directory; h; h = h->next) {
        if (sl_directory_expired(h, wall)) {
            h->visible = false;
            post_locked(r, (sl_runtime_event){.type = SL_EVENT_HOST_OFFLINE,
                                              .host = {.client_id = h->client_id}});
        } else if (h->visible && publish) publish_host_locked(r, h);
    }
    pthread_mutex_unlock(&r->lock);
}
typedef struct {
    sl_runtime *runtime;
    uint64_t now;
} control_update;
static void update_control_session(void *ctx) {
    control_update *update = ctx;
    sl_remote_connection_update(update->runtime->remote, update->now);
}
static void update_control_expiry(void *ctx) {
    control_update *update = ctx;
    refresh_presence(update->runtime, update->now, (int64_t)time(NULL));
}
static void update_control(sl_runtime *r, uint64_t now) {
    /* The original main-thread ticket consumer is inside Test::Start/Join at
     * this boundary. Resume manager Update only after replacement/cancel. */
    if (!r->client || r->test_retry_ticket) return;
    flush_control(r);
    if (now < r->control_next_update) return;
    r->control_next_update = now + 100;
    control_update update = {.runtime = r, .now = now};
#if NSL_DIAGNOSTICS
    uint64_t began = sl_system_now();
#endif
    IHS_ClientUpdate(r->client, update_control_session, update_control_expiry, &update);
    flush_control(r);
#if NSL_DIAGNOSTICS
    uint64_t ended = sl_system_now();
    if (ended-began >= 250 && ended-r->cloud_stall_at >= 1000) {
        r->cloud_stall_at = ended;
        char line[96];
        snprintf(line, sizeof(line), "cloud_update stall_ms=%llu", (unsigned long long)(ended-began));
        sl_log(line);
    }
#endif
}
static void cloud_stream_result(IHS_StreamingResult result, const sl_remote_material *m,
                                void *ctx) {
    (void)m; /* The SDL/native-only build has no SNS transport constructor. */
    sl_runtime *r = ctx;
    if (r->active.type != SL_CMD_STREAM)
        return;
    diagnostic_phase("stream_transport_result", result);
    if (result != IHS_StreamingSuccess) {
        rejected(NULL, NULL, result, ctx);
        return;
    }
#if NSL_HAVE_SNS
    if (m->transport == k_EStreamTransportSDR) {
        if (r->sns || m->key_size > sizeof(r->session_info.sessionKey)) {
            rejected(NULL, NULL, IHS_StreamingFailed, ctx);
            return;
        }
        char error[1024];
        size_t config_size = 0;
        const char *config = sl_sns_config_cache_data(r->sns_config, &config_size);
        r->sns = sl_sns_create_configured(&r->config, m, true, error, sizeof(error), config, config_size);
        memset(error, 0, sizeof(error)); /* SDK text may include an identity. */
        if (!r->sns) {
            if (r->test_active) {
                fail_network_test(r);
                return;
            }
            rejected(NULL, NULL, IHS_StreamingTransportUnavailable, ctx);
            return;
        }
        r->session_info = (IHS_SessionInfo){.steamId = m->steam_id, .sessionKeyLen = m->key_size};
        memcpy(r->session_info.sessionKey, m->key, m->key_size);
        /* Logical endpoint is stable across ICE/SDR route changes. The external
         * provider never uses it as a physical UDP destination. */
        IHS_IPAddressFromString(&r->session_info.address.ip, "127.0.0.1");
        r->sns_info = r->session_info;
        r->sns_waiting = true;
        return;
    }
#endif
    rejected(NULL, NULL, IHS_StreamingTransportUnavailable, ctx);
}
static void accepted_connection(IHS_Client *client, const IHS_HostInfo *host,
                                const IHS_StreamingConnection *connection, void *ctx) {
    sl_runtime *r = ctx;
    /* Once the ticket has been consumed, replies may update manager state but
     * must not create a second media/backend owner. Before consumption, later
     * successful replies in this same Update replace the pending material. */
    if (r->session || (!r->test_retry_pending && (r->test_session
#if NSL_HAVE_SNS
        || r->sns
#endif
    ))) return;
    uint64_t account = 0;
    current_account(r, connection->clientId, &account);
    if (connection->transport == k_EStreamTransportUDP &&
        IHS_ClientAddressHasIP(&connection->address.ip) && connection->address.port) {
        accept_session(r, &connection->address, connection->sessionKey, connection->sessionKeyLen,
                       account);
        return;
    }
    sl_remote_material material = {.client_id = connection->clientId,
                                   .steam_id = account,
                                   .transport = connection->transport,
                                   .port = (uint16_t)connection->port,
                                   .key_size = connection->sessionKeyLen,
                                   .cert = connection->certificate,
                                   .stun_servers = connection->relayServer};
    if (material.key_size > sizeof(material.key)) {
        rejected(client, host, IHS_StreamingFailed, ctx);
        return;
    }
    memcpy(material.key, connection->sessionKey, material.key_size);
    sl_remote_material *owned = malloc(sizeof(*owned));
    if (owned) {
        *owned = material;
        owned->cert = material.cert ? strdup(material.cert) : NULL;
        owned->stun_servers = material.stun_servers ? strdup(material.stun_servers) : NULL;
        if ((material.cert && !owned->cert) || (material.stun_servers && !owned->stun_servers)) {
            free_session_material(owned);
            owned = NULL;
        }
    }
    if (owned) {
        pthread_mutex_lock(&r->lock);
        free_session_material(r->session_material);
        r->session_material = owned;
        r->session_ready = true;
        pthread_mutex_unlock(&r->lock);
    } else
        rejected(client, host, IHS_StreamingFailed, ctx); /* Local allocation guard. */
    memset(&material, 0, sizeof(material));
}
static bool consume_session_material(sl_runtime *r) {
    sl_remote_material *material = r->session_material;
    if (!material) return false;
    r->session_material = NULL;
    cloud_stream_result(IHS_StreamingSuccess, material, r);
    free_session_material(material);
    return true;
}
static bool cloud_control_packet(const uint8_t *wire, size_t size, void *ctx) {
    sl_runtime *r = ctx;
    /* All authorization, including unknown-host service pairing, enters the
     * shared manager cache/current secret. CM is already on this actor: finish
     * the control frame before the next RPC response can observe its state. */
    if (!r->client)
        return false;
#if NSL_DIAGNOSTICS
    /* Observe only numeric control metadata. The real IHS parser still decides
     * admission; these counters do not claim that a reply matched its owner. */
    uint32_t hs = 0, ms = 0;
    unsigned tag = 0, id = 0;
    int result = -1;
    if (size >= 16) IHS_ReadUInt32LE(wire + 8, &hs);
    if (size >= 16 && hs <= size - 16) {
        IHS_ReadUInt32LE(wire + 12 + hs, &ms);
        sl_proto_reader header = {wire + 12, hs, 0, false};
        sl_proto_field f;
        while (sl_proto_next(&header, &f))
            if (f.number == 2 && f.wire == 0 && f.value <= UINT32_MAX) tag = (unsigned)f.value;
        if (ms == size - 16 - hs) {
            sl_proto_reader body = {wire + 16 + hs, ms, 0, false};
            while (sl_proto_next(&body, &f)) {
                if (tag == k_ERemoteDeviceStreamingResponse && f.wire == 0) {
                    if (f.number == 1 && f.value <= UINT32_MAX) id = (unsigned)f.value;
                    if (f.number == 2 && f.value <= INT32_MAX) result = (int)f.value;
                } else if (tag == k_ERemoteDeviceAuthorizationResponse && f.number == 1 &&
                           f.wire == 0 && f.value <= INT32_MAX) result = (int)f.value;
            }
        }
    }
    pthread_mutex_lock(&r->lock);
    ++r->control_diag.received;
    r->control_diag.received_tag = tag;
    r->control_diag.received_id = id;
    r->control_diag.received_result = result;
    pthread_mutex_unlock(&r->lock);
#endif
    IHS_ClientReceiveRemotePacket(r->client, wire, size);
    return true;
}
static void start_cloud(sl_runtime *r) {
    const sl_remote_callbacks cb = {.diagnostic = cloud_diagnostic,
                                    .connected = cloud_connected,
                                    .disconnecting = cloud_disconnecting,
                                    .host = cloud_observed,
                                    .offline = cloud_offline,
                                    .pair_code = cloud_code,
                                    .begin_pairing = cloud_begin_pairing,
                                    .prepare_pairing = cloud_prepare_pairing,
                                    .abort_pairing = cloud_abort_pairing,
                                    .save_key = cloud_save_key,
                                    .paired = cloud_paired,
                                    .pair_failed = cloud_pair_failed,
                                    .control_packet = cloud_control_packet};
    r->remote = sl_remote_connection_create(&r->config, &cb, r);
    cloud_watch(r);
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
    r->discovery_subscription = false;
    r->discovery_target_count = 0;
    r->discovery_id_count = 0;
    free(r->discovery_targets);
    r->discovery_targets = NULL;
}
static bool start_client(sl_runtime *r) {
    initialize_accounts(r);
    sl_log("discovery: creating IHS client");
    r->client = IHS_ClientCreatePolled(&r->config);
    if (!r->client)
        return false;
    IHS_ClientSetAuthorizationDeferred(r->client, true);
    IHS_ClientSetLogFunction(r->client, ihs_log);
    IHS_ClientSetDiscoveryCallbacks(r->client, &discovery_cb, r);
    IHS_ClientSetAuthorizationCallbacks(r->client, &auth_cb, r);
    IHS_ClientSetStreamingCallbacks(r->client, &stream_cb, r);
    IHS_ClientSetRoutingCallbacks(r->client, &control_cb, r);
    sl_log("discovery: client created; registering periodic broadcast");
    bool started = sync_discovery_targets(r) && start_discovery(r);
    sl_log(started ? "discovery: periodic broadcast registered" : "discovery: registration failed");
    if (!started) stop_client(r);
    r->control_next_update = 0;
    return started;
}
/* Return completion observed before/during join, before destroying its owner. */
static bool stop_session(sl_runtime *r) {
    if (r->session || r->request_at)
        diagnostic_state(r, "stop_begin");
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
        diagnostic_state(r, "ihs_joined");
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
#if NSL_HAVE_SNS
    /* Worker producers have joined. Flush their final queued goodbye before
     * closing the SDK handle; callbacks remain nonblocking throughout join. */
    if (r->sns) sl_sns_update(r->sns, sl_system_now());
    sl_sns_destroy(r->sns);
    r->sns = NULL;
    r->sns_waiting = false;
    memset(&r->sns_info, 0, sizeof(r->sns_info));
#endif
    pthread_mutex_lock(&r->lock);
    host_completed = host_completed || (r->end_game.at && r->end_game.empty >= 2);
    r->end_game = (sl_end_game_watch){0};
    r->connected = r->finished = r->host_stopped = r->session_ready = false;
    free_session_material(r->session_material);
    r->session_material = NULL;
    r->facts.connected = false;
    r->facts.test_failure_pending = false;
    r->facts.requests_closed = true;
    r->facts.protocol_closed = true;
    pthread_mutex_unlock(&r->lock);
    r->first_reported = false;
    r->request_at = 0;
    diagnostic_phase("stop_complete", host_completed);
    return host_completed;
}
static bool launch_session(sl_runtime *r, IHS_SessionInfo info) {
#if NSL_HAVE_SNS
    atomic_store(&r->session_finalized, false);
#endif
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
    if (!sl_stream_settings_apply_limited(&r->settings, r->session, &r->stream_limits)) {
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
#if NSL_HAVE_SNS
    if (r->sns && !IHS_SessionSetDatagramTransport(r->session, sl_sns_datagram_transport(), r->sns))
        return false;
#endif
    if (!IHS_SessionConnect(r->session))
        return false;
    diagnostic_state(r, "ihs_connect_started");
    r->connect_wait_tick = sl_connection_wait_tick(sl_system_now());
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
    if (!r->client) return false;
    if (!control_host(r->client, r->active.host.client_id, &host, r))
        return false;
    if (!pause_discovery(r)) return false;
    const sl_host *paired = sl_host_find(&r->store.registry, r->active.host.id);
    uint8_t selected[32];
    uint64_t key_account = 0;
    bool selected_account = current_account(r, host.clientId, &key_account);
    (void)selected_account;
    int loaded = sl_host_key_load(sl_system_data_dir(), host.clientId, key_account, selected);
#if NSL_DIAGNOSTICS
    char identity_line[160];
    snprintf(identity_line, sizeof(identity_line),
             "control_identity account_present=%d selected_zero=%d paired_match=%d key_file=%d",
             selected_account, key_account == 0, paired && paired->account == key_account, loaded);
    sl_log(identity_line);
#endif
    if (loaded < 0)
        return false;
    if (loaded > 0)
        memcpy(selected, paired && paired->account == key_account && paired->has_secret
                             ? paired->secret : r->store.secret, sizeof(selected));
    IHS_ClientSetSecretKey(r->client, selected);
    memset(selected, 0, sizeof(selected));
    const CStreamingClientConfig *config = r->settings.config;
    /* Freeze one selection through this ticket and its subsequent handshake. */
    if (!network_test) {
        unsigned height = sl_resolution_height(r->resolution, sl_system_docked());
        r->stream_limits = (sl_stream_request_limits){
            .width = height * 16 / 9, .height = height, .fps = 60, .force_resolution = true};
        char line[128];
        snprintf(line, sizeof(line), "video request: %ux%u fps<=60 H264 selection=%u test_force=%d",
                 r->stream_limits.width, r->stream_limits.height, (unsigned)r->resolution,
                 NSL_TEST_FORCE_1080);
        sl_log(line);
    }
    IHS_StreamingRequest req = {
        .networkTest = network_test,
        .keySteamId = key_account,
        .allowSDR = NSL_HAVE_SNS,
        .streamingEnable = {config->enable_video_streaming, config->enable_audio_streaming,
                            config->enable_input_streaming},
        .maxResolution = {network_test ? 1280 : r->stream_limits.width,
                          network_test ? 720 : r->stream_limits.height},
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
#if NSL_DIAGNOSTICS
    r->frame_at = sl_system_now();
#endif
    if (!network_test) {
        pthread_mutex_lock(&r->lock);
        r->launch = (sl_launch_watch){.target = r->active.game_id};
        if (!r->request_pending && !atomic_load(&r->exit_requested))
            sl_media_allow_video();
        pthread_mutex_unlock(&r->lock);
    }
    diagnostic_phase("selected_control_owner", 0);
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
#if NSL_HAVE_SNS
    if (r->sns && !IHS_SessionSetDatagramTransport(r->test_session, sl_sns_datagram_transport(), r->sns))
        return false;
#endif
    IHS_SessionSetLogFunction(r->test_session, ihs_log);
    if (!IHS_SessionConnect(r->test_session))
        return false;
    if (!r->test_waiting_pin && !r->test_retry_pending) {
        /* A delayed old SDK may start during authorization or while awaiting
         * the replacement ticket. Only the control parser can accept it. */
        r->request_at = 0;
        publish_test(r, (sl_network_test_view){.phase = SL_TEST_RUNNING,
                                           .target_kbps = target,
                                           .bandwidth_test = mode == IHS_NetworkTestBandwidth});
    }
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
    if (!r->test_session || r->test_joined || r->test_waiting_pin || test_error_pending(r))
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
    /* A control callback can replace the result after the UI produced this
     * action. Hiding the original dialog does not emit finished (D-A092). */
    if (!r->test_active || !r->test_session || !r->test_joined ||
        cmd->generation != r->active.generation || r->test_waiting_pin || test_error_pending(r))
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
         * preset remains distinct from the selected resolution/H264 request limits. */
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
        start_discovery(r);
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
    bool retry_test = cmd.type == SL_CMD_STREAM && cmd.security_pin_retry &&
                      r->test_active && r->test_waiting_pin &&
                      cmd.generation == r->active.generation &&
                      cmd.host.client_id == r->active.host.client_id;
    /* Cancel/join each request before changing its callback generation. Keep the
     * client socket alive so canceled launch IDs can reject late host responses. */
    if (r->remote)
        sl_remote_cancel(sl_remote_connection_protocol(r->remote));
    if (r->client) {
        IHS_ClientStreamingCancel(r->client);
        IHS_ClientAuthorizationCancel(r->client);
    }
    if (retry_test) {
        r->test_retry_pending = true;
        r->test_retry_ticket = false;
        free_session_material(r->session_material);
        r->session_material = NULL;
    } else
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
    start_discovery(r);
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
    if (cmd.type == SL_CMD_REMOTE_PAIR) {
        if (!r->remote || !sl_remote_pair(sl_remote_connection_protocol(r->remote)))
            fail(r, sl_tr(SL_T_CLOUD_UNAVAILABLE));
        return;
    }
    IHS_HostInfo h;
    bool have_address = host_info(r, &cmd.host, &h);
    if (cmd.type == SL_CMD_STREAM)
        have_address = control_host(r->client, cmd.host.client_id, &h, r);
    if (!have_address) {
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
        if (!retry_test) {
            bool readable = !cmd.test_only && sl_network_stats_load(sl_system_data_dir(), NULL);
            unsigned action = sl_network_stats_connect_action(
                cmd.test_only ? 2 : 0, r->settings.config->enable_video_streaming, readable);
            r->test_active = action != 0;
        }
        if (r->test_active)
            publish_test(r, (sl_network_test_view){.phase = SL_TEST_REQUESTING});
        if (!request_stream(r, r->test_active))
            fail(r, sl_tr(SL_T_REQUEST_STREAM_FAILED));
    }
}
static void sample(sl_runtime *r, uint64_t now) {
    if (r->session || r->request_at)
        diagnostic_state(r, "sample");
    stream_media_snapshot s;
    stream_media_get_snapshot(&s);
#if NSL_DIAGNOSTICS
    if (s.displayed_frames != r->previous.displayed_frames) r->frame_at = now;
#endif
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
                 "OK session=%d displayed=%u debug=%s fps=%s hid=%s ackMax=%s logs_port=%u",
                 r->session != NULL, r->debug.frames, r->debug.title, r->debug.values[0],
                 r->debug.values[4], r->debug.values[5], sl_log_http_port());
    } else if (!strcmp(cmd, "cloud")) {
        char connection[192];
        sl_remote_connection_describe(r->remote, sl_system_now(), connection, sizeof(connection));
        unsigned eligible = 0;
        for (int i = 0; i < r->store.registry.count; ++i) {
            sl_host *h = &r->store.registry.hosts[i];
            eligible += h->paired && h->account && h->client_id;
        }
        size_t online = 0;
        pthread_mutex_lock(&r->lock);
        for (sl_directory_host *h = r->directory; h; h = h->next) online += h->cloud;
        pthread_mutex_unlock(&r->lock);
        snprintf(reply, sizeof(reply), "OK %s saved=%d eligible=%u online=%zu", connection,
                 r->store.registry.count, eligible, online);
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
        if (!sl_log_copy_tail(reply, sizeof(reply), strstr(cmd, "prev") != NULL))
            strcpy(reply, "ERR diagnostic log unavailable or busy");
    } else if (!strcmp(cmd, "hid-history") || !strncmp(cmd, "hidlog", 6)) {
        stream_media_format_hid_history(reply, sizeof(reply), 16);
    } else {
        snprintf(reply, sizeof(reply),
                 "ERR supported: ping state stats perf cloud audio hid hidlog diag [current|prev]");
    }
    sendto(r->udp, reply, strlen(reply), MSG_DONTWAIT, (struct sockaddr *)&peer, len);
}
#endif
static void *worker_main(void *ctx) {
    sl_runtime *r = ctx;
    sl_log("runtime: worker entered; initializing IHS");
    sl_auth_discovery_hint(&r->store, sl_system_data_dir(), r->discovery_hint, sizeof(r->discovery_hint));
    uint32_t launch_probe_seq = 0;
    IHS_Init();
    sl_log("runtime: IHS initialized");
    if (sl_stream_settings_load(&r->settings, sl_system_data_dir()) < 0)
        sl_log("settings: load failed, retaining the previous complete value");
    sync_stream_settings(r, true);
    if (!start_client(r))
        fail(r, sl_tr(SL_T_NETWORK_UNAVAILABLE));
    start_cloud(r);
#if NSL_HAVE_SNS
    r->sns_config = sl_sns_config_cache_create(sl_system_data_dir());
#endif
    while (!r->quit) {
        if (r->waiting_video) {
            if (!sl_media_video_clean()) {
                update_control(r, sl_system_now());
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
        update_control(r, sl_system_now());
        flush_accounts(r);
        sl_command cmd = {0};
        sl_auth_store save;
        bool save_pending, snapshot_pending;
        uint64_t snapshot_credentials = 0;
        sl_language save_language;
        bool save_update_check;
        sl_resolution save_resolution;
        pthread_mutex_lock(&r->lock);
        if (r->request_pending) {
            cmd = r->pending;
            r->request_pending = false;
        }
        save_pending = r->save_pending;
        save_language = r->save_language;
        save_update_check = r->save_update_check;
        save_resolution = r->save_resolution;
        snapshot_pending = r->snapshot_pending;
        if (snapshot_pending) {
            save = r->save;
            snapshot_credentials = r->save_credential_revision;
            r->snapshot_pending = false;
        }
        r->save_pending = false;
        bool terminal = r->request_terminal;
        if (terminal) {
            r->request_at = 0;
            r->request_terminal = false;
        }
        bool ready = !terminal && r->session_ready;
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
        if (terminal && (test_error_pending(r) || r->test_waiting_pin || r->test_retry_pending)) {
            /* Revoke unconsumed material without closing the active Test owner
             * or dismissing its error. Confirmation owns the later cleanup. */
            free_session_material(r->session_material);
            r->session_material = NULL;
            r->test_retry_ticket = false;
        } else if (terminal && !r->session && !r->test_session)
            stop_session(r); /* Error wins over unconsumed/pending backend work. */
        if (snapshot_pending) {
            /* A UI snapshot queued before authorization completed must not
             * undo the just-accepted host facts. An explicitly removed host
             * stays absent; the actor will honor its queued command below. */
            if (r->auth_persist_attempted) {
                const sl_host *known = sl_host_find(&r->store.registry, r->active.host.id);
                sl_host *incoming = sl_host_find(&save.registry, r->active.host.id);
                if (!incoming && known && r->active.type == SL_CMD_REMOTE_PAIR &&
                    snapshot_credentials < r->credential_revision &&
                    save.registry.count < SL_HOST_LIMIT) {
                    incoming = &save.registry.hosts[save.registry.count++];
                    *incoming = *known;
                    if (save.registry.next_id <= known->id)
                        save.registry.next_id = known->id + 1;
                }
                if (known && incoming && known->client_id == incoming->client_id) {
                    incoming->paired = known->paired;
                    incoming->account = known->account;
                    incoming->has_secret = known->has_secret;
                    memcpy(incoming->secret, known->secret, sizeof(incoming->secret));
                }
            }
            sl_host_registry_keep_secrets(&save.registry, &r->store.registry);
            r->store = save;
            cloud_watch(r);
        }
        if (r->client) sync_discovery_targets(r);
        sync_stream_settings(r, snapshot_pending);
        if (save_pending) {
            r->resolution = save_resolution;
            bool profile_saved = sl_auth_save(&r->store, sl_system_data_dir());
            bool language_saved = sl_i18n_save(sl_system_data_dir(), save_language);
            bool update_saved = sl_update_config_save(sl_system_data_dir(), save_update_check);
            bool video_saved = sl_video_settings_save(sl_system_data_dir(), save_resolution);
            if (!profile_saved || !language_saved || !update_saved || !video_saved)
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
        if (ready && r->test_retry_pending)
            r->test_retry_ticket = true;
        ready = ready || r->test_retry_ticket;
        if (ready && r->test_retry_ticket && !finish_test_retry(r))
            ready = false;
        if (ready && !r->session && !r->test_session) {
            /* Ordinary Qt launch destroys its old manager before player BInit,
             * without a StreamingCancel. Keep our discovery-only use, but
             * retire the old handshake before SDK/media construction. The
             * dedicated NetworkTest retains its state6 owner in the original. */
            if (!r->test_active && !IHS_ClientStreamingHandoff(r->client)) {
                stop_session(r);
                fail(r, sl_tr(SL_T_SESSION_FAILED));
                continue;
            }
            if (!consume_session_material(r)) {
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
        }
        if (conn && r->session) {
            stream_media_set_hid_session(r->session, true);
            IHS_SessionHIDNotifyDeviceChange(r->session);
        }
        if (finished && r->session) {
            bool had_video = r->first_reported;
            bool normal = (stop_session(r) || host_stopped) && had_video;
            post(r, (sl_runtime_event){.type = SL_EVENT_STOPPED, .account = normal ? 0 : 1});
            start_discovery(r);
        }
        uint64_t now = sl_system_now();
#if NSL_HAVE_SNS
        sl_sns_config_cache_update(r->sns_config);
        if (r->sns) {
            bool pending_test_error = test_error_pending(r);
            /* An explicit startup config may make BInit ready synchronously.
             * Start IHS/its deadline before the first SDK Update in that case,
             * just as for config completed asynchronously during this pass. */
            if (pending_test_error || !r->sns_waiting || !sl_sns_session_ready(r->sns))
                sl_sns_update(r->sns, now);
            sl_sns_state state = sl_sns_get_state(r->sns);
            if (pending_test_error || r->test_waiting_pin) {
                /* The old Test worker may still be inside BInit when PIN is
                 * requested. Finish its own startup using frozen old material,
                 * without marking the new request Established or taking UI. */
                if (r->test_waiting_pin && r->sns_waiting) {
                    if (sl_sns_session_ready(r->sns)) {
                        r->sns_waiting = false;
                        r->test_startup_failed = !launch_network_test(r, r->sns_info);
                    } else if (state == SL_SNS_FAILED || state == SL_SNS_CLOSED) {
                        r->sns_waiting = false;
                        r->test_startup_failed = true;
                    }
                }
            } else if (r->sns_waiting && sl_sns_session_ready(r->sns)) {
                r->sns_waiting = false;
                if (!(r->test_active ? launch_network_test(r, r->sns_info)
                                     : launch_session(r, r->sns_info))) {
                    if (r->test_active)
                        fail_network_test(r);
                    else {
                        stop_session(r);
                        fail(r, sl_tr(SL_T_SESSION_FAILED));
                    }
                }
            } else if (state == SL_SNS_FAILED || state == SL_SNS_CLOSED) {
                if (r->test_active)
                    fail_network_test(r);
                else {
                    stop_session(r);
                    fail(r, sl_tr(SL_T_CANNOT_CONNECT));
                }
            }
        }
#endif
        sample_network_test(r, now);
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
                start_discovery(r);
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
            start_discovery(r);
            continue;
        }
        if (probe_launch) {
            IHS_HostInfo host;
            if (host_info(r, &r->active.host, &host)) {
                CMsgRemoteClientBroadcastDiscovery probe =
                    CMSG_REMOTE_CLIENT_BROADCAST_DISCOVERY__INIT;
                probe.has_seq_num = true;
                probe.seq_num = ++launch_probe_seq;
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
            t.tv_nsec +=
#if NSL_HAVE_SNS
                r->sns ? 1000000 :
#endif
                       20000000;
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
    flush_control(r); /* Producers joined; no later frame can outlive CM. */
    sl_log("cleanup: cloud connection close");
    sl_remote_connection_destroy(r->remote);
    r->remote = NULL;
#if NSL_HAVE_SNS
    sl_sns_config_cache_destroy(r->sns_config);
    r->sns_config = NULL;
#endif
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
    r->resolution = sl_video_settings_load(sl_system_data_dir());
    r->udp = -1;
    atomic_init(&r->exit_requested, false);
#if NSL_HAVE_SNS
    atomic_init(&r->session_finalized, false);
#endif
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
                                   .deviceName = r->store.device_name,
#ifdef __SWITCH__
                                   .deviceModel = "Nintendo Switch"
#else
                                   .deviceModel = "NSteamLink"
#endif
    };
    r->provider = stream_media_create_hid_provider();
#if NSL_DIAGNOSTICS
    r->udp = socket(AF_INET, SOCK_DGRAM, 0);
#ifdef __SWITCH__
    if (r->udp >= 0 && !sl_control_udp_buffers(r->udp)) {
        int saved = errno;
        close(r->udp);
        r->udp = -1;
        errno = saved;
    }
#endif
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
#ifdef __SWITCH__
    if (r->udp >= 0) {
        int rx = 0, tx = 0;
        socklen_t size = sizeof(rx);
        bool rx_ok = getsockopt(r->udp, SOL_SOCKET, SO_RCVBUF, &rx, &size) == 0;
        size = sizeof(tx);
        bool tx_ok = getsockopt(r->udp, SOL_SOCKET, SO_SNDBUF, &tx, &size) == 0;
        snprintf(udp_status, sizeof(udp_status), "control_udp role=debug rx=%d tx=%d queried=%d",
                 rx, tx, rx_ok && tx_ok);
        sl_log(udp_status);
    }
#endif
#endif
    r->started = pthread_create(&r->worker, NULL, worker_main, r) == 0;
    if (!r->started) {
        sl_runtime_destroy(r);
        return NULL;
    }
    return r;
}
bool sl_runtime_submit(sl_runtime *r, const sl_command *cmd, const sl_auth_store *store) {
    if (!sl_resolution_valid(cmd->resolution))
        return false;
    pthread_mutex_lock(&r->lock);
    if (cmd->type == SL_CMD_STOP || cmd->type == SL_CMD_CANCEL || cmd->type == SL_CMD_EXIT)
        sl_media_close_video();
    if (cmd->type == SL_CMD_SAVE) {
        r->save = *store;
        r->save_credential_revision = r->credential_revision;
        r->snapshot_pending = true;
        r->save_pending = true;
        r->save_language = cmd->language;
        r->save_update_check = cmd->update_check;
        r->save_resolution = cmd->resolution;
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
        r->save_credential_revision = r->credential_revision;
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
    sl_system_dns_cancel_all();
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
    clear_control_locked(r); /* Worker/producers have been joined. */
    sl_directory_destroy(&r->directory);
    sl_accounts_destroy(&r->paired_accounts);
    free(r->discovery_targets);
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
