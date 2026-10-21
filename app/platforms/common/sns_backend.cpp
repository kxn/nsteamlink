extern "C" {
#include "sns_backend.h"
#include "stream_bridge.h"
#include "sdr_probe.h"
#include "dns_policy.h"
}
#include <steam/steamnetworkingsockets.h>
#include <steam/steamnetworkingcustomsignaling.h>
#include <steam/isteamnetworkingutils.h>
#if NSL_DIAGNOSTICS
#include "sns_start_diagnostics.h"
#endif
#include "sns_message_queue.h"
#include "sns_connection_policy.h"
#include "sns_io_policy.h"
#include "sns_config_fetch_policy.h"
#include "sns_config_http.h"
#include <mbedtls/base64.h>
#include <curl/curl.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <vector>

/* Exported by the fixed upstream SDK, but absent from its public header. */
extern "C" void SteamNetworkingSockets_SetManualPollMode(bool);
extern "C" void SteamNetworkingSockets_Poll(int);
extern "C" void sl_gns_set_steam_link_app_id();
extern "C" bool sl_gns_import_trust(const char *, size_t);
extern "C" int sl_gns_certificate_seconds();

namespace {
/* Fixed public SDK's default RecvMaxMessageSize, not the UDP buffer limit.
 * Official SNS packet attachment preserves the entire SDK message (§12.3). */
enum { DATAGRAM_MAX = k_cbMaxSteamNetworkingSocketsMessageSizeSend, SIGNAL_COUNT = 64 };
using Message = std::vector<uint8_t>;
struct Queues {
    std::mutex mutex;
    std::condition_variable wake;
    nsl::SnsMessageQueue rx;
    std::deque<Message> signals;
    std::atomic<sl_sns_state> state{SL_SNS_CONNECTING};
    bool owner = true;
};
std::atomic<bool> sdk_owned{false};
class Signaling final : public ISteamNetworkingConnectionSignaling {
    std::shared_ptr<Queues> q;
public:
    explicit Signaling(std::shared_ptr<Queues> queues) : q(std::move(queues)) {}
    bool SendSignal(HSteamNetConnection, const SteamNetConnectionInfo_t &,
                    const void *data, int size) override {
        if (!data || size <= 0 || size > 60000)
            return false;
        std::lock_guard<std::mutex> lock(q->mutex);
        if (!q->owner || q->signals.size() == SIGNAL_COUNT)
            return false;
        try {
            const uint8_t *p = static_cast<const uint8_t *>(data);
            q->signals.emplace_back(p, p + size);
            return true;
        } catch (const std::bad_alloc &) { return false; }
    }
    void Release() override { delete this; }
};
class ReceiveContext final : public ISteamNetworkingSignalingRecvContext {
public:
    ISteamNetworkingConnectionSignaling *OnConnectRequest(HSteamNetConnection,
        const SteamNetworkingIdentity &, int) override { return nullptr; }
    void SendRejectionSignal(const SteamNetworkingIdentity &, const void *, int) override {}
};
static void wipe(void *p, size_t n) {
    volatile uint8_t *q = static_cast<volatile uint8_t *>(p);
    while (n--) *q++ = 0;
}
static bool decode_cert(const char *text, Message &out) {
    if (!text)
        return false;
    size_t n = strnlen(text, 65537);
    if (!n || n > 65536 || n % 4 == 1)
        return false;
    std::string padded(text, n);
    while (padded.size() % 4)
        padded += '=';
    out.resize(padded.size());
    size_t decoded = 0;
    int ret = mbedtls_base64_decode(out.data(), out.size(), &decoded,
        reinterpret_cast<const uint8_t *>(padded.data()), padded.size());
    wipe(&padded[0], padded.size());
    if (ret || !decoded) {
        wipe(out.data(), out.size());
        out.clear();
        return false;
    }
    out.resize(decoded);
    return true;
}
/* BInit is asynchronous in this port. Retain the bridge's inputs until it
 * succeeds; callers may release response/config storage after sl_sns_create.
 * Copy strings before keys so a throwing string allocation cannot leave an
 * unwiped key in a partially constructed object. */
struct BridgeInit {
    IHS_ClientConfig config{};
    sl_remote_material material{};
    std::string name, model, serial;
    uint8_t secret[32]{};
    BridgeInit(const IHS_ClientConfig &c, const sl_remote_material &m) {
        if (c.deviceName) name = c.deviceName;
        if (c.deviceModel) model = c.deviceModel;
        if (c.deviceSerial) serial = c.deviceSerial;
        config = c;
        config.deviceName = c.deviceName ? name.c_str() : nullptr;
        config.deviceModel = c.deviceModel ? model.c_str() : nullptr;
        config.deviceSerial = c.deviceSerial ? serial.c_str() : nullptr;
        memcpy(secret, c.secretKey, sizeof(secret));
        config.secretKey = secret;
        material = m;
        material.cert = material.stun_servers = nullptr;
    }
    ~BridgeInit() {
        wipe(secret, sizeof(secret));
        wipe(material.key, sizeof(material.key));
    }
};
}
struct sl_sns {
    std::shared_ptr<Queues> q = std::make_shared<Queues>();
    /* Serialize the IHS send callback with handle creation/invalidation/close.
     * Never acquire this mutex while holding q->mutex; SDK send may enqueue
     * signaling under q->mutex. HTTP/bridge updates do not hold it. */
    std::mutex connection_mutex;
    std::atomic<uint64_t> datagrams_sent{0};
    ISteamNetworkingSockets *sockets = nullptr;
    HSteamNetConnection connection = k_HSteamNetConnection_Invalid;
    sl_stream_bridge *bridge = nullptr;
    std::unique_ptr<BridgeInit> bridge_init;
    SteamNetworkingMicroseconds last_check = 0;
    bool initialized = false, connection_attempted = false;
    bool share_ip = true, config_ready = false;
    CURLM *http = nullptr;
    CURL *request = nullptr;
    unsigned config_attempt = 0;
    nsl::SnsConfigFetchPolicy config_fetch;
    std::vector<char> config, config_download;
    Message certificate;
    int end_reason = 0;
    sl_sns_stats stats{};
#if NSL_SNS_PROBES
    sl_sdr_probe *relay_probe = nullptr;
    unsigned sdr_debug[16] = {};
    sl_sdr_loss_snapshot terminal_loss{};
    bool observe_loss = false, terminal_loss_valid = false;
#endif
};
static nsl::SnsConnectionView connection_view(sl_sns *b) {
    return {b->connection, b->q->state, b->last_check};
}
static void record_terminal(sl_sns *b, sl_sns_terminal_source source, int detail,
                             const SteamNetConnectionInfo_t *info) {
    if (b->stats.terminal_source != SL_SNS_TERMINAL_NONE || source == SL_SNS_TERMINAL_NONE)
        return;
    b->stats.terminal_source = source;
    b->stats.terminal_detail = detail;
    b->stats.terminal_sdk_state = info ? int(info->m_eState) : 0;
    b->stats.terminal_end_reason = b->end_reason;
#if NSL_SNS_PROBES && NSL_ENABLE_SDR
    if (b->observe_loss && b->connection)
        b->terminal_loss_valid = sl_gns_sdr_loss_snapshot(b->connection, &b->terminal_loss);
#endif
}
static void unlink_signaling(sl_sns *b) {
    std::lock_guard<std::mutex> lock(b->q->mutex);
    b->q->owner = false;
}
static void clear_datagrams(sl_sns *b) {
    {
        std::lock_guard<std::mutex> lock(b->q->mutex);
        b->q->rx.clear();
    }
    b->q->wake.notify_all();
}
static void close_backend(sl_sns *b, sl_sns_state state,
    sl_sns_terminal_source source = SL_SNS_TERMINAL_NONE, int detail = 0,
    int reason = 2001, const char *debug = "stream transport closed") {
    std::lock_guard<std::mutex> api_lock(b->connection_mutex);
    b->bridge_init.reset();
    SteamNetConnectionInfo_t info{};
    bool have_info = b->connection != k_HSteamNetConnection_Invalid &&
        b->sockets->GetConnectionInfo(b->connection, &info);
    if (have_info) {
        b->stats.sdk_state = int(info.m_eState);
        if (info.m_eEndReason) b->end_reason = info.m_eEndReason;
    }
    record_terminal(b, source, detail, have_info ? &info : nullptr);
    if (state == SL_SNS_FAILED) b->q->state = SL_SNS_FAILED;
    // Local resource errors, last Release and CheckConnection have distinct
    // reasons; callers supply the explicit normal-destruction reason.
    nsl::CloseSnsConnection(b->sockets, connection_view(b), [b] { unlink_signaling(b); },
                            reason, debug);
    clear_datagrams(b);
}
static bool receive_signal(const uint8_t *p, size_t n, void *ctx) {
    sl_sns *b = static_cast<sl_sns *>(ctx);
    if (!b->connection || n > INT32_MAX)
        return false;
    ReceiveContext receive;
    return b->sockets->ReceivedP2PCustomSignal(p, static_cast<int>(n), &receive);
}
static void signal_failed(void *ctx) { close_backend(static_cast<sl_sns *>(ctx), SL_SNS_FAILED, SL_SNS_TERMINAL_SIGNAL); }
static void copy_error(char *error, size_t size, const char *text) {
    if (error && size)
        snprintf(error, size, "%s", text);
}
static size_t receive_config(char *p, size_t size, size_t count, void *ctx) {
    sl_sns *b = static_cast<sl_sns *>(ctx);
    if (size && count > SIZE_MAX / size)
        return 0;
    size_t bytes = size * count;
    if (bytes > 1024 * 1024 - b->config_download.size())
        return 0;
    try {
        b->config_download.insert(b->config_download.end(), p, p + bytes);
        return bytes;
    } catch (const std::bad_alloc &) { return 0; }
}
static void config_event(sl_sns *b, const char *event, int result) {
#if NSL_DIAGNOSTICS
    long status = 0, verified = 0;
    char *remote = nullptr;
    if (b->request) {
        curl_easy_getinfo(b->request, CURLINFO_RESPONSE_CODE, &status);
        curl_easy_getinfo(b->request, CURLINFO_SSL_VERIFYRESULT, &verified);
        curl_easy_getinfo(b->request, CURLINFO_PRIMARY_IP, &remote);
    }
    char line[224];
    snprintf(line, sizeof(line), "sns_config event=%s attempt=%u curl=%d http=%ld verify=%ld ip=%.64s",
        event, b->config_attempt, result, status, verified, remote ? remote : "");
    sl_dns_policy_report(line);
#else
    (void)b; (void)event; (void)result;
#endif
}
static bool begin_config(sl_sns *b, bool force = false) {
    if (!b->config_fetch.begin(force)) return true;
    b->config_download.clear();
    ++b->config_attempt;
    b->request = curl_easy_init();
    if (!b->request) {
        b->config_fetch.cannot_start();
        return false;
    }
    /* Retail Public/Global, without the China hint. Counts 2,4,... use the
     * China WebAPI base while retaining Global configuration via the suffix. */
    const char *url = b->config_fetch.alternate_realm()
        ? "https://api.steamchina.com/ISteamApps/GetSDRConfig/v1?appid=353380&realm=steamglobal"
        : "https://api.steampowered.com/ISteamApps/GetSDRConfig/v1?appid=353380";
    curl_easy_setopt(b->request, CURLOPT_URL, url);
    curl_easy_setopt(b->request, CURLOPT_WRITEFUNCTION, receive_config);
    curl_easy_setopt(b->request, CURLOPT_WRITEDATA, b);
    sl_sns_config_http_options(b->request);
    config_event(b, "begin", -1);
    if (curl_multi_add_handle(b->http, b->request) == CURLM_OK) return true;
    curl_easy_cleanup(b->request); b->request = nullptr;
    b->config_fetch.cannot_start();
    return false;
}
static bool begin_connection(sl_sns *b) {
    std::lock_guard<std::mutex> api_lock(b->connection_mutex);
    b->connection_attempted = true;
    /* NETWORKING section 9.5. Keep explicit official rate, encryption
     * preference, timeout and message flags. The built-in GNS ICE provider is
     * a documented implementation difference from the APK's WebRTC factory. */
    SteamNetworkingConfigValue_t options[6];
    options[0].SetInt32(k_ESteamNetworkingConfig_Unencrypted, 2);
    options[1].SetInt32(k_ESteamNetworkingConfig_P2P_Transport_ICE_Enable,
                      b->share_ip ? 0x7fffffff : 0);
    options[2].SetInt32(k_ESteamNetworkingConfig_SendRateMin, 104857600);
    options[3].SetInt32(k_ESteamNetworkingConfig_SendRateMax, 104857600);
    options[4].SetInt32(k_ESteamNetworkingConfig_TimeoutInitial, 20000);
    options[5].SetInt32(k_ESteamNetworkingConfig_P2P_Transport_ICE_Implementation, 1);
#if NSL_DIAGNOSTICS
    int certificate_seconds = sl_gns_certificate_seconds();
    SteamNetAuthenticationStatus_t authentication{};
    b->sockets->GetAuthenticationStatus(&authentication);
    nsl::StartFailure failure;
    unsigned errors = 0;
    {
        nsl::StartDiagnostics capture(SteamNetworkingUtils());
        b->connection = b->sockets->ConnectP2PCustomSignaling(new Signaling(b->q), nullptr, 0, 6, options);
        failure = capture.failure;
        errors = capture.messages;
    }
    if (b->connection == k_HSteamNetConnection_Invalid) {
        char line[224];
        snprintf(line, sizeof(line), "sns_start failed_stage=%s detail=%u sdk_errors=%u auth=%d cert_seconds=%d",
            failure.stage, failure.detail, errors, int(authentication.m_eAvail), certificate_seconds);
        sl_dns_policy_report(line);
    }
#else
    b->connection = b->sockets->ConnectP2PCustomSignaling(new Signaling(b->q), nullptr, 0, 6, options);
#endif
    return b->connection != k_HSteamNetConnection_Invalid;
}
static bool complete_initialization(sl_sns *b) {
    sl_signal_callbacks callbacks = {receive_signal, signal_failed};
    b->bridge = sl_stream_bridge_create(&b->bridge_init->config,
        &b->bridge_init->material, &callbacks, b);
    b->bridge_init.reset(); // The bridge copied its identity and stream HMAC key.
    if (!b->bridge) {
        close_backend(b, SL_SNS_FAILED, SL_SNS_TERMINAL_BRIDGE);
        return false;
    }
    b->config_ready = true;
    return true;
}
static bool install_certificate(sl_sns *b) {
    SteamNetworkingErrMsg error;
    /* CA trust from the explicit configuration must precede the local cert. */
    bool present = !b->certificate.empty();
    bool installed = !present || b->sockets->SetCertificate(b->certificate.data(),
        static_cast<int>(b->certificate.size()), error);
    config_event(b, !present ? "certificate_absent"
                            : installed ? "certificate_installed" : "certificate_failed", -1);
    wipe(b->certificate.data(), b->certificate.size());
    b->certificate.clear();
    if (!installed) {
        b->end_reason = -2;
        close_backend(b, SL_SNS_FAILED, SL_SNS_TERMINAL_CERTIFICATE);
        return false;
    }
    b->sockets->InitAuthentication();
    return complete_initialization(b);
}
static void pump_config(sl_sns *b) {
    if (!b->request)
        return;
    int running = 0;
    CURLMcode ret = curl_multi_perform(b->http, &running);
    CURLMsg *message;
    int remaining;
    bool done = ret != CURLM_OK, success = false;
    while ((message = curl_multi_info_read(b->http, &remaining))) {
        if (message->msg != CURLMSG_DONE || message->easy_handle != b->request)
            continue;
        done = true;
        config_event(b, "complete", int(message->data.result));
        success = message->data.result == CURLE_OK &&
            sl_gns_import_trust(b->config_download.data(), b->config_download.size());
        if (message->data.result == CURLE_OK)
            config_event(b, success ? "trust_imported" : "trust_failed", -1);
    }
    if (!done)
        return;
    curl_multi_remove_handle(b->http, b->request);
    curl_easy_cleanup(b->request);
    b->request = nullptr;
    auto action = b->config_fetch.complete(success);
    if (success) {
        b->config.swap(b->config_download);
        b->config_download.clear();
        if (!b->config_ready && !install_certificate(b)) return;
    }
    bool started = true;
    if (action == nsl::SnsConfigFetchPolicy::Refresh)
        started = begin_config(b, true);
    else if (action == nsl::SnsConfigFetchPolicy::Retry)
        started = begin_config(b);
    if ((!started || action == nsl::SnsConfigFetchPolicy::None) && !b->config_fetch.available) {
        b->end_reason = -1;
        close_backend(b, SL_SNS_FAILED, SL_SNS_TERMINAL_CONFIG);
    }
}
extern "C" sl_sns *sl_sns_create(const IHS_ClientConfig *config, const sl_remote_material *m,
                                  bool share_ip, char *error, size_t error_size) {
    return sl_sns_create_configured(config, m, share_ip, error, error_size, nullptr, 0);
}
extern "C" sl_sns *sl_sns_create_configured(const IHS_ClientConfig *config, const sl_remote_material *m,
    bool share_ip, char *error, size_t error_size, const char *network_config, size_t network_config_size) {
    if (!config || !config->deviceId || !config->secretKey || !m || !m->client_id ||
        !m->steam_id || !m->key_size || m->key_size > sizeof(m->key) ||
        m->transport != 4 || network_config_size > 1024 * 1024 ||
        (network_config_size && !network_config)) {
        copy_error(error, error_size, "invalid SNS connection material");
        return nullptr;
    }
    bool expected = false;
    if (!sdk_owned.compare_exchange_strong(expected, true)) {
        copy_error(error, error_size, "another stream owns the SNS instance");
        return nullptr;
    }
    sl_sns *b = nullptr;
    SteamNetworkingErrMsg err = {};
    try {
        b = new sl_sns;
        b->bridge_init.reset(new BridgeInit(*config, *m));
        /* Manual mode precedes SDK initialization, preventing a service worker
         * from racing the caller's pump or teardown. */
        SteamNetworkingSockets_SetManualPollMode(true);
        if (!GameNetworkingSockets_Init(nullptr, err))
            goto fail;
        b->initialized = true;
        b->sockets = SteamNetworkingSockets();
        SteamNetworkingUtils()->SetDebugOutputFunction(k_ESteamNetworkingSocketsDebugOutputType_None, nullptr);
        sl_gns_set_steam_link_app_id();
        b->share_ip = share_ip;
        b->sockets->ResetIdentity(nullptr);
        if (m->stun_servers && m->stun_servers[0] &&
            !SteamNetworkingUtils()->SetGlobalConfigValueString(
                k_ESteamNetworkingConfig_P2P_STUN_ServerList, m->stun_servers)) {
            copy_error(err, sizeof(err), "cannot set SNS STUN servers");
            goto fail;
        }
        if (network_config_size) {
            b->config.assign(network_config, network_config + network_config_size);
            if (!sl_gns_import_trust(b->config.data(), b->config.size())) {
                config_event(b, "startup_trust_failed", -1);
                copy_error(err, sizeof(err), "invalid startup SNS network configuration");
                goto fail;
            }
            b->config_fetch.available = true;
            b->config_fetch.state = 100;
        }
        /* The original consumes explicit config before even decoding cert.
         * An absent cert skips SetCertificate and still requests auth. */
        if (m->cert && m->cert[0] && !decode_cert(m->cert, b->certificate)) {
            copy_error(err, sizeof(err), "invalid base64 SNS certificate");
            goto fail;
        }
        if (network_config_size) {
            if (!install_certificate(b)) {
                copy_error(err, sizeof(err), "SNS certificate or bridge initialization failed");
                goto fail;
            }
            config_event(b, "startup_imported", -1);
            return b;
        }
        b->http = curl_multi_init();
        if (!b->http || !begin_config(b)) {
            copy_error(err, sizeof(err), "cannot start SNS network configuration");
            goto fail;
        }
        return b;
    } catch (const std::bad_alloc &) { copy_error(err, sizeof(err), "SNS allocation failed"); }
fail:
    copy_error(error, error_size, err[0] ? err : "SNS initialization failed");
    if (b)
        sl_sns_destroy(b);
    else
        sdk_owned = false;
    return nullptr;
}
static bool check_connection(sl_sns *b) {
    std::lock_guard<std::mutex> api_lock(b->connection_mutex);
    /* The official synchronous BInit precedes BConnect/CheckConnection. Our
     * asynchronous config/certificate HTTP stage has no SDK handle yet and
     * must not be mistaken for an already-invalidated connection. */
    if (!b->connection_attempted) return false;
    nsl::SnsConnectionObservation observed;
    auto source = [&] {
        switch (observed.failure) {
        case nsl::SnsCheckFailure::Info: return SL_SNS_TERMINAL_CONNECTION_INFO;
        case nsl::SnsCheckFailure::Status: return SL_SNS_TERMINAL_STATUS;
        case nsl::SnsCheckFailure::None: return SL_SNS_TERMINAL_NONE;
        default: return SL_SNS_TERMINAL_CONNECTION;
        }
    };
    auto update_info = [&] {
        if (!observed.infoValid) return;
        const auto &info = observed.info;
        b->end_reason = info.m_eEndReason;
        b->stats.sdk_state = int(info.m_eState);
        b->stats.authenticated = !(info.m_nFlags & k_nSteamNetworkConnectionInfoFlags_Unauthenticated);
        b->stats.relayed = (info.m_nFlags & k_nSteamNetworkConnectionInfoFlags_Relayed) != 0;
    };
    bool valid = nsl::CheckSnsConnection(b->sockets, SteamNetworkingUtils(), connection_view(b),
        observed, [&] {
            update_info();
            record_terminal(b, source(), observed.detail, &observed.info);
            unlink_signaling(b);
        });
    update_info();
    record_terminal(b, source(), observed.detail, observed.infoValid ? &observed.info : nullptr);
    if (b->q->state == SL_SNS_FAILED || b->q->state == SL_SNS_CLOSED)
        clear_datagrams(b);
    return valid;
}
static void update_backend(sl_sns *b, uint64_t now) {
    if (!b || !b->initialized)
        return;
    /* Official BInit returns before SDR UpdateState creates the SDK handle.
     * Let the caller create IHS/start its deadline after config completion;
     * the next owner pass may then start SDK route finding. */
    bool connect_now = b->config_ready && !b->connection_attempted;
    SteamNetworkingSockets_Poll(0);
#if NSL_SNS_PROBES
    sl_gns_sdr_probe_update(b->relay_probe);
#endif
    b->sockets->RunCallbacks();
    pump_config(b);
    if (connect_now && b->q->state == SL_SNS_CONNECTING) {
        bool started = begin_connection(b);
        config_event(b, started ? "p2p_started" : "p2p_start_failed", -1);
        if (!started)
            close_backend(b, SL_SNS_FAILED, SL_SNS_TERMINAL_START);
    }
#if NSL_ENABLE_SDR && NSL_SNS_PROBES
    if (b->connection)
        sl_gns_sdr_transport_stats(b->connection, b->sdr_debug);
#endif
    bool connected = check_connection(b);
    {
        /* SDK callbacks only enqueue. Never hold this mutex across an SDK call
         * that might call SendSignal again. */
        std::deque<Message> signals;
        {
            std::lock_guard<std::mutex> lock(b->q->mutex);
            signals.swap(b->q->signals);
        }
        for (const auto &p : signals)
            if (!sl_stream_bridge_queue(b->bridge, p.data(), p.size())) {
                close_backend(b, SL_SNS_FAILED, SL_SNS_TERMINAL_SIGNAL_QUEUE);
                break;
            }
    }
    sl_stream_bridge_update(b->bridge, now,
        b->q->state == SL_SNS_CONNECTING || b->q->state == SL_SNS_CONNECTED);
    if (!connected || b->q->state != SL_SNS_CONNECTED)
        return;
    SteamNetworkingMessage_t *messages[128];
    for (unsigned batch = 0; batch < 32; ++batch) {
        int count = b->sockets->ReceiveMessagesOnConnection(b->connection, messages, 128);
        if (count < 0) {
            close_backend(b, SL_SNS_FAILED, SL_SNS_TERMINAL_RECEIVE, count);
            return;
        }
        bool overflow = false;
        {
            std::lock_guard<std::mutex> lock(b->q->mutex);
            for (int i = 0; i < count; ++i) {
                SteamNetworkingMessage_t *m = messages[i];
                ++b->stats.datagrams_received;
                if (!overflow && (m->m_cbSize < 0 || !b->q->rx.push(
                        static_cast<const uint8_t *>(m->m_pData),
                        static_cast<size_t>(m->m_cbSize), DATAGRAM_MAX)))
                    overflow = true;
                m->Release();
            }
        }
        b->q->wake.notify_all();
        if (overflow) {
            close_backend(b, SL_SNS_FAILED, SL_SNS_TERMINAL_DATAGRAM);
            return;
        }
        if (count < 128)
            break;
    }
}
extern "C" void sl_sns_update(sl_sns *b, uint64_t now) {
    try { update_backend(b, now); }
    catch (const std::bad_alloc &) {
        if (b)
            close_backend(b, SL_SNS_FAILED, SL_SNS_TERMINAL_MEMORY);
    }
}
extern "C" sl_sns_state sl_sns_get_state(const sl_sns *b) {
    return b ? b->q->state.load() : SL_SNS_CLOSED;
}
extern "C" bool sl_sns_session_ready(const sl_sns *b) {
    if (!b || !b->config_ready) return false;
    sl_sns_state state = b->q->state.load();
    return state == SL_SNS_CONNECTING || state == SL_SNS_CONNECTED;
}
extern "C" int sl_sns_end_reason(const sl_sns *b) { return b ? b->end_reason : 0; }
extern "C" void sl_sns_get_stats(const sl_sns *b, sl_sns_stats *out) {
    if (out) {
        *out = b ? b->stats : sl_sns_stats{};
        if (b) out->datagrams_sent = b->datagrams_sent.load();
    }
}
#if NSL_SNS_PROBES
extern "C" bool sl_sns_start_relay_probe(sl_sns *b) {
    if (!b || !b->connection || b->relay_probe || b->q->state != SL_SNS_CONNECTED)
        return false;
    b->relay_probe = sl_gns_sdr_probe_create(b->connection, b->config.data(), b->config.size());
    return b->relay_probe != nullptr;
}
extern "C" void sl_sns_relay_probe_stats(const sl_sns *b, unsigned out[5]) {
    if (!out)
        return;
    sl_sdr_probe_stats s{};
    if (b)
        sl_gns_sdr_probe_stats(b->relay_probe, &s);
    out[0] = s.sent_pings;
    out[1] = s.valid_ping_replies;
    out[2] = s.requests;
    out[3] = s.established;
    out[4] = s.rejected;
}
extern "C" void sl_sns_sdr_debug(const sl_sns *b, unsigned out[16]) {
    if (b && out)
        memcpy(out, b->sdr_debug, sizeof(b->sdr_debug));
}
extern "C" bool sl_sns_test_relay_loss(sl_sns *b, int mode, unsigned out[5]) {
#if NSL_ENABLE_SDR
    bool result=b && b->connection && sl_gns_sdr_test_loss(b->connection, mode, out);
    if (result && mode>=0) b->observe_loss=mode!=0;
    return result;
#else
    (void)b; (void)mode; (void)out;
    return false;
#endif
}
extern "C" bool sl_sns_test_migration(sl_sns *b, bool start, unsigned out[6]) {
#if NSL_ENABLE_SDR
    return b && b->connection && sl_gns_sdr_test_migration(b->connection,start,out);
#else
    (void)b; (void)start; (void)out; return false;
#endif
}
extern "C" bool sl_sns_loss_snapshot(sl_sns *b, sl_sdr_loss_snapshot *out) {
#if NSL_ENABLE_SDR
    if (!b || !out) return false;
    if (b->connection && sl_gns_sdr_loss_snapshot(b->connection,out)) return true;
    if (!b->terminal_loss_valid) return false;
    *out=b->terminal_loss;
    return true;
#else
    (void)b; (void)out; return false;
#endif
}
extern "C" bool sl_sns_test_terminal(sl_sns *b, int packet_case) {
#if NSL_ENABLE_SDR
    return b && b->connection && sl_gns_sdr_test_terminal(b->connection, packet_case);
#else
    (void)b; (void)packet_case;
    return false;
#endif
}
#endif
extern "C" int sl_sns_set_mtu(sl_sns *b, int mtu) {
    if (!b) return -1;
    std::lock_guard<std::mutex> api_lock(b->connection_mutex);
    return nsl::SetSnsMaximumMTU(SteamNetworkingUtils(), b->connection, mtu);
}
static bool send_datagram(void *ctx, const uint8_t *p, size_t n) {
    sl_sns *b = static_cast<sl_sns *>(ctx);
    if (!b) return nsl::SnsSendAccepted(3);
    std::lock_guard<std::mutex> api_lock(b->connection_mutex);
    int result = nsl::SendSnsDatagram(b->sockets, b->connection, b->q->state.load(), p, n);
    if (result == 0) ++b->datagrams_sent;
    return nsl::SnsSendAccepted(result);
}
static int wait_datagram(void *ctx, uint32_t wait_us) {
    sl_sns *b = static_cast<sl_sns *>(ctx);
    if (!b) return -1;
    std::unique_lock<std::mutex> lock(b->q->mutex);
    b->q->wake.wait_for(lock, std::chrono::microseconds(wait_us), [&] {
        return !b->q->rx.empty() || b->q->state == SL_SNS_FAILED || b->q->state == SL_SNS_CLOSED;
    });
    if (b->q->state == SL_SNS_FAILED || b->q->state == SL_SNS_CLOSED) return -1;
    return b->q->rx.empty() ? 0 : 1;
}
static int receive_datagram(void *ctx, uint8_t *p, size_t capacity,
                            size_t *received, uint32_t wait_us) {
    sl_sns *b = static_cast<sl_sns *>(ctx);
    if (!b || !p || !received) return -1;
    std::unique_lock<std::mutex> lock(b->q->mutex);
    if (wait_us)
        b->q->wake.wait_for(lock, std::chrono::microseconds(wait_us), [&] {
            return !b->q->rx.empty() || b->q->state == SL_SNS_FAILED || b->q->state == SL_SNS_CLOSED;
        });
    /* Like official Recv, terminal handle state takes priority over old data. */
    if (b->q->state == SL_SNS_FAILED || b->q->state == SL_SNS_CLOSED) return -1;
    if (b->q->rx.empty()) return 0;
    const Message &m = b->q->rx.front();
    if (m.size() > capacity) return -1;
    *received = m.size();
    if (*received) memcpy(p, m.data(), *received);
    b->q->rx.pop();
    return 1;
}
static size_t next_datagram_size(void *ctx) {
    sl_sns *b = static_cast<sl_sns *>(ctx);
    if (!b) return 0;
    std::lock_guard<std::mutex> lock(b->q->mutex);
    return b->q->rx.empty() ? 0 : b->q->rx.front().size();
}
extern "C" const IHS_DatagramTransport *sl_sns_datagram_transport(void) {
    static const IHS_DatagramTransport callbacks = {
        send_datagram, receive_datagram, wait_datagram, DATAGRAM_MAX, next_datagram_size};
    return &callbacks;
}
extern "C" void sl_sns_destroy(sl_sns *b) {
    if (!b)
        return;
    /* The owner first stops/joins IHS users of the datagram callbacks. Detach
     * SDK callbacks before closing the handle; their shared queue stays alive
     * until the SDK releases its signaling object. */
    {
        std::lock_guard<std::mutex> lock(b->q->mutex);
        b->q->owner = false;
    }
    close_backend(b, SL_SNS_CLOSED, SL_SNS_TERMINAL_NONE, 0,
        nsl::SnsDestroyedReason, nsl::SnsDestroyedDebug);
#if NSL_SNS_PROBES
    sl_gns_sdr_probe_destroy(b->relay_probe);
#endif
    if (!b->certificate.empty())
        wipe(b->certificate.data(), b->certificate.size());
    if (b->request) {
        curl_multi_remove_handle(b->http, b->request);
        curl_easy_cleanup(b->request);
    }
    if (b->http)
        curl_multi_cleanup(b->http);
    sl_stream_bridge_destroy(b->bridge);
    if (b->initialized)
        GameNetworkingSockets_Kill();
    SteamNetworkingSockets_SetManualPollMode(false);
    delete b;
    sdk_owned = false;
}
