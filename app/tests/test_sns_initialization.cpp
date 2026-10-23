/* Production async config owner and real SDK certificate rejection. HTTP,
 * trust import and bridge I/O are explicit providers. The successful BInit
 * stage is supplied to complete_initialization; no accepted SDK cert is claimed. */
#ifndef NSL_SNS_OWNER_SOURCE
#define NSL_SNS_OWNER_SOURCE "../platforms/common/sns_backend.cpp"
#endif
#include NSL_SNS_OWNER_SOURCE
#include <cassert>
#include <cstdarg>

static const char *mode;
static CURL *easy;
static CURLMsg done;
static bool pending;
static unsigned attempts, creates, destroys, activations, imports;
static bool fail_bridge;

extern "C" CURL *__real_curl_easy_init(void);
extern "C" CURL *__wrap_curl_easy_init(void) { return easy = __real_curl_easy_init(); }
extern "C" CURLMcode __wrap_curl_multi_perform(CURLM *, int *running) {
    *running = 1;
    if (!strcmp(mode, "hold") || !strcmp(mode, "ready") || !strcmp(mode, "bridge-failure"))
        return CURLM_OK;
    *running = 0;
    pending = true;
    done = CURLMsg{}; done.msg = CURLMSG_DONE; done.easy_handle = easy;
    done.data.result = !strcmp(mode, "config-failure") ? CURLE_COULDNT_CONNECT : CURLE_OK;
    return CURLM_OK;
}
extern "C" CURLMsg *__wrap_curl_multi_info_read(CURLM *, int *left) {
    *left = 0;
    if (!pending) return nullptr;
    pending = false; return &done;
}
extern "C" CURLcode __wrap_curl_easy_getinfo(CURL *handle, CURLINFO info, ...) {
    assert(handle == easy && info == CURLINFO_RESPONSE_CODE);
    va_list args; va_start(args, info); *va_arg(args, long *) = 200; va_end(args);
    return CURLE_OK;
}
extern "C" bool __wrap_sl_gns_import_trust(const char *, size_t) {
    ++imports;
    return !strcmp(mode, "bad-cert");
}
extern "C" sl_stream_bridge *__real_sl_stream_bridge_create(const IHS_ClientConfig *,
    const sl_remote_material *, const sl_signal_callbacks *, void *);
extern "C" sl_stream_bridge *__wrap_sl_stream_bridge_create(const IHS_ClientConfig *c,
    const sl_remote_material *m, const sl_signal_callbacks *cb, void *ctx) {
    ++attempts;
    assert(c->deviceId == 42 && !strcmp(c->deviceName, "fixture-client"));
    assert(!strcmp(c->deviceModel, "fixture-model") && !strcmp(c->deviceSerial, "fixture-serial"));
    assert(c->deviceProvisioningId == 9 && m->client_id == 123 && m->steam_id == 456);
    assert(m->key_size == 32);
    for (unsigned i = 0; i < 32; ++i) assert(c->secretKey[i] == i && m->key[i] == 128+i);
    if (fail_bridge) return nullptr;
    auto b = __real_sl_stream_bridge_create(c, m, cb, ctx);
    assert(b); ++creates; return b;
}
extern "C" void __wrap_sl_stream_bridge_update(sl_stream_bridge *b, uint64_t, bool wants) {
    if (b && wants) ++activations; // Observe admission; do not contact any CM.
}
extern "C" void __real_sl_stream_bridge_destroy(sl_stream_bridge *);
extern "C" void __wrap_sl_stream_bridge_destroy(sl_stream_bridge *b) {
    if (b) ++destroys;
    __real_sl_stream_bridge_destroy(b);
}
static sl_sns *start() {
    auto secret = new uint8_t[32];
    char *name = strdup("fixture-client"), *model = strdup("fixture-model"),
         *serial = strdup("fixture-serial"), *cert = strdup("AA==");
    assert(name && model && serial && cert);
    IHS_ClientConfig c{};
    c.deviceId = 42; c.secretKey = secret; c.deviceName = name;
    c.deviceModel = model; c.deviceSerial = serial; c.deviceProvisioningId = 9;
    sl_remote_material material{}; material.client_id = 123; material.steam_id = 456;
    material.transport = 4; material.key_size = 32; material.cert = cert;
    for (unsigned i = 0; i < 32; ++i) { secret[i] = i; material.key[i] = 128+i; }
    char error[256]{};
    sl_sns *b = sl_sns_create(&c, &material, false, error, sizeof(error));
    assert(b && !error[0]);
    // None of the pointers passed to sl_sns_create survive its return.
    memset(secret, 0xee, 32); delete[] secret;
    memset(name, 0xee, strlen(name)); free(name);
    memset(model, 0xee, strlen(model)); free(model);
    memset(serial, 0xee, strlen(serial)); free(serial);
    memset(cert, 0xee, strlen(cert)); free(cert);
    wipe(&material, sizeof(material));
    return b;
}
int main(int argc, char **argv) {
    assert(argc == 2); mode = argv[1];
    bool success = !strcmp(mode, "ready"), resource_failure = !strcmp(mode, "bridge-failure");
    fail_bridge = resource_failure;
    for (unsigned round = 0; round < 2; ++round) {
        attempts = creates = destroys = activations = imports = 0; pending = false;
        assert(!sdk_owned);
        sl_sns *b = start();
        for (unsigned i = 0; i < 4; ++i) sl_sns_update(b, i);
        unsigned before_attempts = attempts, before_activations = activations;
        bool before_ready = sl_sns_initialized(b);
        unsigned config_attempts = b->config_attempt;
        if (success || resource_failure) {
            // Provider boundary: configuration/certificate/authentication succeeded.
            // The real bridge factory and its copying/cleanup execute below.
            curl_multi_remove_handle(b->http, b->request);
            curl_easy_cleanup(b->request); b->request = nullptr;
#ifdef NSL_LEGACY_INIT_OWNER
            b->config_ready = true;
#else
            complete_initialization(b);
#endif
            sl_stream_bridge_update(b->bridge, 10, true);
        }
        bool ready = sl_sns_initialized(b);
        unsigned state = sl_sns_get_state(b), terminal = b->stats.terminal_source;
        assert(!b->connection_attempted && !b->connection);
        sl_sns_destroy(b);
        assert(!sdk_owned && creates == destroys);
        printf("{\"round\":%u,\"before_attempts\":%u,\"before_activations\":%u,"
               "\"before_ready\":%s,\"attempts\":%u,\"creates\":%u,\"destroys\":%u,"
               "\"activations\":%u,\"ready\":%s,\"state\":%u,\"terminal\":%u,"
               "\"config_attempts\":%u,\"imports\":%u,\"clean\":true}\n",
               round, before_attempts, before_activations, before_ready ? "true" : "false",
               attempts, creates, destroys, activations, ready ? "true" : "false", state,
               terminal, config_attempts, imports);
    }
}
