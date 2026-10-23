/* Actual SNS construction/SDK rejection and ownership. Trust acceptance is
 * supplied explicitly; no accepted local certificate or network is claimed. */
#include "../platforms/common/sns_backend.cpp"
#include <cassert>
static unsigned imports, requests;
static bool accept_trust;
extern "C" CURL *__real_curl_easy_init(void);
extern "C" CURL *__wrap_curl_easy_init(void) { ++requests; return __real_curl_easy_init(); }
extern "C" bool __wrap_sl_gns_import_trust(const char *p, size_t n) {
    assert(std::string(p, n) == "startup-config");
    ++imports; return accept_trust;
}
int main() {
    uint8_t secret[32]{};
    IHS_ClientConfig config{};
    config.deviceId = 42; config.secretKey = secret;
    sl_remote_material material{};
    material.client_id = 123; material.steam_id = 456; material.transport = 4;
    material.key_size = 32; material.cert = "AA==";
    assert(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK);
    for (unsigned round = 0; round < 2; ++round) {
        for (unsigned mode = 0; mode < 3; ++mode) {
            imports = requests = 0; accept_trust = mode == 2;
            char error[256]{};
            const char *cache = mode ? "startup-config" : nullptr;
            auto b = sl_sns_create_configured(&config, &material, true, error, sizeof(error),
                                              cache, mode ? strlen(cache) : 0);
            if (!mode) {
                assert(b && b->request && !imports && requests == 1 && !sl_sns_session_ready(b));
                sl_sns_destroy(b); // cancel fallback while still pending
            } else {
                assert(!b && error[0] && imports == 1 && !requests);
                // The malformed cert is rejected by the actual SDK, after the
                // supplied successful trust import, without an HTTP fallback.
                assert(strstr(error, mode == 2 ? "certificate" : "configuration"));
            }
            assert(!sdk_owned);
        }
    }
    curl_global_cleanup();
    puts("PASS cached BInit: explicit import before cert, no silent fallback for invalid cache/cert, empty cache starts fetch, pending request cleanup, repeated SDK owners");
}
