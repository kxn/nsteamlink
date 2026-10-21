/* Actual production config callback from an already initialized/usable state.
 * HTTP completion and trust validation are providers. No SDK connection, Steam,
 * certificate acceptance, disk cache or application startup is claimed. */
#include "../platforms/common/sns_backend.cpp"
#include <cassert>
#include <cstdarg>
static sl_sns *fixture;
static CURL *easy;
static CURLMsg message;
static bool pending, parsed;
static unsigned status;
static std::vector<std::string> urls;
extern "C" CURL *__real_curl_easy_init(void);
extern "C" CURL *__wrap_curl_easy_init(void) { return easy = __real_curl_easy_init(); }
extern "C" CURLcode __real_curl_easy_setopt(CURL *, CURLoption, ...);
extern "C" CURLcode __wrap_curl_easy_setopt(CURL *e, CURLoption op, ...) {
    va_list args; va_start(args, op); CURLcode ret;
    if (op == CURLOPT_WRITEFUNCTION) ret = __real_curl_easy_setopt(e, op, va_arg(args, curl_write_callback));
    else if (op >= CURLOPTTYPE_OBJECTPOINT && op < CURLOPTTYPE_FUNCTIONPOINT) {
        auto p = va_arg(args, void *);
        if (op == CURLOPT_URL) urls.emplace_back(static_cast<const char *>(p));
        ret = __real_curl_easy_setopt(e, op, p);
    } else { assert(op < CURLOPTTYPE_OBJECTPOINT); ret = __real_curl_easy_setopt(e, op, va_arg(args, long)); }
    va_end(args); return ret;
}
extern "C" CURLMcode __wrap_curl_multi_perform(CURLM *, int *running) {
    *running = 0; pending = true;
    message = CURLMsg{}; message.msg = CURLMSG_DONE; message.easy_handle = easy; message.data.result = status >= 400 ? CURLE_HTTP_RETURNED_ERROR : CURLE_OK;
    char data[] = "new-config"; assert(receive_config(data, 1, sizeof(data)-1, fixture) == sizeof(data)-1);
    return CURLM_OK;
}
extern "C" CURLMsg *__wrap_curl_multi_info_read(CURLM *, int *left) {
    *left = 0; if (!pending) return nullptr; pending = false; return &message;
}
extern "C" CURLcode __wrap_curl_easy_getinfo(CURL *, CURLINFO info, ...) {
    assert(info == CURLINFO_RESPONSE_CODE); va_list args; va_start(args, info);
    *va_arg(args, long *) = status; va_end(args); return CURLE_OK;
}
extern "C" bool __wrap_sl_gns_import_trust(const char *p, size_t n) {
    assert(std::string(p, n) == "new-config"); return parsed;
}
int main(int argc, char **argv) {
    assert(argc == 2); bool first_success = !strcmp(argv[1], "success-then-failure");
    bool cold = !strcmp(argv[1], "cold-failover");
    auto snapshot = [] {
        printf("{\"available\":%d,\"completed\":%u,\"active\":%s,\"urls\":[",
            fixture->config_fetch.state, fixture->config_fetch.completed, fixture->request ? "true" : "false");
        for (unsigned i = 0; i < urls.size(); ++i) printf("%s\"%s\"", i ? "," : "", urls[i].c_str());
        puts("]}");
    };
    for (unsigned round = 0; round < (first_success ? 3u : 2u); ++round) {
        assert(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK);
        auto b = new sl_sns; fixture = b; urls.clear();
        if (cold) {
            b->http = curl_multi_init(); assert(b->http);
            assert(begin_config(b)); snapshot();
            parsed = false; status = 500;
            for (unsigned i = 0; i < 3; ++i) { pump_config(b); snapshot(); }
            assert(!b->request && b->q->state == SL_SNS_FAILED);
            assert(b->stats.terminal_source == SL_SNS_TERMINAL_CONFIG);
            sl_sns_destroy(b); fixture = nullptr; curl_global_cleanup();
            continue;
        }
        b->config_ready = true; b->config_fetch.available = true; b->config_fetch.state = 100;
        b->q->state = SL_SNS_CONNECTED; b->config.assign({'o','l','d'});
        b->http = curl_multi_init(); assert(b->http);
        assert(begin_config(b, true) && b->request);
        assert(std::string(b->config.begin(), b->config.end()) == "old");
        assert(begin_config(b, true) && urls.size() == 1); // Existing request is not replaced.
        parsed = first_success; status = first_success ? 200 : 500;
        pump_config(b);
        if (first_success) {
            assert(b->request && b->config_fetch.completed == 1 && urls.size() == 2);
            assert(std::string(b->config.begin(), b->config.end()) == "new-config");
            if (round == 2) {
                // Exit while the automatic refresh still owns an HTTP handle.
                sl_sns_destroy(b); fixture = nullptr; curl_global_cleanup();
                continue;
            }
            parsed = false; status = 500; pump_config(b);
        }
        assert(!b->request && !b->config_fetch.active && b->config_fetch.available);
        assert(b->q->state == SL_SNS_CONNECTED && b->config_ready);
        assert(b->config_fetch.completed == (first_success ? 2u : 1u));
        assert(std::string(b->config.begin(), b->config.end()) == (first_success ? "new-config" : "old"));
        assert(b->stats.terminal_source == SL_SNS_TERMINAL_NONE);
        sl_sns_destroy(b); fixture = nullptr; curl_global_cleanup();
    }
    if (!cold) puts("PASS actual config callback: no duplicate request, old data retained on failed refresh, no certificate reinstall or media failure; repeated owner lifetimes and exit with automatic refresh pending");
}
