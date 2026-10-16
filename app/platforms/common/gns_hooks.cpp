/* Compiled as part of the pinned GNS target so its private interfaces and
 * generated protobuf definitions use exactly the SDK's build configuration.
 * No changes to vendored source, crypto checks or trusted root keys. */
#include "steamnetworkingsockets/clientlib/csteamnetworkingsockets.h"
#include "steamnetworkingsockets/steamnetworkingsockets_certstore.h"
#define JSMN_STRICT
#define JSMN_STATIC
#define JSMN_PARENT_LINKS
#include "jsmn.h"
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <memory>
#include <string>

extern "C" void sl_gns_set_steam_link_app_id() {
    using namespace SteamNetworkingSocketsLib;
    static_cast<CSteamNetworkingUtils *>(SteamNetworkingUtils())->SetAppID(353380);
}
extern "C" bool sl_gns_import_trust(const char *json, size_t size) {
    using namespace SteamNetworkingSocketsLib;
    if (!json || size > 1024 * 1024)
        return false;
    std::unique_ptr<jsmntok_t[], decltype(&free)> tokens(
        static_cast<jsmntok_t *>(malloc(sizeof(jsmntok_t) * 32768)), free);
    if (!tokens)
        return false;
    jsmn_parser parser;
    jsmn_init(&parser);
    int count = jsmn_parse(&parser, json, size, tokens.get(), 32768);
    if (count < 1 || tokens[0].type != JSMN_OBJECT)
        return false;
    bool certs = false, success = false;
    for (int i = 1; i < count; ++i) {
        const jsmntok_t &t = tokens[i];
        if (t.parent != 0 || t.type != JSMN_STRING || i + 1 >= count)
            continue;
        std::string key(json + t.start, t.end - t.start);
        const jsmntok_t &value = tokens[++i];
        if (key == "success") {
            success = value.type == JSMN_PRIMITIVE && value.end - value.start == 4 &&
                !memcmp(json + value.start, "true", 4);
        } else if (key == "certs" || key == "revoked_keys") {
            if (value.type != JSMN_ARRAY || value.size > 256)
                return false;
            int parent = i;
            for (int k = 0; k < value.size; ++k) {
                if (++i >= count || tokens[i].parent != parent || tokens[i].type != JSMN_STRING)
                    return false;
                std::string text(json + tokens[i].start, tokens[i].end - tokens[i].start);
                /* Production certs are bare base64. Reject escaped/embedded
                 * strings instead of accidentally installing another key. */
                if (text.find('\\') != std::string::npos || text.find('\0') != std::string::npos)
                    return false;
                if (key == "certs") {
                    SteamNetworkingErrMsg error;
                    if (!CertStore_AddCertFromBase64(text.c_str(), error))
                        return false;
                    certs = true;
                } else {
                    char *end = nullptr;
                    errno = 0;
                    uint64_t id = strtoull(text.c_str(), &end, 10);
                    if (text.empty() || text.size() > 20 ||
                        text.find_first_not_of("0123456789") != std::string::npos ||
                        errno || !end || *end)
                        return false;
                    CertStore_AddKeyRevocation(id);
                }
            }
        }
    }
    return certs && success;
}
