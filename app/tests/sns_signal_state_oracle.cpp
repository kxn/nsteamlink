/* Production authenticated signal channel and actual backend callbacks/policy.
 * SDK results/state changes and clock are controlled. No real network. */
#include "../platforms/common/sns_backend.cpp"
extern "C" {
#include "remote_wire.h"
}
#include <cassert>
#include <mbedtls/md.h>
#include <iostream>
#include <sstream>

static std::vector<std::string> events;
struct Signal { std::vector<uint8_t> bytes; bool ok; int state; };
struct Sdk {
    sl_sns *b;
    std::vector<Signal> signals;
    size_t received = 0;
    bool info_ok;
    int sdk_state, status;
    SteamNetworkingMicroseconds now;
    SteamNetworkingMicroseconds GetLocalTimestamp() { events.emplace_back("\"time\""); return now; }
    bool GetConnectionInfo(HSteamNetConnection handle, SteamNetConnectionInfo_t *info) {
        assert(handle == 1); events.emplace_back("\"info\"");
        info->m_eState = static_cast<ESteamNetworkingConnectionState>(sdk_state);
        info->m_eEndReason = 4321;
        return info_ok;
    }
    EResult GetConnectionRealTimeStatus(HSteamNetConnection handle,
        SteamNetConnectionRealTimeStatus_t *, int lanes, void *out) {
        assert(handle == 1 && !lanes && !out); events.emplace_back("\"status\"");
        return static_cast<EResult>(status);
    }
    bool ReceivedP2PCustomSignal(const void *data, int size, ISteamNetworkingSignalingRecvContext *) {
        assert(received < signals.size()); const auto &s = signals[received++];
        assert(size == int(s.bytes.size()) && (!size || !memcmp(data, s.bytes.data(), size)));
        std::string hex;
        for (auto byte : s.bytes) { hex += "0123456789abcdef"[byte>>4]; hex += "0123456789abcdef"[byte&15]; }
        events.push_back("[\"signal\",\""+hex+"\"]");
        sdk_state = s.state;
        return s.ok;
    }
    bool CloseConnection(HSteamNetConnection handle, int reason, const char *debug, bool linger) {
        assert(handle == 1 && !linger && !b->q->owner);
        events.push_back("[\"close\","+std::to_string(reason)+","+
            std::to_string(b->q->state.load())+",\""+(debug ? debug : "")+"\"]");
        return true;
    }
};
static bool receive(const uint8_t *data, size_t size, void *ctx) {
    auto sdk = static_cast<Sdk *>(ctx);
    return receive_signal_with(sdk->b, sdk, data, size);
}
static void failed(void *ctx) {
    auto sdk = static_cast<Sdk *>(ctx); signal_failed_with(sdk->b, sdk);
}
static void updated(void *ctx) {
    auto sdk = static_cast<Sdk *>(ctx); check_connection_with(sdk->b, sdk, sdk);
}
static std::vector<uint8_t> parse_hex(const std::string &text) {
    std::vector<uint8_t> out;
    if (text == "-") return out;
    for (size_t i = 0; i < text.size(); i+=2) out.push_back(std::stoul(text.substr(i, 2), nullptr, 16));
    return out;
}
int main() {
    unsigned programs; assert(bool(std::cin >> programs));
    for (unsigned p = 0; p < programs; ++p) {
        sl_sns b; int state; unsigned steps;
        assert(bool(std::cin >> state >> b.connection >> b.last_check >> steps));
        b.q->state = static_cast<sl_sns_state>(state); b.connection_attempted = true;
        Sdk sdk{}; sdk.b = &b;
        uint8_t key[32]{};
        sl_signal_callbacks callbacks = {receive, failed, updated};
        auto channel = sl_signal_channel_create(77, 88, key, sizeof(key), &callbacks, &sdk);
        assert(channel);
        for (unsigned step = 0; step < steps; ++step) {
            unsigned count;
            assert(bool(std::cin >> sdk.now >> sdk.info_ok >> sdk.status >> sdk.sdk_state >> count));
            sdk.signals.clear(); sdk.received = 0;
            uint8_t inner[4096], outer[8192], token[32];
            sl_proto_writer payload = {inner, 0, sizeof(inner), false};
            for (unsigned n = 0; n < count; ++n) {
                std::string hex; Signal s;
                assert(bool(std::cin >> hex >> s.ok >> s.state)); s.bytes = parse_hex(hex);
                sl_proto_bytes(&payload, 2, s.bytes.data(), s.bytes.size());
                sdk.signals.push_back(s);
            }
            assert(!payload.invalid);
            assert(!mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                key, sizeof(key), inner, payload.size, token));
            sl_proto_writer envelope = {outer, 0, sizeof(outer), false};
            sl_proto_bytes(&envelope, 1, token, sizeof(token));
            sl_proto_bytes(&envelope, 2, inner, payload.size); assert(!envelope.invalid);
            events.clear();
            int result = sl_signal_channel_receive(channel, 77, outer, envelope.size);
            std::printf("{\"result\":%s,\"state\":%d,\"handle\":%u,\"last_check\":%lld,"
                "\"owner_linked\":%s,\"events\":[", result == 1 ? "true":"false",
                int(b.q->state.load()), b.connection, (long long)b.last_check, b.q->owner ? "true":"false");
            for (size_t i = 0; i < events.size(); ++i) std::printf("%s%s", i ? ",":"", events[i].c_str());
            std::puts("]}");
        }
        sl_signal_channel_destroy(channel);
    }
}
