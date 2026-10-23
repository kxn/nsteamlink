/* Actual production receive queue/callbacks plus actual IHS receiveCycle.
 * SDK results/Poll, clock and final packet/update consumers are providers. */
#include "../platforms/common/sns_backend.cpp"
#include <cassert>
#include <iostream>
#include <sstream>
extern "C" {
#include "crypto.h"
void *sns_receive_session(const IHS_DatagramTransport *, void *);
bool sns_receive_cycle(void *, uint32_t, unsigned);
void sns_receive_destroy(void *);
}
static std::vector<std::string> events;
static std::string digest(const uint8_t *data, size_t size) {
    uint8_t hash[32];
    assert(!IHS_CryptoSHA256(data, size, hash));
    const char *hex = "0123456789abcdef";
    std::string result;
    for (uint8_t b : hash) { result += hex[b >> 4]; result += hex[b & 15]; }
    return result;
}
extern "C" void sns_receive_packet(const uint8_t *data, size_t size) {
    events.push_back("[\"packet\"," + std::to_string(size) + ",\"" + digest(data, size) + "\"]");
}
extern "C" void sns_receive_update(uint32_t stamp) {
    events.push_back("[\"update\"," + std::to_string(stamp) + "]");
}
struct ProbeMessage : SteamNetworkingMessage_t { ~ProbeMessage() = default; };
struct Sdk {
    std::vector<int> batches;
    std::vector<unsigned> lengths;
    size_t next = 0;
    unsigned serial = 0, released = 0;
    static void release(SteamNetworkingMessage_t *m) {
        auto s = reinterpret_cast<Sdk *>(m->m_nUserData);
        ++s->released;
        delete[] static_cast<uint8_t *>(m->m_pData);
        delete static_cast<ProbeMessage *>(m);
    }
    int ReceiveMessagesOnConnection(HSteamNetConnection h, SteamNetworkingMessage_t **out, int max) {
        assert(h == 1 && max == 128);
        // Unexpected extra queries see an empty SDK queue and remain visible
        // in the trace, so regressions fail comparison without crashing.
        int count = next < batches.size() ? batches[next++] : 0;
        events.push_back("[\"receive\"," + std::to_string(count) + "]");
        for (int i = 0; i < count; ++i) {
            unsigned size = lengths[serial % lengths.size()];
            ++serial;
            auto m = new ProbeMessage{};
            auto data = new uint8_t[size ? size : 1]{};
            for (unsigned byte = 0; byte < 4 && byte < size; ++byte) data[byte] = serial >> (byte*8);
            m->m_pData = data; m->m_cbSize = size;
            m->m_nUserData = reinterpret_cast<intptr_t>(this);
            m->m_pfnRelease = release;
            out[i] = m;
        }
        return count;
    }
};
int main() {
    IHS_Init();
    unsigned programs; assert(bool(std::cin >> programs));
    for (unsigned p = 0; p < programs; ++p) {
        sl_sns b;
        int state; unsigned steps;
        assert(bool(std::cin >> state >> b.connection >> steps));
        b.q->state = static_cast<sl_sns_state>(state);
        Sdk sdk;
        void *session = sns_receive_session(sl_sns_datagram_transport(), &b);
        for (unsigned step = 0; step < steps; ++step) {
            unsigned wait, counts, lengths; uint32_t now;
            assert(bool(std::cin >> wait >> now >> counts >> lengths));
            sdk.batches.resize(counts); sdk.lengths.resize(lengths); sdk.next = 0;
            for (auto &n : sdk.batches) assert(bool(std::cin >> n));
            for (auto &n : sdk.lengths) assert(bool(std::cin >> n));
            events.clear();
            events.push_back("[\"poll\"," + std::to_string(wait) + "]");
            bool accepted = receive_messages(&b, &sdk);
            bool readable = !b.q->rx.empty();
            bool keep = accepted && sns_receive_cycle(session, now, wait);
            assert(sdk.released == sdk.serial);
            std::printf("{\"readable\":%s,\"keep\":%s,\"state\":%d,\"handle\":%u,\"events\":[",
                readable ? "true":"false", keep ? "true":"false", int(b.q->state.load()), b.connection);
            for (size_t i = 0; i < events.size(); ++i)
                std::printf("%s%s", i ? ",":"", events[i].c_str());
            std::puts("]}");
        }
        sns_receive_destroy(session);
    }
    {
        // Local capacity failure still releases the complete SDK batch. This
        // is an explicit port bound, separate from original protocol traces.
        sl_sns b; b.connection = 1; b.q->state = SL_SNS_CONNECTED;
        for (size_t n = 0; n < nsl::SnsMessageQueue::CountLimit; ++n)
            assert(b.q->rx.push(nullptr, 0, DATAGRAM_MAX));
        Sdk sdk; sdk.batches = {128}; sdk.lengths = {0};
        assert(!receive_messages(&b, &sdk));
        assert(sdk.serial == 128 && sdk.released == 128 && !b.q->rx.empty());
    }
    IHS_Quit();
}
