#include "steamnetworkingsockets/clientlib/csteamnetworkingsockets.h"
#include "steamdatagram_messages_sdr.pb.h"
#include "crypto.h"
#ifdef NSL_GNS_SDR
#include "steamnetworkingsockets/clientlib/steamnetworkingsockets_p2p.h"
#include "sdr_client.h"
#endif
extern "C" {
#include "sdr_probe.h"
#include "sdr_wire.h"
#include "sdr_config.h"
#include "sdr_policy.h"
}
#include <memory>
#include <string>
#include <vector>
#include <algorithm>
#include <deque>
#include <unordered_map>

using namespace SteamNetworkingSocketsLib;
struct ProbeRelay {
    netadr_t address;
    uint32_t cookie = 0, server_time = 0, ping_timestamp = 0;
    uint64_t challenge = 0;
    SteamNetworkingMicroseconds challenge_at = 0, ping_sent = 0, request_until = 0, ping_deadline = 0;
    unsigned ping_failures = 0, request_failures = 0, probes_sent = 0;
    bool force_ping = false;
    PingTrackerForRouteSelection front;
    sl_sdr_failure_cache failures{};
    sl_sdr_downtime downtime{};
    int ping_ms = -1;
    bool established = false, closed_by_relay = false;
    uint32_t pop_id = 0;
    std::string routing_token;
    sl_sdr_target forward{};
    sl_sdr_acks acks{};
    LinkStatsTracker<LinkStatsTrackerEndToEnd> stats;
    std::deque<std::pair<uint16_t, SteamNetworkingMicroseconds>> sent_acks;
    SteamNetworkingMicroseconds last_received = 0;
    sl_sdr_latencies interior{};
    int penalty = 0;
    ProbeRelay() {
        front.Reset();
        stats.Init(SteamNetworkingSockets_GetLocalTimestamp(), ELinkActivityLevel::Idle);
    }
    uint64_t address_key() const { return uint64_t(address.GetIPv4()) << 16 | address.GetPort(); }
    void received(SteamNetworkingMicroseconds now) {
        last_received = now;
        ping_failures = 0;
        sl_sdr_address_received(&failures, address_key());
    }
};
struct sl_sdr_probe {
    HSteamNetConnection connection;
    sl_sdr_config config;
    IRawUDPSocket *socket = nullptr;
    std::deque<ProbeRelay> relays;
    sl_sdr_probe_stats counters{};
    SteamNetworkingMicroseconds last_round = 0, initialized_at = 0;
    bool good_enough = false, have_primary = false, have_backup = false;
    void *owner = nullptr;
    void (*owner_receive)(const RecvPktInfo_t &, ProbeRelay &, void *) = nullptr;
    std::vector<ProbeRelay *> pursue, pursue_token;
#if NSL_SNS_PROBES
    bool drop_enabled = false;
    netadr_t drop_address;
    uint32_t drop_pop = 0;
    unsigned dropped_tx = 0, dropped_rx = 0;
#endif
};
static bool send_packet(sl_sdr_probe *p, const void *data, int size, const netadr_t &address) {
#if NSL_SNS_PROBES
    if (p->drop_enabled && address == p->drop_address) { ++p->dropped_tx; return true; }
#endif
    return p->socket->BSendRawPacket(data, size, address);
}
static uint32_t random_below(uint32_t bound) {
    uint32_t n, threshold = uint32_t(-bound) % bound;
    do { CCrypto::GenerateRandomBlock(&n, sizeof(n)); } while (n < threshold);
    return n % bound;
}
/* Fixed APK 81b554/81b6a4 and 83e9a4: a terminal reply to a late
 * session establishment is ConnectionClosed (20), not NoConnection (21). */
static void send_closed(sl_sdr_probe *p, CSteamNetworkConnectionBase &connection,
    ProbeRelay &r, bool end_to_end, bool primary_session, bool primary_transport, bool session) {
    CMsgSteamDatagramConnectionClosed m;
    m.set_from_connection_id(connection.m_unConnectionIDLocal);
    if (connection.m_unConnectionIDRemote) m.set_to_connection_id(connection.m_unConnectionIDRemote);
    m.set_reason_code(connection.GetConnectionEndReason());
    m.set_debug(connection.GetConnectionEndDebugString());
    if (connection.GetWireState() == k_ESteamNetworkingConnectionState_ClosedByPeer)
        m.set_relay_mode(CMsgSteamDatagramConnectionClosed::ClosedByPeer);
    else if (end_to_end) m.set_relay_mode(CMsgSteamDatagramConnectionClosed::EndToEnd);
    m.set_not_primary_session(!primary_session);
    m.set_not_primary_transport(!primary_transport);
    m.set_relay_override_active(false);
    if (session) {
        if (sl_sdr_target_populate(&r.forward)) {
            m.set_forward_target_relay_routing_token(r.forward.sent, r.forward.sent_size);
            m.set_forward_target_revision(r.forward.revision);
        }
        r.stats.PopulateLifetimeMessage(*m.mutable_quality_relay()->mutable_lifetime());
    }
    if (end_to_end)
        connection.m_statsEndToEnd.PopulateLifetimeMessage(*m.mutable_quality_e2e()->mutable_lifetime());
    uint8_t packet[1300];
    size_t size = m.ByteSizeLong();
    if (size >= sizeof(packet)) return;
    packet[0] = 20;
    m.SerializeToArray(packet+1, int(size));
    send_packet(p, packet, int(size+1), r.address);
}
static void warn_downtime(ProbeRelay &r, uint32_t wire_seconds, SteamNetworkingMicroseconds now) {
    int32_t seconds = int32_t(wire_seconds);
    if (r.downtime.known && now + int64(seconds) * 1000000 >= r.downtime.shutdown - 3000000) return;
    uint32_t random;
    CCrypto::GenerateRandomBlock(&random, sizeof(random));
    float seconds_before = 45.0f + float(double(random) / 4294967296.0 * 15.0);
    sl_sdr_warn_downtime(&r.downtime, seconds, seconds_before, now);
}
static bool build_request(CSteamNetworkConnectionBase &connection, const ProbeRelay &r,
    const sl_sdr_config &config, CMsgSteamDatagramP2PSessionRequest &message) {
    if (!connection.m_unConnectionIDRemote || !r.challenge)
        return false;
    auto &interface = *connection.m_pSteamNetworkingSocketsInterface;
    CMsgSteamDatagramP2PSessionRequestBody body;
    body.set_challenge_time(r.server_time);
    body.set_challenge(r.challenge);
    body.set_client_connection_id(connection.m_unConnectionIDLocal);
    body.set_peer_connection_id(connection.m_unConnectionIDRemote);
    body.set_protocol_version(13);
    body.set_network_config_version(config.revision);
    body.set_platform(interface.m_pSteamNetworkingUtils->GetPlatformString());
    body.set_build("nsteamlink");
    SteamNetworkingIdentityRender peer(connection.m_identityRemote);
    body.set_peer_identity_string(peer.c_str());
    if (config.have_relay_key) {
        CECKeyExchangePrivateKey private_key;
        CECKeyExchangePublicKey public_key, relay_key;
        CCrypto::GenerateKeyExchangeKeyPair(&public_key, &private_key);
        if (!relay_key.SetRawDataWithoutWipingInput(config.relay_public_key, 32))
            return false;
        SHA256Digest_t shared, aes_key;
        if (!CCrypto::PerformKeyExchange(private_key, relay_key, &shared))
            return false;
        std::string hash_input(reinterpret_cast<const char *>(shared), 32);
        hash_input += interface.m_msgCert.identity_string();
        CCrypto::GenerateSHA256Digest(hash_input.data(), hash_input.size(), &aes_key);
        SecureZeroMemory(&hash_input[0], hash_input.size());
        SecureZeroMemory(shared, sizeof(shared));
        AES_GCM_EncryptContext cipher;
        bool initialized = cipher.Init(aes_key, sizeof(aes_key), 12, 16);
        SecureZeroMemory(aes_key, sizeof(aes_key));
        if (!initialized)
            return false;
        uint8_t nonce[12] = {};
        for (unsigned i = 0; i < 8; ++i)
            nonce[i] = uint8_t(r.challenge >> (i * 8));
        CMsgSteamDatagramP2PSessionRequestBody_EncryptedData encrypted;
        encrypted.set_peer_identity_string(peer.c_str());
        std::string plaintext = encrypted.SerializeAsString();
        uint8_t ciphertext[512];
        uint32_t size = sizeof(ciphertext);
        bool ok = cipher.Encrypt(plaintext.data(), plaintext.size(), nonce, ciphertext, &size, nullptr, 0);
        SecureZeroMemory(&plaintext[0], plaintext.size());
        if (!ok)
            return false;
        body.set_encrypted_data(ciphertext, size);
        body.set_encryption_your_public_key_lead_byte(config.relay_public_key[0]);
        uint8_t raw_public[32];
        if (public_key.GetRawData(raw_public) != 32)
            return false;
        body.set_encryption_my_ephemeral_public_key(raw_public, sizeof(raw_public));
        body.clear_peer_identity_string();
    }
    *message.mutable_cert() = interface.m_msgSignedCert;
    message.set_body(body.SerializeAsString());
    CryptoSignature_t signature;
    interface.m_keyPrivateKey.GenerateSignature(message.body().data(), message.body().size(), &signature);
    message.set_signature(signature, sizeof(signature));
    return true;
}
static void receive_packet(const RecvPktInfo_t &packet, sl_sdr_probe *probe) {
    if (packet.m_cbPkt < 5 || packet.m_cbPkt > 1300)
        return;
#if NSL_SNS_PROBES
    if (probe->drop_enabled && packet.m_adrFrom == probe->drop_address) { ++probe->dropped_rx; return; }
#endif
    ProbeRelay *r = nullptr;
    for (auto &candidate : probe->relays)
        if (candidate.address == packet.m_adrFrom) {
            r = &candidate;
            break;
        }
    if (!r)
        return;
    const uint8_t *data = static_cast<const uint8_t *>(packet.m_pPkt);
    if (data[0] == 2) {
        CMsgSteamDatagramRouterPingReply reply;
        if (!reply.ParseFromArray(data + 1, packet.m_cbPkt - 1) || reply.client_cookie() != r->cookie ||
            reply.client_timestamp() != r->ping_timestamp ||
            reply.latency_datacenter_ids_size() != reply.latency_ping_ms_size() ||
            reply.latency_datacenter_ids_p2p_size() != reply.latency_ping_ms_p2p_size())
            return;
        int32_t delay = int32_t(uint32_t(packet.m_usecNow) - reply.client_timestamp());
        if (delay < -2000 || delay > 10000000)
            return; /* Diagnostic resource bound; no routing score is inferred. */
        if (!r->ping_deadline)
            return; /* A measurement must match a live ping, once. */
        if (reply.has_seconds_until_shutdown()) warn_downtime(*r, reply.seconds_until_shutdown(), packet.m_usecNow);
        r->front.ReceivedPing(std::max(0, delay / 1000), packet.m_usecNow);
        r->ping_ms = r->front.m_nSmoothedPing;
        r->ping_deadline = 0;
        r->received(packet.m_usecNow);
        r->penalty = sl_sdr_cluster_penalty(int32_t(reply.scoring_penalty_relay_cluster()));
        sl_sdr_latencies_begin(&r->interior, reply.flags(), packet.m_usecNow);
        for (int i = 0; i < reply.latency_datacenter_ids_size(); ++i)
            sl_sdr_latency_measure(&r->interior, reply.latency_datacenter_ids(i),
                int32_t(reply.latency_ping_ms(i)), false, packet.m_usecNow);
        for (int i = 0; i < reply.latency_datacenter_ids_p2p_size(); ++i)
            sl_sdr_latency_measure(&r->interior, reply.latency_datacenter_ids_p2p(i),
                int32_t(reply.latency_ping_ms_p2p(i)), true, packet.m_usecNow);
        if (reply.latency_datacenter_ids_size() || reply.latency_datacenter_ids_p2p_size()) {
            /* The original propagates all cached edges, before exceptions,
             * without replacing a reverse edge measured directly. */
            for (size_t i=0; i<r->interior.count; ++i)
                for (auto &other : probe->relays)
                    if (other.pop_id == r->interior.entries[i].pop)
                        sl_sdr_latency_estimate(&other.interior, r->pop_id, r->interior.entries[i].ping);
            for (const auto &exception : reply.route_exceptions())
                sl_sdr_latency_exception(&r->interior, exception.data_center_id(), exception.flags(),
                    int32_t(exception.penalty()));
        }
        if (reply.has_challenge()) {
            r->challenge = reply.challenge();
            r->server_time = reply.server_time();
            r->challenge_at = packet.m_usecNow;
        }
        ++probe->counters.valid_ping_replies;
    } else if (data[0] == 25) {
        CMsgSteamDatagramP2PSessionEstablished reply;
        ConnectionScopeLock connection_lock;
        CSteamNetworkConnectionBase *connection = GetConnectionByHandle(probe->connection, connection_lock);
        if (!connection || !reply.ParseFromArray(data + 1, packet.m_cbPkt - 1) ||
            reply.connection_id() != connection->m_unConnectionIDLocal || reply.relay_routing_token().empty())
            return;
        r->request_until = 0;
        if (reply.has_seconds_until_shutdown()) warn_downtime(*r, reply.seconds_until_shutdown(), packet.m_usecNow);
        r->received(packet.m_usecNow);
        int action = sl_sdr_established_action(int(connection->GetState()));
        if (action != SL_SDR_STATE_THINK) {
            if (action == SL_SDR_STATE_CLOSE)
                send_closed(probe, *connection, *r, false, r->stats.IsActive(),
                    static_cast<void *>(connection->m_pTransport) == probe->owner, false);
            return;
        }
        r->closed_by_relay = false;
        if (!r->established)
            ++probe->counters.established;
        r->established = true;
        r->routing_token = reply.relay_routing_token();
        if (reply.seq_num_r2c()) {
            r->stats.InitMaxRecvPktNum(reply.seq_num_r2c() - 1);
            int64 sequence = r->stats.ExpandWirePacketNumberAndCheck(uint16_t(reply.seq_num_r2c()), 0);
            if (sequence > 0)
                r->stats.TrackProcessSequencedPacket(sequence, packet.m_usecNow, 0, 0);
        }
        r->received(packet.m_usecNow);
        r->request_until = 0;
        r->request_failures = 0;
        /* The token is deliberately not exposed or logged by this driver. */
    } else if (data[0] == 7) {
        CMsgSteamDatagramNoSessionRelayToClient reply;
        ConnectionScopeLock connection_lock;
        CSteamNetworkConnectionBase *connection = GetConnectionByHandle(probe->connection, connection_lock);
        if (!connection || !reply.ParseFromArray(data + 1, packet.m_cbPkt - 1) ||
            reply.connection_id() != connection->m_unConnectionIDLocal)
            return;
        if (reply.has_challenge()) {
            r->challenge = reply.challenge();
            r->server_time = reply.server_time();
            r->challenge_at = packet.m_usecNow;
        }
        if (reply.has_seconds_until_shutdown()) warn_downtime(*r, reply.seconds_until_shutdown(), packet.m_usecNow);
        ++probe->counters.rejected;
        r->received(packet.m_usecNow);
        r->request_until = 0;
        r->established = false;
        r->routing_token.clear();
    }
    if (probe->owner_receive)
        probe->owner_receive(packet, *r, probe->owner);
}
static sl_sdr_probe *make_network(uint32_t handle, const sl_sdr_config &config) {
    std::unique_ptr<sl_sdr_probe> p(new sl_sdr_probe);
    p->connection = handle;
    p->config = config;
    p->initialized_at = SteamNetworkingSockets_GetLocalTimestamp();
    for (size_t i = 0; i < p->config.pop_count; ++i) {
        const sl_sdr_pop &pop = p->config.pops[i];
        uint32_t slots = 0;
        for (size_t k = 0; k < pop.endpoint_count; ++k) {
            const sl_sdr_endpoint &ep = p->config.endpoints[pop.first_endpoint + k];
            slots += uint32_t(ep.port_max) - ep.port_min + 1;
        }
        if (!slots)
            continue;
        uint32_t slot = random_below(slots);
        for (size_t k = 0; k < pop.endpoint_count; ++k) {
            const sl_sdr_endpoint &ep = p->config.endpoints[pop.first_endpoint + k];
            uint32_t count = uint32_t(ep.port_max) - ep.port_min + 1;
            if (slot >= count) {
                slot -= count;
                continue;
            }
            p->relays.emplace_back();
            ProbeRelay &r = p->relays.back();
            r.pop_id = pop.id;
            r.address.SetIPAndPort(ep.ipv4, uint16_t(ep.port_min + slot));
            CCrypto::GenerateRandomBlock(&r.cookie, sizeof(r.cookie));
            break;
        }
    }
    SteamNetworkingIPAddr local;
    local.Clear();
    int family = k_nAddressFamily_IPv4;
    SteamNetworkingErrMsg error;
    p->socket = OpenRawUDPSocket(CRecvPacketCallback(receive_packet, p.get()), error, &local, &family);
    if (!p->socket)
        return nullptr;
    return p.release();
}
static const sl_sdr_pop *find_pop(const sl_sdr_config &config, uint32_t id) {
    for (size_t i = 0; i < config.pop_count; ++i)
        if (config.pops[i].id == id) return &config.pops[i];
    return nullptr;
}
static unsigned address_count(const sl_sdr_probe *p, const ProbeRelay &r) {
    const auto *pop = find_pop(p->config, r.pop_id);
    unsigned count = 0;
    if (pop)
        for (size_t k = 0; k < pop->endpoint_count; ++k) {
            const auto &ep = p->config.endpoints[pop->first_endpoint + k];
            count += unsigned(ep.port_max) - ep.port_min + 1;
        }
    return count;
}
static bool choose_address(sl_sdr_probe *p, ProbeRelay &r, SteamNetworkingMicroseconds now) {
    const auto *pop = find_pop(p->config, r.pop_id);
    unsigned total = address_count(p, r);
    if (!pop || !total) return false;
    sl_sdr_expire_addresses(&r.failures, total, now);
    for (unsigned attempt = 0; attempt < 99; ++attempt) {
        unsigned slot = random_below(total);
        for (size_t k = 0; k < pop->endpoint_count; ++k) {
            const auto &ep = p->config.endpoints[pop->first_endpoint + k];
            unsigned count = unsigned(ep.port_max) - ep.port_min + 1;
            if (slot >= count) { slot -= count; continue; }
            uint16_t port = uint16_t(ep.port_min + slot);
            if (sl_sdr_address_failed(&r.failures, uint64_t(ep.ipv4) << 16 | port)) break;
            r.address.SetIPAndPort(ep.ipv4, port);
            return true;
        }
    }
    return false;
}
static bool send_ping(sl_sdr_probe *p, ProbeRelay &r, SteamNetworkingMicroseconds now) {
    if (r.ping_deadline || (r.downtime.known && r.downtime.avoid < now)) return false;
    uint8_t ping[1300];
    sl_sdr_ping(ping, sizeof(ping), false, now, r.cookie, uint32_t(p->config.revision),
        r.address.GetIPv4(), r.address.GetPort());
    r.ping_timestamp = uint32_t(now);
    r.ping_sent = r.failures.last_probe = r.front.m_usecTimeLastSentPingRequest = now;
    r.ping_deadline = now + r.front.CalcConservativeTimeout();
    ++r.probes_sent;
    if (!send_packet(p, ping, sizeof(ping), r.address)) return false;
    ++p->counters.sent_pings;
    return true;
}
static bool pursue_sessions(sl_sdr_probe *p, CSteamNetworkConnectionBase *connection,
    const std::vector<ProbeRelay *> &candidates, unsigned quota, SteamNetworkingMicroseconds now) {
    bool started = false;
    for (ProbeRelay *r : candidates) {
        if (!quota) break;
        if (r->established && !(r->downtime.known && r->downtime.avoid <= now)) { --quota; continue; }
        if (r->downtime.known && r->downtime.avoid < now) continue;
        if (r->challenge && r->challenge_at + 10000000 < now) r->challenge = 0;
        bool ready = r->challenge && r->server_time && r->last_received &&
            r->last_received + 20000000 >= now && r->front.m_nValidPings >= 3 &&
            r->front.TimeRecvMostRecentPing() + 20000000 >= now && !r->ping_failures;
        if (!ready) {
            send_ping(p, *r, now);
            if (r->ping_failures < 2) { --quota; started = true; }
            continue;
        }
        --quota;
        if (r->request_until || started) { started = true; continue; }
        CMsgSteamDatagramP2PSessionRequest request;
        if (!build_request(*connection, *r, p->config, request)) continue;
        size_t bytes = request.ByteSizeLong();
        if (bytes >= 1300) continue;
        uint8_t packet[1300];
        packet[0] = 24;
        request.SerializeToArray(packet + 1, int(bytes));
        r->request_until = now + 750000;
        if (send_packet(p, packet, int(bytes + 1), r->address)) ++p->counters.requests;
        SecureZeroMemory(packet, sizeof(packet));
        started = true;
    }
    return started;
}
static void update_network(sl_sdr_probe *p, CSteamNetworkConnectionBase *connection,
                            SteamNetworkingMicroseconds now) {
    if (now < p->last_round + 100000) return;
    p->last_round = now;
    std::vector<std::pair<float, ProbeRelay *>> priorities;
    int ordinary = 0, measured = 0, fast = 0, medium = 0, broad = 0;
    for (auto &r : p->relays) {
        sl_sdr_expire_addresses(&r.failures, address_count(p, r), now);
        sl_sdr_timeouts timeouts{r.ping_deadline, r.request_until, r.last_received,
            r.ping_failures, r.request_failures, r.established};
        unsigned events = sl_sdr_expire(&timeouts, now);
        r.ping_deadline = timeouts.ping_deadline; r.request_until = timeouts.request_deadline;
        r.ping_failures = timeouts.ping_failures; r.request_failures = timeouts.request_failures;
        if (events & SL_SDR_TIMEOUT_PING) ++r.failures.failures;
        bool shutting_down = r.downtime.known && r.downtime.shutdown <= now;
        if ((events & SL_SDR_TIMEOUT_REMOVE) || shutting_down) {
            sl_sdr_fail_address(&r.failures, r.address_key(), address_count(p, r), now);
            r.established = false; r.routing_token.clear(); r.forward = {};
            r.challenge = 0; r.ping_deadline = r.request_until = 0;
            r.ping_failures = r.request_failures = 0; r.last_received = 0;
            r.stats.Init(now, ELinkActivityLevel::Idle); r.sent_acks.clear();
            if (choose_address(p, r, now)) { r.downtime = {}; r.force_ping = true; }
        }
        if (r.established && r.last_received + 60000000 < now) {
            r.established = false; r.routing_token.clear(); r.forward = {};
        }
        if (events & SL_SDR_TIMEOUT_REPROBE) r.force_ping = true;
        if (r.force_ping && !r.ping_deadline) { send_ping(p, r, now); r.force_ping = false; }
        const auto *pop = find_pop(p->config, r.pop_id);
        ++ordinary;
        if (r.front.m_nTotalPingsReceived >= 2) ++measured;
        if (r.front.m_nTotalPingsReceived > 2 && r.front.m_nValidPings >= 2 && r.failures.reachability == 1) {
            int conservative = r.front.WorstPingInRecentSample();
            fast += conservative < 30; medium += conservative < 75; broad += conservative < 150;
        }
        sl_sdr_probe_input input{r.ping_ms, int(r.probes_sent), r.front.m_nTotalPingsReceived,
            r.front.m_nValidPings, int(r.failures.failures), r.failures.reachability, 1,
            pop ? pop->tier : 1, 0, r.ping_ms < 0 ? 5000.0f + random_below(101) : float(r.ping_ms),
            now-r.ping_sent, now-r.front.TimeRecvMostRecentPing()};
        float priority;
        if (!r.ping_deadline && sl_sdr_probe_priority(&input, !p->have_primary, !p->have_backup, &priority))
            priorities.emplace_back(priority, &r);
    }
    std::stable_sort(priorities.begin(), priorities.end(), [](const auto &a, const auto &b) { return a.first < b.first; });
    unsigned budget = (!p->have_primary || !p->have_backup) ? 10 : 1;
    for (const auto &entry : priorities) {
        if (!budget) break;
        if (send_ping(p, *entry.second, now)) --budget;
    }
    p->good_enough |= sl_sdr_routing_ready(ordinary, measured, fast, medium, broad, now-p->initialized_at);
    if (!p->good_enough) return;
    if (p->owner) {
        pursue_sessions(p, connection, p->pursue, 2, now);
        pursue_sessions(p, connection, p->pursue_token, 1, now);
    } else {
        std::vector<ProbeRelay *> candidates;
        for (auto &r : p->relays) if (r.ping_ms >= 0) candidates.push_back(&r);
        std::stable_sort(candidates.begin(), candidates.end(), [](ProbeRelay *a, ProbeRelay *b) { return a->ping_ms < b->ping_ms; });
        pursue_sessions(p, connection, candidates, 2, now);
    }
}
#if NSL_SNS_PROBES
extern "C" sl_sdr_probe *sl_gns_sdr_probe_create(uint32_t handle, const char *json, size_t size) {
    SteamNetworkingGlobalLock global_lock("nsl relay session probe");
    ConnectionScopeLock connection_lock;
    CSteamNetworkConnectionBase *connection = GetConnectionByHandle(handle, connection_lock);
    if (!connection || !connection->m_unConnectionIDRemote)
        return nullptr;
    std::unique_ptr<sl_sdr_config> config(new sl_sdr_config);
    if (!sl_sdr_config_parse(json, size, config.get()))
        return nullptr;
    return make_network(handle, *config);
}
extern "C" void sl_gns_sdr_probe_update(sl_sdr_probe *p) {
    if (!p)
        return;
    SteamNetworkingGlobalLock global_lock("nsl relay probe update");
    ConnectionScopeLock connection_lock;
    CSteamNetworkConnectionBase *connection = GetConnectionByHandle(p->connection, connection_lock);
    if (connection)
        update_network(p, connection, SteamNetworkingSockets_GetLocalTimestamp());
}
extern "C" void sl_gns_sdr_probe_stats(const sl_sdr_probe *p, sl_sdr_probe_stats *out) {
    if (out)
        *out = p ? p->counters : sl_sdr_probe_stats{};
}
extern "C" void sl_gns_sdr_probe_destroy(sl_sdr_probe *p) {
    if (!p)
        return;
    SteamNetworkingGlobalLock lock("nsl relay probe destroy");
    p->socket->Close();
    delete p;
}

#endif

#ifdef NSL_GNS_SDR
namespace SteamNetworkingSocketsLib {
template<> inline uint32 StatsMsgImpliedFlags<CMsgSteamDatagramConnectionStatsP2PClientToRouter>(
    const CMsgSteamDatagramConnectionStatsP2PClientToRouter &m) {
    return (m.has_quality_relay() ? 1u : 0u) | (m.has_quality_e2e() ? 2u : 0u);
}
namespace {
sl_sdr_config network_config;
bool network_config_ready = false;
class SDRTransport;
std::unordered_map<CSteamNetworkConnectionP2P *, SDRTransport *> transports;
struct SDRSendContext : SendPacketContext<CMsgSteamDatagramConnectionStatsP2PClientToRouter> {
    ProbeRelay *relay = nullptr;
    sl_sdr_routing_fields routing{};
    explicit SDRSendContext(SteamNetworkingMicroseconds now, const char *reason)
        : SendPacketContext(now, reason) {}
};
class SDRTransport final : public CConnectionTransport, public CConnectionTransportP2PBase {
public:
    sl_sdr_probe *network = nullptr;
    ProbeRelay *primary = nullptr, *backup = nullptr;
    sl_sdr_revisions revisions{};
    CMsgSteamDatagramP2PRoutes peer_routes, local_routes;
    std::string last_snapshot;
    int route_ping = 0, route_score = 0;
#if NSL_SNS_PROBES
    unsigned debug[16] = {}, route_generation = 0;
    void count(unsigned index) { ++debug[index]; }
#else
    void count(unsigned) {}
#endif
    explicit SDRTransport(CSteamNetworkConnectionP2P &c)
        : CConnectionTransport(c), CConnectionTransportP2PBase("SDR", this) {}
    ~SDRTransport() override { transports.erase(&conn()); }
    CSteamNetworkConnectionP2P &conn() const {
        return *static_cast<CSteamNetworkConnectionP2P *>(&m_connection);
    }
    void TransportFreeResources() override {
        if (network) {
            network->owner = nullptr;
            network->owner_receive = nullptr;
            network->socket->Close();
            delete network;
            network = nullptr;
        }
        primary = backup = nullptr;
    }
    void TransportConnectionStateChanged(ESteamNetworkingConnectionState old) override {
        CConnectionTransport::TransportConnectionStateChanged(old);
        int action = sl_sdr_state_action(int(ConnectionState()));
        if (action == SL_SDR_STATE_THINK) EnsureP2PTransportThink(k_nThinkTime_ASAP);
        if (action != SL_SDR_STATE_CLOSE || !network) return;
        for (auto &r : network->relays)
            if (r.established && !r.closed_by_relay) {
                bool e2e = (!m_connection.m_pTransport || m_connection.m_pTransport == this) &&
                    (!primary || &r == primary);
                send_closed(network, m_connection, r, e2e, &r == primary,
                    m_connection.m_pTransport == this, true);
            }
    }
    bool BCanSendEndToEndData() const override {
        return primary && primary->established && primary->forward.desired_size;
    }
    void TransportPopulateConnectionInfo(SteamNetConnectionInfo_t &info) const override {
        info.m_nFlags |= k_nSteamNetworkConnectionInfoFlags_Relayed;
        if (primary)
            info.m_idPOPRelay = primary->pop_id;
    }
    void select_routes(SteamNetworkingMicroseconds now) {
        std::vector<std::pair<int, ProbeRelay *>> any, token_routes;
        sl_sdr_candidate metrics[SL_SDR_CANDIDATES] = {};
        ProbeRelay *relays[SL_SDR_CANDIDATES] = {};
        int pings[SL_SDR_CANDIDATES] = {};
        bool desired[SL_SDR_CANDIDATES] = {};
        int current = -1, old_backup = -1;
        size_t count = 0;
        for (auto &r : network->relays) {
            if (count == SL_SDR_CANDIDATES) break;
            int score = SL_SDR_UNKNOWN, comparison = INT_MAX, any_comparison = INT_MAX, ping = 0;
            const CMsgSteamDatagramP2PRoutes_RelayCluster *target = nullptr;
            int interior_score = 0;
            for (const auto &peer : peer_routes.relay_clusters()) {
                if (r.ping_ms < 0 || !find_pop(network->config, peer.pop_id()) || peer.ping_ms() > 10000 ||
                    peer.session_relay_routing_token().size() > SL_SDR_TOKEN_MAX) continue;
                int interior = 0;
                if (peer.pop_id() != r.pop_id) {
                    const auto *edge = sl_sdr_latency_find(&r.interior, peer.pop_id());
                    if (!edge || edge->ping < 0 || edge->ping > 10000) continue;
                    interior = edge->ping;
                }
                const auto *edge = sl_sdr_latency_find(&r.interior, peer.pop_id());
                int edge_penalty = peer.pop_id() != r.pop_id && edge ? edge->penalty : 0;
                int front = r.ping_ms + int(peer.ping_ms());
                int64 forward = int64(front) + front / 10 + interior + edge_penalty + r.penalty + peer.score_penalty();
                if (forward >= SL_SDR_UNKNOWN) continue;
                int reverse = SL_SDR_UNKNOWN;
                for (const auto &route : peer_routes.routes()) {
                    if (route.my_pop_id() != peer.pop_id() || route.your_pop_id() != r.pop_id) continue;
                    int64 value = route.has_interior_score()
                        ? int64(front) + front / 10 + r.penalty + peer.score_penalty() + route.interior_score()
                        : route.has_legacy_score() ? int64(route.legacy_score()) : INT_MAX;
                    reverse = value < INT_MAX ? int(value) : INT_MAX;
                }
                int combined = sl_sdr_comparison_score(int(forward), reverse);
                any_comparison = std::min(any_comparison, combined);
                if (!peer.session_relay_routing_token().empty() && combined < comparison) {
                    comparison = combined; score = int(forward); ping = front + interior;
                    interior_score = interior + edge_penalty;
                    target = &peer;
                }
            }
            if (target) {
                const auto &token = target->session_relay_routing_token();
                sl_sdr_target_desire(&r.forward, reinterpret_cast<const uint8_t *>(token.data()), token.size(), target->pop_id());
                token_routes.emplace_back(comparison, &r);
            } else sl_sdr_target_desire(&r.forward, nullptr, 0, 0);
            if (any_comparison < INT_MAX) any.emplace_back(any_comparison, &r);
            else if (!peer_routes.relay_clusters_size() && r.ping_ms >= 0) any.emplace_back(r.ping_ms, &r);
            auto &m = metrics[count];
            relays[count] = &r; pings[count] = ping;
            desired[count] = r.established && r.forward.desired_size;
            if (&r == primary) current = int(count);
            if (&r == backup && r.established && target) old_backup = int(count);
            int low, high;
            m.buckets = r.front.GetPingRangeFromRecentBuckets(low, high, now);
            int64 other = 0;
            m.shutdown_seconds = INT_MAX;
            if (r.downtime.known) {
                int64 remaining = r.downtime.shutdown - now;
                m.shutdown_seconds = int(remaining >= 0 ? remaining / 1000000 : -((-remaining + 999999) / 1000000));
                if (m.shutdown_seconds <= 0) other += 1000;
                else if (m.shutdown_seconds < 30) other += (30 - m.shutdown_seconds) * 1000 / 30;
                m.draining = r.downtime.avoid <= now;
            }
            if (r.stats.m_nReplyTimeoutsSinceLastRecv && r.last_received + 500000 < now) {
                m.gap = now-r.last_received;
                if (m.gap > 1750000) other += 100;
            }
            int remote = target ? int(target->ping_ms()) : 0;
            int penalties = r.penalty + (target ? int(target->score_penalty()) : 0) + int(other);
            auto value = [&](int local) { int internet = local + remote; return internet + internet/10 + interior_score + penalties; };
            m.score = score + int(other); m.minimum = value(low); m.maximum = value(high);
            m.other_penalty = int(other);
            m.front_samples = r.front.m_nValidPings;
            m.cluster = int(r.pop_id); m.eligible = r.established && target && m.score < SL_SDR_UNKNOWN;
            m.last_received = r.last_received;
            m.front_oldest = r.front.m_arPing[2].m_usecTimeRecv;
            m.last_ping_sent = r.ping_sent;
            m.bucket_end = r.front.m_arTimeBuckets[r.front.m_idxCurrentBucket].m_usecEnd;
            m.ping_pending = r.ping_deadline != 0;
            ++count;
        }
        auto order = [](const auto &a, const auto &b) { return a.first < b.first; };
        std::stable_sort(any.begin(), any.end(), order);
        std::stable_sort(token_routes.begin(), token_routes.end(), order);
        network->pursue.clear(); network->pursue_token.clear();
        for (const auto &candidate : any) network->pursue.push_back(candidate.second);
        for (const auto &candidate : token_routes) network->pursue_token.push_back(candidate.second);
        sl_sdr_selection selected;
        sl_sdr_clean_active(desired, count, &current, &old_backup);
        if (!sl_sdr_select(metrics, count, current, old_backup, false, now, &selected)) return;
        ProbeRelay *next = selected.primary >= 0 ? relays[selected.primary] : nullptr;
        backup = selected.backup >= 0 ? relays[selected.backup] : nullptr;
        for (size_t i = 0; i < count; ++i) if (selected.probe[i]) relays[i]->force_ping = true;
        if (primary != next) {
#if NSL_SNS_PROBES
            ++route_generation;
#endif
            primary = next;
            conn().m_usecNextEvaluateTransport = k_nThinkTime_ASAP;
            conn().SetNextThinkTimeASAP();
        }
        network->have_primary = primary != nullptr; network->have_backup = backup != nullptr;
        route_ping = primary ? pings[selected.primary] : 0;
        route_score = primary ? metrics[selected.primary].score : SL_SDR_UNKNOWN;
        for (auto &r : network->relays)
            r.stats.SetActivityLevel(&r == primary ? ELinkActivityLevel::Active : ELinkActivityLevel::Idle, now);
    }
    void rebuild_routes() {
        CMsgSteamDatagramP2PRoutes snapshot;
        for (const auto &r : network->relays) {
            if (!r.established || r.routing_token.empty())
                continue;
            auto *cluster = snapshot.add_relay_clusters();
            cluster->set_pop_id(r.pop_id);
            cluster->set_ping_ms(std::max(0, r.ping_ms));
            cluster->set_score_penalty(r.penalty);
            cluster->set_session_relay_routing_token(r.routing_token);
            for (const auto &peer : peer_routes.relay_clusters()) {
                const auto *interior = sl_sdr_latency_find(&r.interior, peer.pop_id());
                if (peer.pop_id() != r.pop_id && (!interior || interior->ping < 0))
                    continue;
                int64 interior_score = peer.pop_id() == r.pop_id ? 0 : int64(interior->ping)+interior->penalty;
                if (interior_score < INT_MIN || interior_score > INT_MAX) continue;
                auto *route = snapshot.add_routes();
                route->set_my_pop_id(r.pop_id);
                route->set_your_pop_id(peer.pop_id());
                route->set_interior_score(int(interior_score));
            }
        }
        std::string bytes = snapshot.SerializeAsString();
        if (bytes != last_snapshot) {
            last_snapshot = std::move(bytes);
            ++revisions.local;
            snapshot.set_revision(revisions.local);
            local_routes = std::move(snapshot);
            revisions.retry_us = 0;
            conn().ScheduleSendSignal("SDR routing snapshot");
        }
    }
    void recv_routes(const std::string &bytes) {
        CMsgSteamDatagramP2PRoutes message;
        bool parsed = message.ParseFromString(bytes);
        if (sl_sdr_routes_received(&revisions, parsed, message.revision())) {
            peer_routes = std::move(message);
            select_routes(SteamNetworkingSockets_GetLocalTimestamp());
            rebuild_routes();
        }
        EnsureP2PTransportThink(k_nThinkTime_ASAP);
    }
    void populate(SDRSendContext &ctx, ProbeRelay &r, EStatsReplyRequest request, bool force) {
        ctx.relay = &r;
        bool target = sl_sdr_target_populate(&r.forward);
        ctx.routing = sl_sdr_routes_populate_stats(&revisions, target, r.forward.acknowledged,
            &r == primary, m_connection.m_pTransport == this, force,
            m_bNeedToConfirmEndToEndConnectivity, uint64_t(ctx.m_usecNow));
        auto &m = ctx.msg;
        if (ctx.routing.forward) {
            m.set_forward_target_relay_routing_token(r.forward.sent, r.forward.sent_size);
            m.set_forward_target_revision(r.forward.revision);
        }
        if (ctx.routing.peer_ack)
            m.set_ack_peer_routes_revision(revisions.peer);
        if (ctx.routing.routes)
            m.set_routes(local_routes.SerializeAsString());
        uint32_t acks[5];
        size_t count = sl_sdr_ack_pack(&r.acks, uint64_t(ctx.m_usecNow), acks);
        for (size_t i = 0; i < count; ++i)
            m.add_ack_relay(acks[i]);
        ctx.m_nFlags = ctx.routing.flags;
        if (request >= k_EStatsReplyRequest_DelayedOK) {
            ctx.m_nFlags |= 1;
            if (ctx.routing.e2e_mode == 2)
                ctx.m_nFlags |= 2;
        }
        if (request == k_EStatsReplyRequest_Immediate)
            ctx.m_nFlags |= 4;
        int need = r.stats.GetStatsSendNeed(ctx.m_usecNow);
        if (need)
            r.stats.PopulateMessage(need, *m.mutable_quality_relay(), ctx.m_usecNow);
        if (ctx.routing.e2e_mode) {
            int e2e_need = m_connection.m_statsEndToEnd.GetStatsSendNeed(ctx.m_usecNow);
            if (e2e_need)
                m_connection.m_statsEndToEnd.PopulateMessage(e2e_need, *m.mutable_quality_e2e(), ctx.m_usecNow);
        }
        ctx.SlamFlagsAndCalcSize();
        ctx.CalcMaxEncryptedPayloadSize(9, &m_connection);
    }
    void track(SDRSendContext &ctx) {
        ProbeRelay &r = *ctx.relay;
        const auto &m = ctx.msg;
        uint32_t flags = m.flags() | StatsMsgImpliedFlags(m);
        bool delayed = !(flags & 4);
        if (m.ack_relay_size())
            sl_sdr_ack_commit(&r.acks);
        if (m.has_quality_relay())
            r.stats.TrackSentStats(m.quality_relay(), ctx.m_usecNow, delayed);
        else if (flags & 1)
            r.stats.TrackSentMessageExpectingSeqNumAck(ctx.m_usecNow, delayed);
        if ((flags & 1) || m.has_quality_relay()) {
            /* RTT samples older than the accepted 3s window cannot contribute.
             * The count cap is a local memory bound, not a wire constant. */
            while (!r.sent_acks.empty() && (r.sent_acks.size() >= 256 ||
                r.sent_acks.front().second + 3000000 < ctx.m_usecNow))
                r.sent_acks.pop_front();
            r.sent_acks.emplace_back(uint16_t(r.stats.m_nNextSendSequenceNumber - 1), ctx.m_usecNow);
        }
        if (m.has_quality_e2e())
            m_connection.m_statsEndToEnd.TrackSentStats(m.quality_e2e(), ctx.m_usecNow, delayed);
        else if (flags & 2)
            m_connection.m_statsEndToEnd.TrackSentMessageExpectingSeqNumAck(ctx.m_usecNow, delayed);
        if ((flags & 2) || m.has_quality_e2e())
            P2PTransportTrackSentEndToEndPingRequest(ctx.m_usecNow, delayed);
        sl_sdr_routes_track_stats(&revisions, ctx.routing, uint64_t(ctx.m_usecNow));
    }
    bool SendDataPacket(SteamNetworkingMicroseconds now) override {
        if (!BCanSendEndToEndData())
            return false;
        SDRSendContext ctx(now, "data");
        populate(ctx, *primary, k_EStatsReplyRequest_NothingToSend, false);
        return m_connection.SNP_SendPacket(this, ctx);
    }
    int SendEncryptedDataChunk(const void *chunk, int size, SendPacketContext_t &base) override {
        auto &ctx = static_cast<SDRSendContext &>(base);
        if (!ctx.relay || size < 0 || size > 1289)
            return 0;
        ProbeRelay &r = *ctx.relay;
        auto previous = m_connection.m_statsEndToEnd.m_usecTimeLastSentSeq;
        sl_sdr_data data{};
        data.connection_id = ConnectionIDLocal();
        data.e2e_sequence = m_connection.m_statsEndToEnd.ConsumeSendPacketNumberAndGetWireFmt(ctx.m_usecNow);
        data.relay_sequence = r.stats.ConsumeSendPacketNumberAndGetWireFmt(ctx.m_usecNow);
        data.sender_spacing_us = previous && ctx.m_usecNow - previous <= 250000
            ? int(ctx.m_usecNow - previous) : -1;
        uint8_t stats[1300], packet[1300];
        size_t remaining = sizeof(packet) - 9 - size - (data.sender_spacing_us >= 0 ? 2 : 0);
        while (ctx.m_cbTotalSize > 0 && size_t(ctx.m_cbTotalSize) >= remaining) {
            auto &m = ctx.msg;
            auto trim = [](CMsgSteamDatagramConnectionQuality *quality) {
                if (quality->has_instantaneous() && quality->has_lifetime()) {
                    quality->clear_instantaneous();
                    return false;
                }
                return true;
            };
            if (m.has_quality_relay()) {
                if (trim(m.mutable_quality_relay())) m.clear_quality_relay();
            } else if (m.has_quality_e2e()) {
                if (trim(m.mutable_quality_e2e())) m.clear_quality_e2e();
            } else {
                ctx.m_cbTotalSize = 0;
                break;
            }
            ctx.SlamFlagsAndCalcSize();
        }
        if (ctx.m_cbTotalSize > 0) {
            if (!ctx.msg.SerializeToArray(stats, sizeof(stats)))
                return 0;
            data.stats = stats;
            data.stats_size = ctx.m_cbMsgSize;
            track(ctx); /* Inline commit precedes the UDP send, including failure. */
        }
        data.chunk = static_cast<const uint8_t *>(chunk);
        data.chunk_size = size;
        size_t sent = sl_sdr_write_data(packet, sizeof(packet), &data);
        if (!sent || !send_packet(network, packet, int(sent), r.address))
            return 0;
        count(8);
        r.stats.TrackSentPacket(int(sent));
        return int(sent);
    }
    void send_stats(ProbeRelay &r, EStatsReplyRequest request, SteamNetworkingMicroseconds now, bool force) {
        SDRSendContext ctx(now, "relay stats");
        populate(ctx, r, request, force);
        if (ConnectionState() == k_ESteamNetworkingConnectionState_Connected &&
            ((ctx.msg.flags() & 2) || ctx.msg.has_quality_e2e() || force ||
             (&r == primary && m_connection.m_pTransport == this && m_connection.SNP_WantsToSendPacket()))) {
            if (m_connection.SNP_SendPacket(this, ctx))
                return;
        }
        ctx.msg.set_connection_id(ConnectionIDLocal());
        ctx.msg.set_seq_num_c2r(r.stats.ConsumeSendPacketNumberAndGetWireFmt(now));
        bool e2e = ctx.routing.e2e_mode && ((ctx.msg.flags() & 2) || ctx.msg.has_quality_e2e() || force);
        if (e2e)
            ctx.msg.set_seq_num_e2e(m_connection.m_statsEndToEnd.ConsumeSendPacketNumberAndGetWireFmt(now));
        uint8_t packet[1300];
        size_t size = ctx.msg.ByteSizeLong();
        if (size >= sizeof(packet))
            return;
        packet[0] = 26;
        ctx.msg.SerializeToArray(packet + 1, int(size));
        if (send_packet(network, packet, int(size + 1), r.address)) {
            count(6);
            r.stats.TrackSentPacket(int(size + 1));
            track(ctx);
            if (e2e)
                m_connection.SNP_SentNonDataPacket(this, int(size + 1), now);
        }
    }
    void SendEndToEndStatsMsg(EStatsReplyRequest request, SteamNetworkingMicroseconds now, const char *) override {
        if (primary)
            send_stats(*primary, request, now, true);
    }
    void valid_e2e(SteamNetworkingMicroseconds now, uint32_t flags) {
        if (!(flags & 16))
            conn().SetPeerSelectedTransport(this);
        P2PTransportTrackRecvEndToEndPacket(now);
        if (BCanSendEndToEndData()) {
            if (m_pingEndToEnd.m_nSmoothedPing < 0)
                m_pingEndToEnd.ReceivedPing(route_ping, now);
            if (m_bNeedToConfirmEndToEndConnectivity)
                P2PTransportEndToEndConnectivityConfirmed(now);
        }
    }
    void recv_stats(ProbeRelay &r, const CMsgSteamDatagramConnectionStatsP2PRouterToClient &m,
                    uint16_t relay_sequence, SteamNetworkingMicroseconds now) {
        if (m.has_seconds_until_shutdown()) warn_downtime(r, m.seconds_until_shutdown(), now);
        if (m.has_scoring_penalty_relay_cluster())
            r.penalty = std::min(5000u, m.scoring_penalty_relay_cluster());
        if (m.has_ack_forward_target_revision())
            sl_sdr_target_ack(&r.forward, m.ack_forward_target_revision());
        if (m.has_routes())
            recv_routes(m.routes());
        if (m.has_ack_peer_routes_revision())
            sl_sdr_routes_ack(&revisions, m.ack_peer_routes_revision());
        if (m.has_quality_relay())
            r.stats.ProcessMessage(m.quality_relay(), now);
        if (m.has_quality_e2e())
            m_connection.m_statsEndToEnd.ProcessMessage(m.quality_e2e(), now);
        uint32_t flags = m.flags() | (m.has_quality_relay() ? 1u : 0u) | (m.has_quality_e2e() ? 2u : 0u);
        for (uint32_t packed : m.ack_relay()) {
            uint16_t sequence = uint16_t(packed >> 16);
            if (uint16_t(r.stats.m_pktNumInFlight) == sequence)
                r.stats.InFlightPktAck(now);
            for (auto it = r.sent_acks.begin(); it != r.sent_acks.end(); ++it) {
                int16_t gap = int16_t(it->first - sequence);
                if (gap < -16384 || gap > 16384 || gap > 0)
                    break;
                if (!gap) {
                    auto elapsed = now - it->second - (packed & 65535) * 64;
                    r.sent_acks.erase(it);
                    int ms = int(elapsed / 1000);
                    if (ms >= -1 && ms <= 3000)
                        r.stats.ReceivedPing(std::max(0, ms), now);
                    break;
                }
            }
        }
        if (flags & 1) {
            sl_sdr_ack_queue(&r.acks, relay_sequence, uint64_t(now), flags & 4);
            uint64_t deadline = sl_sdr_ack_deadline(&r.acks);
            EnsureP2PTransportThink(deadline ? SteamNetworkingMicroseconds(deadline) : k_nThinkTime_ASAP);
        }
        if (m.has_seq_num_e2e()) {
            valid_e2e(now, flags);
            if (flags & 2) {
                m_connection.QueueEndToEndAck(flags & 4, now);
                if ((flags & 4) || m_connection.m_pTransport != this)
                    send_stats(r, k_EStatsReplyRequest_NoReply, now, true);
            }
        }
    }
    void receive(const RecvPktInfo_t &packet, ProbeRelay &r) {
        const uint8_t *data = static_cast<const uint8_t *>(packet.m_pPkt);
        auto now = packet.m_usecNow;
        if (data[0] == 25 || data[0] == 7 || data[0] == 2) {
            select_routes(now);
            rebuild_routes();
            EnsureP2PTransportThink(k_nThinkTime_ASAP);
            return;
        }
        if (data[0] == 28) {
            count(15);
            CMsgSteamDatagramP2PBadRouteRouterToClient m;
            if (!m.ParseFromArray(data + 1, packet.m_cbPkt - 1) || m.connection_id() != ConnectionIDLocal())
                return;
            for (auto &peer : *peer_routes.mutable_relay_clusters())
                if (peer.session_relay_routing_token() == m.failed_relay_routing_token()) {
                    peer.clear_session_relay_routing_token();
                    select_routes(now);
                    break;
                }
            return;
        }
        if (!r.established)
            return;
        if (data[0] == 20) {
            CMsgSteamDatagramConnectionClosed m;
            if (!m.ParseFromArray(data+1, packet.m_cbPkt-1) || m.to_connection_id() != ConnectionIDLocal() ||
                (m.from_connection_id() && m.from_connection_id() != ConnectionIDRemote())) return;
            r.closed_by_relay = true;
            r.received(now);
            if (m.has_quality_relay()) r.stats.ProcessMessage(m.quality_relay(), now);
            if (m.has_quality_e2e()) m_connection.m_statsEndToEnd.ProcessMessage(m.quality_e2e(), now);
            if (m.relay_mode() == CMsgSteamDatagramConnectionClosed::EndToEnd)
                m_connection.m_statsEndToEnd.TrackRecvPacket(packet.m_cbPkt, now);
            m_connection.ConnectionState_ClosedByPeer(m.reason_code(), m.debug().c_str());
            CMsgSteamDatagramNoConnection ack;
            ack.set_from_connection_id(m.to_connection_id());
            if (m.from_connection_id()) ack.set_to_connection_id(m.from_connection_id());
            if (m.relay_mode() == CMsgSteamDatagramConnectionClosed::EndToEnd) ack.set_end_to_end(true);
            ack.set_not_primary_session(&r != primary);
            ack.set_not_primary_transport(m_connection.m_pTransport != this);
            ack.set_relay_override_active(false);
            r.stats.PopulateLifetimeMessage(*ack.mutable_quality_relay()->mutable_lifetime());
            m_connection.m_statsEndToEnd.PopulateLifetimeMessage(*ack.mutable_quality_e2e()->mutable_lifetime());
            uint8_t reply[1300]; size_t size = ack.ByteSizeLong();
            if (size < sizeof(reply)) {
                reply[0] = 21; ack.SerializeToArray(reply+1, int(size));
                send_packet(network, reply, int(size+1), r.address);
            }
        } else if (data[0] == 21) {
            CMsgSteamDatagramNoConnection m;
            if (!m.ParseFromArray(data+1, packet.m_cbPkt-1) || m.to_connection_id() != ConnectionIDLocal() ||
                (m.from_connection_id() && m.from_connection_id() != ConnectionIDRemote())) return;
            r.closed_by_relay = true;
            r.received(now);
            if (m.has_quality_relay()) r.stats.ProcessMessage(m.quality_relay(), now);
            if (m.has_quality_e2e()) m_connection.m_statsEndToEnd.ProcessMessage(m.quality_e2e(), now);
            m_connection.ConnectionState_ClosedByPeer(5010, "Peer has no connection");
        } else if (data[0] == 26) {
            count(7);
            CMsgSteamDatagramConnectionStatsP2PRouterToClient m;
            if (!m.ParseFromArray(data + 1, packet.m_cbPkt - 1) ||
                m.connection_id() != ConnectionIDLocal() || !m.has_seq_num_r2c())
                return;
            int64 relay = r.stats.ExpandWirePacketNumberAndCheck(uint16_t(m.seq_num_r2c()), 0);
            int64 e2e = m.has_seq_num_e2e() ? m_connection.m_statsEndToEnd.ExpandWirePacketNumberAndCheckMaybeInitialize(
                uint16_t(m.seq_num_e2e()), 0) : 1;
            if (relay <= 0 || e2e <= 0)
                return;
            if (m.has_seq_num_e2e())
                m_connection.RecvNonDataSequencedPacket(e2e, now);
            r.stats.TrackRecvPacket(packet.m_cbPkt, now);
            r.stats.TrackProcessSequencedPacket(relay, now, 0, 0);
            r.received(now);
            recv_stats(r, m, uint16_t(m.seq_num_r2c()), now);
        } else if ((data[0] & 0xe0) == 0x40) {
            count(9);
            sl_sdr_data d;
            if (!sl_sdr_parse_data(data, packet.m_cbPkt, &d) || d.connection_id != ConnectionIDLocal())
                return;
            CMsgSteamDatagramConnectionStatsP2PRouterToClient m;
            if (d.stats && !m.ParseFromArray(d.stats, int(d.stats_size)))
                return;
            int64 relay = r.stats.ExpandWirePacketNumberAndCheck(d.relay_sequence, 0);
            if (relay <= 0)
                return;
            RecvPacketContext_t ctx;
            ctx.m_usecNow = now;
            ctx.m_pTransport = this;
            if (!m_connection.DecryptDataChunk(d.e2e_sequence, packet.m_cbPkt, d.chunk, int(d.chunk_size), ctx)) {
                count(10);
                return;
            }
            r.stats.TrackRecvPacket(packet.m_cbPkt, now);
            r.stats.TrackProcessSequencedPacket(relay, now, d.relay_spacing_us, 0);
            r.received(now);
            valid_e2e(now, m.flags());
            if (!m_connection.ProcessPlainTextDataChunk(d.sender_spacing_us, ctx))
                return;
            if (d.stats) {
                m.set_seq_num_e2e(d.e2e_sequence);
                recv_stats(r, m, d.relay_sequence, now);
            }
        }
    }
    static void received(const RecvPktInfo_t &packet, ProbeRelay &relay, void *ctx) {
        auto *self = static_cast<SDRTransport *>(ctx);
        ConnectionScopeLock lock;
        auto *connection = GetConnectionByHandle(self->network->connection, lock);
        if (connection == &self->m_connection)
            self->receive(packet, relay);
    }
    void P2PTransportUpdateRouteMetrics(SteamNetworkingMicroseconds now) override {
        if (!BCanSendEndToEndData() || m_pingEndToEnd.m_nSmoothedPing < 0) {
            m_routeMetrics.SetInvalid();
            return;
        }
        int low, high;
        m_routeMetrics.m_nBucketsValid = m_pingEndToEnd.GetPingRangeFromRecentBuckets(low, high, now);
        m_routeMetrics.m_nScoreCurrent = m_pingEndToEnd.m_nSmoothedPing;
        m_routeMetrics.m_nScoreMin = low;
        m_routeMetrics.m_nScoreMax = high;
        m_routeMetrics.m_nTotalPenalty = 10;
    }
    void P2PTransportThink(SteamNetworkingMicroseconds now) override {
        if (!network || ConnectionWireState() < k_ESteamNetworkingConnectionState_Connecting ||
            ConnectionWireState() > k_ESteamNetworkingConnectionState_Connected)
            return;
        update_network(network, &m_connection, now);
        select_routes(now);
        rebuild_routes();
        if (primary && (sl_sdr_routes_due(&revisions, uint64_t(now)) || revisions.ack_pending))
            send_stats(*primary, m_bNeedToConfirmEndToEndConnectivity ? k_EStatsReplyRequest_Immediate
                : k_EStatsReplyRequest_DelayedOK, now, true);
        if (sl_sdr_routes_due(&revisions, uint64_t(now)) || revisions.ack_pending)
            conn().ScheduleSendSignal("SDR routes retry");
        for (auto &r : network->relays) {
            r.stats.Think(now);
            if (!r.established) continue;
            SteamNetworkingMicroseconds next = now + 2000000;
            EStatsReplyRequest request;
            bool send = r.stats.GetSendReasonOrUpdateNextThinkTime(now, request, next) != nullptr;
            if (&r == backup && !r.stats.m_usecInFlightReplyTimeout) {
                SteamNetworkingMicroseconds keepalive = r.last_received + 45000000;
                if (keepalive <= now) { send = true; request = k_EStatsReplyRequest_DelayedOK; }
                else next = std::min(next, keepalive);
            }
            uint64_t ack_deadline = sl_sdr_ack_deadline(&r.acks);
            if (ack_deadline <= uint64_t(now)) {
                if (!send) request = k_EStatsReplyRequest_NoReply;
                send = true;
            } else if (ack_deadline < uint64_t(next)) next = SteamNetworkingMicroseconds(ack_deadline);
            if (send) send_stats(r, request, now, false);
            EnsureP2PTransportThink(next);
        }
        CConnectionTransportP2PBase::P2PTransportThink(now);
        EnsureP2PTransportThink(now + 100000);
    }
};
}
bool NSL_SDR_Configure(const char *json, size_t size) {
    network_config_ready = sl_sdr_config_parse(json, size, &network_config);
    return network_config_ready;
}
bool NSL_SDR_Init(CSteamNetworkConnectionP2P &connection, char *error) {
    if (!network_config_ready) {
        strcpy(error, "SDR network configuration unavailable");
        return false;
    }
    auto *t = new SDRTransport(connection);
    t->network = make_network(connection.m_hConnectionSelf, network_config);
    if (!t->network) {
        delete t;
        strcpy(error, "SDR relay socket initialization failed");
        return false;
    }
    t->network->owner = t;
    t->network->owner_receive = SDRTransport::received;
    connection.m_vecAvailableTransports.push_back(t);
    transports[&connection] = t;
    t->EnsureP2PTransportThink(k_nThinkTime_ASAP);
    return true;
}
void NSL_SDR_Populate(CSteamNetworkConnectionP2P &connection, CMsgSteamNetworkingP2PRendezvous &m, long long now) {
    auto it = transports.find(&connection);
    if (it == transports.end())
        return;
    auto &t = *it->second;
    t.rebuild_routes();
    auto fields = sl_sdr_routes_rendezvous(&t.revisions, m.has_connection_closed(), uint64_t(now));
    m.set_ack_peer_routes_revision(t.revisions.peer);
    if (fields.routes)
        m.set_sdr_routes(t.local_routes.SerializeAsString());
}
void NSL_SDR_Process(CSteamNetworkConnectionP2P &connection, const CMsgSteamNetworkingP2PRendezvous &m, long long) {
    auto it = transports.find(&connection);
    if (it == transports.end())
        return;
    auto &t = *it->second;
    if (m.has_sdr_routes())
        t.recv_routes(m.sdr_routes());
    if (m.has_ack_peer_routes_revision())
        sl_sdr_routes_ack(&t.revisions, m.ack_peer_routes_revision());
}
long long NSL_SDR_Wait(CSteamNetworkConnectionP2P &connection, long long now) {
    auto it = transports.find(&connection);
    if (it == transports.end())
        return now;
    auto &t = *it->second;
    auto until = connection.GetTimeEnteredConnectionState() + 7000001;
    if (!t.network->good_enough && now < until)
        return std::min<long long>(now + 20000, until);
    if (connection.GetState() == k_ESteamNetworkingConnectionState_FindingRoute &&
        t.network->counters.established == 0 && t.peer_routes.relay_clusters_size()) {
        until = connection.GetTimeEnteredConnectionState() + 100000;
        if (now < until)
            return std::min<long long>(now + 20000, until);
    }
    return now;
}
#if NSL_SNS_PROBES
extern "C" bool sl_gns_sdr_test_terminal(uint32_t handle, int which) {
    if (which < 1 || which > 5) return false;
    SteamNetworkingGlobalLock global("nsl SDR terminal fixture");
    sl_sdr_probe *network = nullptr;
    netadr_t source;
    uint32_t local = 0, remote = 0;
    {
        ConnectionScopeLock lock;
        auto *base = GetConnectionByHandle(handle, lock);
        auto *connection = base ? base->AsSteamNetworkConnectionP2P() : nullptr;
        auto it = transports.find(connection);
        if (it == transports.end() || !it->second->primary) return false;
        network = it->second->network; source = it->second->primary->address;
        local = connection->m_unConnectionIDLocal; remote = connection->m_unConnectionIDRemote;
    }
    uint8_t packet[1300]; size_t size;
    if (which == 2) {
        CMsgSteamDatagramNoConnection m;
        m.set_to_connection_id(local); m.set_from_connection_id(remote); m.set_end_to_end(true);
        size = m.ByteSizeLong(); packet[0] = 21; m.SerializeToArray(packet+1, int(size));
    } else {
        CMsgSteamDatagramConnectionClosed m;
        m.set_to_connection_id(which == 3 ? local^1 : local);
        m.set_from_connection_id(which == 4 ? remote^1 : remote);
        m.set_relay_mode(CMsgSteamDatagramConnectionClosed::EndToEnd);
        m.set_reason_code(1042); m.set_debug("synthetic terminal fixture");
        size = m.ByteSizeLong(); packet[0] = 20; m.SerializeToArray(packet+1, int(size));
        if (which == 5) source.SetIPAndPort(0x7f000001, 1);
    }
    RecvPktInfo_t received{};
    received.m_pPkt = packet; received.m_cbPkt = int(size+1); received.m_adrFrom = source;
    received.m_usecNow = SteamNetworkingSockets_GetLocalTimestamp(); received.m_pSock = network->socket;
    receive_packet(received, network);
    ConnectionScopeLock lock;
    auto *connection = GetConnectionByHandle(handle, lock);
    return connection && (which >= 3 ? connection->GetState() == k_ESteamNetworkingConnectionState_Connected
        : connection->GetState() == k_ESteamNetworkingConnectionState_ClosedByPeer);
}
extern "C" bool sl_gns_sdr_test_loss(uint32_t handle, int mode, unsigned out[5]) {
    if (mode < -1 || mode > 1 || !out) return false;
    SteamNetworkingGlobalLock global("nsl SDR loss fixture");
    ConnectionScopeLock lock;
    auto *base = GetConnectionByHandle(handle, lock);
    auto *connection = base ? base->AsSteamNetworkConnectionP2P() : nullptr;
    auto it = transports.find(connection);
    if (it == transports.end()) return false;
    auto &t = *it->second;
    auto &n = *t.network;
    if (mode == 1) {
        if (!t.primary || !t.backup || !t.BCanSendEndToEndData() || n.drop_enabled) return false;
        n.drop_address = t.primary->address;
        n.drop_pop = t.primary->pop_id;
        n.drop_enabled = true;
    } else if (mode == 0) n.drop_enabled = false;
    out[0] = t.route_generation; out[1] = n.dropped_tx; out[2] = n.dropped_rx;
    out[3] = t.BCanSendEndToEndData() && (!n.drop_enabled || t.primary->address != n.drop_address);
    out[4] = t.primary && t.primary->pop_id != n.drop_pop;
    return true;
}
extern "C" bool sl_gns_sdr_transport_stats(uint32_t handle, unsigned out[16]) {
    SteamNetworkingGlobalLock global("nsl SDR diagnostics");
    ConnectionScopeLock lock;
    auto *base = GetConnectionByHandle(handle, lock);
    auto *connection = base ? base->AsSteamNetworkConnectionP2P() : nullptr;
    auto it = transports.find(connection);
    if (it == transports.end())
        return false;
    auto &t = *it->second;
    memcpy(out, t.debug, sizeof(t.debug));
    out[0] = t.network->counters.valid_ping_replies;
    out[1] = t.network->counters.requests;
    out[2] = t.network->counters.established;
    out[3] = unsigned(t.peer_routes.relay_clusters_size());
    out[4] = t.revisions.local;
    out[5] = t.revisions.peer;
    out[11] = t.primary != nullptr;
    out[12] = t.primary && t.primary->forward.acknowledged;
    out[13] = t.primary ? unsigned(t.primary->stats.m_nMaxRecvPktNum) : 0;
    out[14] = t.revisions.ack_pending;
    return true;
}
#endif
}
#endif
