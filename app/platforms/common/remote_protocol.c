#include "remote_protocol.h"
#include "authorization_kx.h"
#include "client_pri.h"
#include "crypto.h"
#include "endianness.h"
#include "remote_wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { PAIR_NONE, PAIR_PIN, PAIR_AUTH, PAIR_CANCEL, PAIR_KNOWN };
struct sl_remote {
    IHS_ClientConfig config;
    uint8_t installation_secret[32];
    char device_name[64];
    sl_remote_callbacks cb;
    void *ctx;
    uint64_t session;
    IHS_SteamUniverse universe;
    bool opening, failed;
    bool pending_start, pending_set;
    unsigned pending_cancel;
    int64_t wall_time, rpc_deadline;
    sl_remote_peer peers[SL_REMOTE_PEERS];
    size_t count;
    int pairing;
    char pin[5];
    uint8_t pair_secret[32], last_auth[32];
    bool have_auth;
    unsigned exchanges;
    int last_auth_result;
    IHS_AuthorizationKeyExchange kx;
    uint32_t pair_request;
    struct {
        bool active, updated;
        sl_remote_peer peer;
        IHS_StreamingRequest request;
        sl_remote_stream_options options;
        uint8_t pin_cipher[64];
        size_t pin_size;
        uint32_t id;
        int64_t next_send;
    } stream;
};
static void erase(void *data, size_t size) {
    volatile uint8_t *p = data;
    while (size--)
        *p++ = 0;
}
static bool envelope(sl_remote *r, unsigned kind, const uint8_t *data, size_t size) {
    uint8_t *packet = malloc(size + 16);
    if (!packet)
        return false;
    sl_proto_writer w = {packet, 0, size + 16, false};
    sl_proto_bytes(&w, kind, data, size);
    bool ok = !w.invalid && r->cb.send(packet, w.size, r->ctx);
    erase(packet, w.size);
    free(packet);
    return ok;
}
static bool session_request(sl_remote *r, unsigned kind) {
    uint8_t body[16];
    sl_proto_writer w = {body, 0, sizeof(body), false};
    sl_proto_fixed64(&w, 1, r->session);
    return envelope(r, kind, body, w.size);
}
static bool subscription(sl_remote *r, const sl_remote_peer *peer, bool enable) {
    uint8_t body[48];
    sl_proto_writer w = {body, 0, sizeof(body), false};
    sl_proto_fixed64(&w, 1, r->session);
    sl_proto_fixed64(&w, 2, peer->steam_id);
    if (enable) {
        sl_proto_fixed64(&w, 3, r->config.deviceId);
        sl_proto_uint(&w, 4, 1);
    }
    bool ok = envelope(r, enable ? 5 : 6, body, w.size);
    if (!ok)
        r->failed = true; /* Recreate the complete subscription set, not a partial one. */
    return ok;
}
sl_remote *sl_remote_create(const IHS_ClientConfig *config, const sl_remote_callbacks *cb,
                            void *ctx) {
    if (!config || !config->deviceId || !config->secretKey || !cb || !cb->send)
        return NULL;
    sl_remote *r = calloc(1, sizeof(*r));
    if (!r)
        return NULL;
    r->config = *config;
    memcpy(r->installation_secret, config->secretKey, 32);
    r->config.secretKey = r->installation_secret;
    snprintf(r->device_name, sizeof(r->device_name), "%s",
             config->deviceName ? config->deviceName : "NSteamLink");
    r->config.deviceName = r->device_name;
    r->cb = *cb;
    r->ctx = ctx;
    return r;
}
void sl_remote_destroy(sl_remote *r) {
    if (r) {
        erase(r, sizeof(*r));
        free(r);
    }
}
bool sl_remote_open(sl_remote *r) {
    if (r->session || r->opening)
        return false;
    r->opening = true;
    r->failed = false;
    return envelope(r, 1, NULL, 0);
}
bool sl_remote_ready(const sl_remote *r) {
    return r && r->session != 0 && !r->failed;
}
bool sl_remote_failed(const sl_remote *r) {
    return r && r->failed;
}
void sl_remote_close(sl_remote *r) {
    bool connected = r->session != 0;
    bool pairing = r->pairing == PAIR_PIN || r->pairing == PAIR_AUTH;
    r->session = 0;
    r->opening = false;
    r->failed = false;
    bool known = r->pairing == PAIR_KNOWN;
    if (!known)
        r->pairing = PAIR_NONE;
    r->pending_start = r->pending_set = false;
    r->pending_cancel = 0;
    if (!r->stream.active) {
        IHS_AuthorizationKeyExchangeClear(&r->kx);
        erase(r->pair_secret, 32);
        erase(r->pin, sizeof(r->pin));
    }
    if (connected && r->cb.connected)
        r->cb.connected(false, r->ctx);
    if (pairing && r->cb.pair_failed)
        r->cb.pair_failed(IHS_AuthorizationOffline, r->ctx);
    /* An in-flight stream request is retained by the owner; envelopes from the
     * dead session are never retained. update can reconstruct on a fresh one. */
}
bool sl_remote_watch(sl_remote *r, const sl_remote_peer *peers, size_t count) {
    if (count > SL_REMOTE_PEERS || (count && !peers))
        return false;
    for (size_t i = 0; i < count; ++i) {
        if (!peers[i].client_id || !peers[i].steam_id)
            return false;
        for (size_t j = 0; j < i; ++j)
            if (peers[i].client_id == peers[j].client_id)
                return false;
    }
    bool ok = true;
    if (r->session) {
        for (size_t i = 0; i < r->count; ++i) {
            bool found = false;
            for (size_t j = 0; j < i; ++j)
                found |= r->peers[i].steam_id == r->peers[j].steam_id;
            for (size_t j = 0; j < count; ++j)
                found |= r->peers[i].steam_id == peers[j].steam_id;
            if (!found)
                ok = subscription(r, &r->peers[i], false) && ok;
        }
        for (size_t i = 0; i < count; ++i) {
            bool found = false;
            for (size_t j = 0; j < i; ++j)
                found |= peers[i].steam_id == peers[j].steam_id;
            for (size_t j = 0; j < r->count; ++j)
                found |= r->peers[j].steam_id == peers[i].steam_id;
            if (!found)
                ok = subscription(r, &peers[i], true) && ok;
        }
    }
    erase(r->peers, sizeof(r->peers));
    if (count)
        memcpy(r->peers, peers, count * sizeof(*peers));
    r->count = count;
    return ok;
}
bool sl_remote_packet(sl_remote *r, uint64_t account, const uint8_t *data, size_t size) {
    if (!sl_remote_ready(r) || !account || size > SL_REMOTE_FRAME_MAX - 64)
        return false;
    uint8_t *body = malloc(size + 64);
    if (!body)
        return false;
    sl_proto_writer w = {body, 0, size + 64, false};
    sl_proto_fixed64(&w, 1, r->session);
    sl_proto_fixed64(&w, 2, account);
    sl_proto_bytes(&w, 4, data, size);
    bool ok = !w.invalid && envelope(r, 7, body, w.size);
    erase(body, w.size);
    free(body);
    return ok;
}
static bool send_message(sl_remote *r, uint64_t account, ERemoteClientBroadcastMsg type,
                         const ProtobufCMessage *message) {
    CMsgRemoteClientBroadcastHeader header = CMSG_REMOTE_CLIENT_BROADCAST_HEADER__INIT;
    header.has_client_id = header.has_msg_type = true;
    header.client_id = r->config.deviceId;
    header.msg_type = type;
    size_t hs = protobuf_c_message_get_packed_size(&header.base);
    size_t ms = protobuf_c_message_get_packed_size(message);
    if (hs + ms > SL_REMOTE_FRAME_MAX - 80)
        return false;
    uint8_t *packet = malloc(hs + ms + 16);
    if (!packet)
        return false;
    static const uint8_t magic[] = {255, 255, 255, 255, 33, 76, 95, 160};
    memcpy(packet, magic, 8);
    IHS_WriteUInt32LE(packet + 8, (uint32_t)hs);
    protobuf_c_message_pack(&header.base, packet + 12);
    IHS_WriteUInt32LE(packet + 12 + hs, (uint32_t)ms);
    protobuf_c_message_pack(message, packet + 16 + hs);
    bool ok = sl_remote_packet(r, account, packet, hs + ms + 16);
    erase(packet, hs + ms + 16);
    free(packet);
    return ok;
}
bool sl_remote_send_signal(sl_remote *r, uint64_t account, const uint8_t *body, size_t size) {
    if (!r || !body || size > SL_REMOTE_FRAME_MAX - 128)
        return false;
    CMsgRemoteDeviceStreamTransportSignal *message =
        cmsg_remote_device_stream_transport_signal__unpack(NULL, size, body);
    if (!message)
        return false;
    bool ok = send_message(r, account, k_ERemoteDeviceStreamTransportSignal, &message->base);
    cmsg_remote_device_stream_transport_signal__free_unpacked(message, NULL);
    return ok;
}
bool sl_remote_pair(sl_remote *r) {
    if (!sl_remote_ready(r) || r->pairing || r->stream.active || r->pending_start ||
        r->pending_set || r->pending_cancel)
        return false;
    r->pairing = PAIR_PIN;
    r->have_auth = false;
    r->exchanges = 0;
    erase(r->pin, sizeof(r->pin));
    r->pending_start = true;
    r->rpc_deadline = r->wall_time + 20;
    if (session_request(r, 2))
        return true;
    r->pending_start = false;
    r->pairing = PAIR_NONE;
    return false;
}
static void cancel_pair_slot(sl_remote *r) {
    if (r->session && session_request(r, 4)) {
        if (!r->pending_start && !r->pending_set && !r->pending_cancel)
            r->rpc_deadline = r->wall_time + 20;
        ++r->pending_cancel;
    }
}
void sl_remote_cancel(sl_remote *r) {
    bool known = r->pairing == PAIR_KNOWN;
    if (r->pairing) {
        if (!known)
            cancel_pair_slot(r);
        /* Outstanding StartPairing cannot be identified by a wire request ID.
         * Retire it before admitting another attempt, and cancel a late PIN. */
        r->pairing = r->pairing == PAIR_PIN ? PAIR_CANCEL : PAIR_NONE;
        IHS_AuthorizationKeyExchangeClear(&r->kx);
        erase(r->pair_secret, 32);
        erase(r->pin, sizeof(r->pin));
    }
    if (r->stream.active) {
        if (known) {
            CMsgRemoteDeviceAuthorizationCancelRequest cancel =
                CMSG_REMOTE_DEVICE_AUTHORIZATION_CANCEL_REQUEST__INIT;
            send_message(r, r->stream.peer.steam_id, k_ERemoteDeviceAuthorizationCancelRequest,
                         &cancel.base);
        } else {
            CMsgRemoteDeviceStreamingCancelRequest cancel =
                CMSG_REMOTE_DEVICE_STREAMING_CANCEL_REQUEST__INIT;
            cancel.request_id = r->stream.id;
            send_message(r, r->stream.peer.steam_id, k_ERemoteDeviceStreamingCancelRequest,
                         &cancel.base);
        }
        r->stream.active = false;
    }
}
static void pairing_failed(sl_remote *r, IHS_AuthorizationResult result) {
    bool known = r->pairing == PAIR_KNOWN;
    r->pairing = PAIR_NONE;
    IHS_AuthorizationKeyExchangeClear(&r->kx);
    erase(r->pair_secret, 32);
    erase(r->pin, sizeof(r->pin));
    if (known) {
        r->stream.active = false;
        if (r->cb.stream_result)
            r->cb.stream_result(result == IHS_AuthorizationDenied ? IHS_StreamingUnauthorized
                                                                  : IHS_StreamingFailed,
                                NULL, r->ctx);
    } else if (r->cb.pair_failed)
        r->cb.pair_failed(result, r->ctx);
}
static bool send_authorization(sl_remote *r, bool publish) {
    uint8_t token[32], id[8], pubkey[384], ticket_bytes[2048], encrypted[2048], auth[32];
    size_t token_size = sizeof(token), pubkey_size = sizeof(pubkey),
           encrypted_size = sizeof(encrypted);
    IHS_WriteUInt64LE(id, r->config.deviceId);
    if (IHS_CryptoSymmetricEncrypt(id, 8, r->pair_secret, 32, token, &token_size) ||
        !IHS_ClientAuthorizationPubKey(NULL, r->universe, pubkey, &pubkey_size))
        return false;
    CMsgRemoteDeviceAuthorizationRequest__CKeyEscrowTicket ticket =
        CMSG_REMOTE_DEVICE_AUTHORIZATION_REQUEST__CKEY_ESCROW__TICKET__INIT;
    ticket.has_password = ticket.has_identifier = ticket.has_payload = ticket.has_usage = true;
    ticket.password = (ProtobufCBinaryData){4, (uint8_t *)r->pin};
    ticket.identifier = r->config.deviceId;
    ticket.payload = (ProtobufCBinaryData){32, r->pair_secret};
    ticket.usage = k_EKeyEscrowUsageStreamingDevice;
    ticket.device_name = r->device_name;
    size_t ticket_size = protobuf_c_message_pack(&ticket.base, ticket_bytes);
    int crypto = IHS_CryptoRSAEncrypt(ticket_bytes, ticket_size, pubkey, pubkey_size, encrypted,
                                      &encrypted_size);
    erase(ticket_bytes, sizeof(ticket_bytes));
    if (crypto)
        return false;
    IHS_AuthorizationKeyExchangeMaskedKey(&r->kx, auth);
    CMsgRemoteDeviceAuthorizationRequest request = CMSG_REMOTE_DEVICE_AUTHORIZATION_REQUEST__INIT;
    request.device_name = r->device_name;
    request.device_token = (ProtobufCBinaryData){token_size, token};
    request.encrypted_request = (ProtobufCBinaryData){encrypted_size, encrypted};
    request.has_auth_key = request.has_request_id = true;
    request.auth_key = (ProtobufCBinaryData){32, auth};
    request.request_id = r->pair_request;
    if (!publish)
        return send_message(r, r->stream.peer.steam_id, k_ERemoteDeviceAuthorizationRequest,
                            &request.base);
    uint8_t raw[4096], body[4200];
    size_t size = protobuf_c_message_pack(&request.base, raw);
    sl_proto_writer w = {body, 0, sizeof(body), false};
    sl_proto_fixed64(&w, 1, r->session);
    sl_proto_fixed64(&w, 2, r->config.deviceId);
    /* SetPairingInfo carries ONLY the authorization body, no discovery header. */
    sl_proto_bytes(&w, 3, raw, size);
    bool ok = !w.invalid && envelope(r, 3, body, w.size);
    erase(raw, sizeof(raw));
    erase(body, sizeof(body));
    if (ok) {
        if (!r->pending_start && !r->pending_set && !r->pending_cancel)
            r->rpc_deadline = r->wall_time + 20;
        r->pending_set = true;
        r->pairing = PAIR_AUTH;
        if (r->cb.pair_code)
            r->cb.pair_code(r->pin, r->ctx);
    }
    return ok;
}
static bool publish_pairing(sl_remote *r, uint32_t pin) {
    if (pin > 9999)
        return false;
    snprintf(r->pin, sizeof(r->pin), "%04u", pin);
    if (!IHS_AuthorizationKeyExchangeInit(&r->kx, r->pin) ||
        IHS_CryptoRandomBytes(r->pair_secret, 32))
        return false;
    r->pair_request = IHS_CryptoRandomUInt32();
    return send_authorization(r, true);
}
static void authorization(sl_remote *r, uint64_t client_id, const uint8_t *data, size_t size) {
    CMsgRemoteDeviceAuthorizationResponse *a =
        cmsg_remote_device_authorization_response__unpack(NULL, size, data);
    if (!a)
        return;
    if (r->cb.diagnostic) {
        char line[80];
        snprintf(line, sizeof(line), "cloud: authorization response result=%d", (int)a->result);
        r->cb.diagnostic(line, r->ctx);
    }
    CMsgRemoteDeviceAuthorizationConfirmed confirm =
        CMSG_REMOTE_DEVICE_AUTHORIZATION_CONFIRMED__INIT;
    uint64_t account = a->steamid;
    bool progress = false;
    bool known = r->pairing == PAIR_KNOWN;
    sl_remote_peer peer = {.client_id = client_id, .steam_id = account};
    if (known && (client_id != r->stream.peer.client_id || account != r->stream.peer.steam_id))
        goto done;
    if (r->pairing != PAIR_AUTH && !known) {
        confirm.result = k_ERemoteDeviceAuthorizationCanceled;
    } else if (a->result != k_ERemoteDeviceAuthorizationSuccess) {
        if (known && a->result == k_ERemoteDeviceAuthorizationInProgress)
            goto done;
        /* Cloud pairing InProgress terminates, unlike known-host authorization. */
        pairing_failed(r, (IHS_AuthorizationResult)a->result);
        goto done;
    } else if (!client_id || !account) {
        goto done;
    } else if (!a->has_auth_key) {
        memcpy(peer.secret, r->pair_secret, 32);
        progress = true;
    } else if (a->auth_key.len != 32) {
        confirm.result = k_ERemoteDeviceAuthorizationDenied;
    } else if (r->have_auth && !memcmp(r->last_auth, a->auth_key.data, 32)) {
        confirm.result = (ERemoteDeviceAuthorizationResult)r->last_auth_result;
    } else {
        bool ok = r->exchanges++ < 3 && a->has_device_token &&
                  IHS_AuthorizationKeyExchangeComplete(&r->kx, a->auth_key.data, a->auth_key.len,
                                                       a->device_token.data, a->device_token.len,
                                                       r->config.deviceId, peer.secret);
        memcpy(r->last_auth, a->auth_key.data, 32);
        r->have_auth = true;
        r->last_auth_result =
            ok ? k_ERemoteDeviceAuthorizationSuccess : k_ERemoteDeviceAuthorizationDenied;
        confirm.result = (ERemoteDeviceAuthorizationResult)r->last_auth_result;
        progress = ok;
    }
    if (progress) {
        if (!r->cb.save_key || !r->cb.save_key(&peer, r->ctx)) {
            if (a->has_auth_key) {
                confirm.result = k_ERemoteDeviceAuthorizationSuccess;
                send_message(r, account, k_ERemoteDeviceAuthorizationConfirmed, &confirm.base);
            }
            pairing_failed(r, IHS_AuthorizationFailed);
            goto done;
        }
        if (a->has_auth_key) {
            confirm.result = k_ERemoteDeviceAuthorizationSuccess;
            send_message(r, account, k_ERemoteDeviceAuthorizationConfirmed, &confirm.base);
        }
        if (!known)
            subscription(r, &peer, true);
        size_t index = 0;
        while (index < r->count && r->peers[index].client_id != peer.client_id)
            ++index;
        if (index < SL_REMOTE_PEERS) {
            if (index == r->count)
                ++r->count;
            r->peers[index] = peer;
        }
        r->pairing = PAIR_NONE;
        IHS_AuthorizationKeyExchangeClear(&r->kx);
        erase(r->pair_secret, 32);
        erase(r->pin, sizeof(r->pin));
        if (known) {
            r->stream.peer = peer;
            r->stream.next_send = 0;
        } else if (r->cb.paired)
            r->cb.paired(&peer, r->ctx);
    } else if (a->has_auth_key && account) {
        send_message(r, account, k_ERemoteDeviceAuthorizationConfirmed, &confirm.base);
        if (r->exchanges > 3)
            pairing_failed(r, IHS_AuthorizationDenied);
    }
done:
    erase(&peer, sizeof(peer));
    cmsg_remote_device_authorization_response__free_unpacked(a, NULL);
}
static void status(sl_remote *r, const CMsgRemoteClientBroadcastHeader *h, const uint8_t *data,
                   size_t size) {
    CMsgRemoteClientBroadcastStatus *s =
        cmsg_remote_client_broadcast_status__unpack(NULL, size, data);
    if (!s || !h->client_id)
        goto done;
    sl_remote_host host = {0};
    for (size_t i = 0; i < r->count; ++i)
        if (r->peers[i].client_id == h->client_id)
            host.steam_id = r->peers[i].steam_id;
    if (!host.steam_id)
        goto done;
    host.info = (IHS_HostInfo){.clientId = h->client_id,
                               .instanceId = h->instance_id,
                               .ostype = s->ostype,
                               .universe = s->euniverse,
                               .gamesRunning = s->games_running,
                               .hasGamesRunning = s->has_games_running,
                               .hasTimestamp = s->has_timestamp,
                               .timestamp = s->timestamp};
    snprintf(host.info.hostname, sizeof(host.info.hostname), "%s",
             s->hostname ? s->hostname : "Steam");
    for (size_t i = 0; i < s->n_ip_addresses && host.address_count < SL_REMOTE_ADDRESSES; ++i) {
        IHS_IPAddress ip;
        if (strlen(s->ip_addresses[i]) < 64 && IHS_IPAddressFromString(&ip, s->ip_addresses[i]))
            snprintf(host.addresses[host.address_count++], 64, "%s", s->ip_addresses[i]);
    }
    if (s->public_ip_address && host.address_count < SL_REMOTE_ADDRESSES) {
        IHS_IPAddress ip;
        bool duplicate = false;
        for (size_t i = 0; i < host.address_count; ++i)
            duplicate |= !strcmp(host.addresses[i], s->public_ip_address);
        if (!duplicate && strlen(s->public_ip_address) < 64 &&
            IHS_IPAddressFromString(&ip, s->public_ip_address))
            snprintf(host.addresses[host.address_count++], 64, "%s", s->public_ip_address);
    }
    if (r->cb.host)
        r->cb.host(&host, r->ctx);
done:
    if (s)
        cmsg_remote_client_broadcast_status__free_unpacked(s, NULL);
}
static void streaming_reply(sl_remote *, const CMsgRemoteClientBroadcastHeader *, const uint8_t *,
                            size_t);
static bool discovery(sl_remote *r, const uint8_t *data, size_t size) {
    static const uint8_t magic[] = {255, 255, 255, 255, 33, 76, 95, 160};
    if (size < 16 || memcmp(data, magic, 8))
        return false;
    uint32_t hs, ms;
    IHS_ReadUInt32LE(data + 8, &hs);
    if (hs > size - 16)
        return false;
    IHS_ReadUInt32LE(data + 12 + hs, &ms);
    if (ms != size - 16 - hs)
        return false;
    CMsgRemoteClientBroadcastHeader *h =
        cmsg_remote_client_broadcast_header__unpack(NULL, hs, data + 12);
    if (!h)
        return false;
    const uint8_t *body = data + 16 + hs;
    if (h->msg_type == k_ERemoteClientBroadcastMsgStatus)
        status(r, h, body, ms);
    else if (h->msg_type == k_ERemoteDeviceStreamTransportSignal) {
        if (r->cb.transport_signal)
            r->cb.transport_signal(h->client_id, body, ms, r->ctx);
    } else if (h->msg_type == k_ERemoteDeviceAuthorizationResponse)
        authorization(r, h->client_id, body, ms);
    else if (h->msg_type == k_ERemoteClientBroadcastMsgOffline) {
        if (r->cb.offline)
            r->cb.offline(h->client_id, r->ctx);
    } else
        streaming_reply(r, h, body, ms);
    cmsg_remote_client_broadcast_header__free_unpacked(h, NULL);
    return true;
}
bool sl_remote_receive(sl_remote *r, const uint8_t *data, size_t size) {
    if (size > SL_REMOTE_FRAME_MAX)
        return false;
    sl_proto_reader reader = {data, size, 0, false};
    sl_proto_field f, body = {0};
    int result = 0;
    bool have_result = false;
    while (sl_proto_next(&reader, &f)) {
        if (f.number == 1) {
            if (have_result || f.wire != 0 || f.value > INT32_MAX)
                return false;
            result = (int)f.value;
            have_result = true;
        } else if (f.number >= 2 && f.number <= 7) {
            if (body.number || f.wire != 2)
                return false;
            body = f;
        }
    }
    if (!sl_proto_done(&reader) || !body.number)
        return false;
    reader = (sl_proto_reader){body.bytes, body.size, 0, false};
    uint64_t session = 0, account = 0, client_id = 0;
    uint32_t pin = UINT32_MAX;
    int universe = 0;
    unsigned seen = 0;
    /* Validate the complete body BEFORE dispatching any side effect. */
    while (sl_proto_next(&reader, &f)) {
        unsigned expected = body.number == 6   ? (f.number == 1 ? 2 : 99)
                            : body.number == 2 ? (f.number == 1   ? 1
                                                  : f.number == 2 ? 0
                                                                  : 99)
                            : body.number == 3 ? (f.number == 1 ? 0 : 99)
                            : body.number == 7 ? (f.number <= 3 ? 1 : 99)
                                               : 99;
        if (expected == 99)
            continue;
        if (f.wire != expected || (body.number != 6 && (seen & (1u << f.number))))
            return false;
        seen |= 1u << f.number;
        if (body.number == 2) {
            if (f.number == 1)
                session = f.value;
            else
                universe = (int)f.value;
        } else if (body.number == 3) {
            if (f.value > 9999)
                return false;
            pin = (uint32_t)f.value;
        } else if (body.number == 7) {
            if (f.number == 1)
                session = f.value;
            else if (f.number == 2)
                account = f.value;
            else
                client_id = f.value;
        }
    }
    if (!sl_proto_done(&reader))
        return false;
    bool pairing_rpc = true;
    if (body.number == 3) {
        pairing_rpc = r->pending_start;
        r->pending_start = false;
    } else if (body.number == 4) {
        pairing_rpc = r->pending_set;
        r->pending_set = false;
    } else if (body.number == 5) {
        pairing_rpc = r->pending_cancel != 0;
        if (r->pending_cancel)
            --r->pending_cancel;
    }
    if (result != 1) {
        if (r->cb.diagnostic) {
            char line[96];
            snprintf(line, sizeof(line), "cloud: service response kind=%u result=%d", body.number,
                     result);
            r->cb.diagnostic(line, r->ctx);
        }
        if (body.number == 2) {
            r->failed = true;
            return true;
        }
        if (pairing_rpc && body.number >= 3 && body.number <= 5 &&
            (r->pairing == PAIR_PIN || r->pairing == PAIR_AUTH))
            pairing_failed(r, IHS_AuthorizationFailed);
        else if (body.number == 3 && r->pairing == PAIR_CANCEL)
            r->pairing = PAIR_NONE;
        return true;
    }
    if (body.number == 2) {
        if (!r->opening || !session || universe < 1 || universe > 4)
            return false;
        r->opening = false;
        r->session = session;
        r->universe = (IHS_SteamUniverse)universe;
        for (size_t i = 0; i < r->count; ++i) {
            bool duplicate = false;
            for (size_t j = 0; j < i; ++j)
                duplicate |= r->peers[i].steam_id == r->peers[j].steam_id;
            if (!duplicate && !subscription(r, &r->peers[i], true))
                return false;
        }
        if (r->cb.connected)
            r->cb.connected(true, r->ctx);
    } else if (!r->session)
        return false;
    else if (body.number == 3) {
        if (!pairing_rpc)
            return true;
        if (r->pairing != PAIR_PIN) {
            cancel_pair_slot(r);
            r->pairing = PAIR_NONE;
        } else if (pin == UINT32_MAX || !publish_pairing(r, pin))
            pairing_failed(r, IHS_AuthorizationFailed);
    } else if (body.number == 6) {
        reader = (sl_proto_reader){body.bytes, body.size, 0, false};
        while (sl_proto_next(&reader, &f))
            if (f.number == 1)
                discovery(r, f.bytes, f.size);
    } else if (body.number == 7 && (!session || session == r->session) && r->cb.offline) {
        for (size_t i = 0; i < r->count; ++i)
            if ((client_id && r->peers[i].client_id == client_id) ||
                (!client_id && account && r->peers[i].steam_id == account))
                r->cb.offline(r->peers[i].client_id, r->ctx);
    }
    return true;
}

bool sl_remote_stream(sl_remote *r, uint64_t id, const IHS_StreamingRequest *request) {
    return sl_remote_stream_ex(r, id, request, NULL);
}
bool sl_remote_stream_ex(sl_remote *r, uint64_t id, const IHS_StreamingRequest *request,
                          const sl_remote_stream_options *options) {
    if (!sl_remote_ready(r) || r->pairing || r->stream.active || !request)
        return false;
    const sl_remote_peer *peer = NULL;
    for (size_t i = 0; i < r->count; ++i)
        if (r->peers[i].client_id == id)
            peer = &r->peers[i];
    if (!peer)
        return false;
    memset(&r->stream, 0, sizeof(r->stream));
    r->stream.peer = *peer;
    r->stream.request = *request;
    if (options)
        r->stream.options = *options;
    if (request->pin[0]) {
        r->stream.pin_size = sizeof(r->stream.pin_cipher);
        if (IHS_CryptoSymmetricEncrypt((const uint8_t *)request->pin,
                                       strnlen(request->pin, sizeof(request->pin)), peer->secret,
                                       32, r->stream.pin_cipher, &r->stream.pin_size))
            return false;
    }
    do
        r->stream.id = IHS_CryptoRandomUInt32();
    while (!r->stream.id);
    r->pair_request = r->stream.id;
    uint32_t authorization_pin;
    do
        authorization_pin = IHS_CryptoRandomUInt32() % 10000;
    while (!authorization_pin);
    snprintf(r->pin, sizeof(r->pin), "%04u", authorization_pin);
    if (!IHS_AuthorizationKeyExchangeInit(&r->kx, r->pin))
        return false;
    memcpy(r->pair_secret, peer->secret, 32);
    r->exchanges = 0;
    r->have_auth = false;
    r->stream.active = true;
    return true;
}
void sl_remote_update(sl_remote *r, int64_t now) {
    r->wall_time = now;
    if (r->session && (r->pending_start || r->pending_set || r->pending_cancel) &&
        now >= r->rpc_deadline) {
        if (r->cb.diagnostic)
            r->cb.diagnostic("cloud: pairing service response deadline expired", r->ctx);
        if (r->pairing == PAIR_PIN || r->pairing == PAIR_AUTH)
            pairing_failed(r, IHS_AuthorizationTimedOut);
        /* No transaction ID exists for these RPCs. A new WebSocket, rather than
         * reusing a possibly occupied slot, makes a fresh user attempt safe. */
        r->failed = true;
        return;
    }
    if (!r->session || !r->stream.active || now < r->stream.next_send)
        return;
    if (r->pairing == PAIR_KNOWN) {
        r->stream.next_send = now + 3;
        memcpy(r->pair_secret, r->stream.peer.secret, 32);
        send_authorization(r, false);
        return;
    }
    r->stream.next_send = now + 1; /* Official wall-clock retry, not monotonic +1s. */
    IHS_StreamingRequest *q = &r->stream.request;
    uint8_t id[8], token[32];
    size_t token_size = sizeof(token);
    IHS_WriteUInt64LE(id, r->config.deviceId);
    if (IHS_CryptoSymmetricEncrypt(id, sizeof(id), r->stream.peer.secret, 32, token, &token_size))
        return;
    CMsgRemoteDeviceStreamingRequest msg = CMSG_REMOTE_DEVICE_STREAMING_REQUEST__INIT;
    msg.request_id = r->stream.id;
    msg.has_client_id = msg.has_device_token = true;
    msg.client_id = r->stream.peer.client_id;
    msg.device_token = (ProtobufCBinaryData){token_size, token};
    msg.device_version = "1.3.32";
    msg.has_maximum_resolution_x = msg.has_maximum_resolution_y = true;
    msg.maximum_resolution_x = q->maxResolution.x;
    msg.maximum_resolution_y = q->maxResolution.y;
    msg.has_audio_channel_count = true;
    msg.audio_channel_count = q->audioChannelCount;
    msg.has_enable_video_streaming = msg.has_enable_audio_streaming =
        msg.has_enable_input_streaming = true;
    msg.enable_video_streaming = q->streamingEnable.video;
    msg.enable_audio_streaming = q->streamingEnable.audio;
    msg.enable_input_streaming = q->streamingEnable.input;
    msg.has_stream_interface = msg.has_stream_desktop = true;
    msg.stream_interface = (EStreamInterface)q->streamingInterface;
    msg.stream_desktop = q->streamDesktop;
    msg.has_gameid = q->gameId != 0;
    msg.gameid = q->gameId;
    msg.has_pin = r->stream.pin_size != 0;
    msg.pin = (ProtobufCBinaryData){r->stream.pin_size, r->stream.pin_cipher};
    CMsgRemoteDeviceStreamingRequest__ReservedGamepad pads[16];
    CMsgRemoteDeviceStreamingRequest__ReservedGamepad *pad_pointers[16];
    int pad_count = q->gamepadCount > 16 ? 16 : q->gamepadCount;
    if (pad_count > 0) {
        msg.has_gamepad_count = true;
        msg.gamepad_count = pad_count;
        msg.n_gamepads = (size_t)pad_count;
        msg.gamepads = pad_pointers;
        for (int i = 0; i < pad_count; ++i) {
            cmsg_remote_device_streaming_request__reserved_gamepad__init(&pads[i]);
            pad_pointers[i] = &pads[i];
        }
    }
    msg.has_network_test = true;
    msg.network_test = r->stream.options.network_test;
    /* Runtime default stays UDP. The explicit diagnostic SNS path never
     * accepts a final UDP choice that would bypass the backend under test. */
    EStreamTransport transports[2];
    msg.n_supported_transport = 0;
    if (!r->stream.options.sns || r->stream.options.udp)
        transports[msg.n_supported_transport++] = k_EStreamTransportUDP;
    if (r->stream.options.sns)
        transports[msg.n_supported_transport++] = k_EStreamTransportSDR;
    msg.supported_transport = transports;
    send_message(r, r->stream.peer.steam_id, k_ERemoteDeviceStreamingRequest, &msg.base);
}
static void streaming_reply(sl_remote *r, const CMsgRemoteClientBroadcastHeader *h,
                            const uint8_t *data, size_t size) {
    if (!h->client_id)
        return;
    if (!r->stream.active || h->client_id != r->stream.peer.client_id) {
        const sl_remote_peer *peer = NULL;
        for (size_t i = 0; i < r->count; ++i)
            if (r->peers[i].client_id == h->client_id)
                peer = &r->peers[i];
        if (!peer)
            return;
        if (h->msg_type == k_ERemoteDeviceStreamingResponse) {
            CMsgRemoteDeviceStreamingResponse *a =
                cmsg_remote_device_streaming_response__unpack(NULL, size, data);
            if (a && a->result == k_ERemoteDeviceStreamingInProgress) {
                CMsgRemoteDeviceStreamingCancelRequest cancel =
                    CMSG_REMOTE_DEVICE_STREAMING_CANCEL_REQUEST__INIT;
                cancel.request_id = a->request_id;
                send_message(r, peer->steam_id, k_ERemoteDeviceStreamingCancelRequest,
                             &cancel.base);
            }
            if (a)
                cmsg_remote_device_streaming_response__free_unpacked(a, NULL);
        } else if (h->msg_type == k_ERemoteDeviceProofRequest) {
            CMsgRemoteDeviceProofRequest *q =
                cmsg_remote_device_proof_request__unpack(NULL, size, data);
            if (q) {
                CMsgRemoteDeviceProofResponse empty = CMSG_REMOTE_DEVICE_PROOF_RESPONSE__INIT;
                send_message(r, peer->steam_id, k_ERemoteDeviceProofResponse, &empty.base);
                cmsg_remote_device_proof_request__free_unpacked(q, NULL);
            }
        }
        return;
    }
    if (h->msg_type == k_ERemoteDeviceProofRequest) {
        CMsgRemoteDeviceProofRequest *q =
            cmsg_remote_device_proof_request__unpack(NULL, size, data);
        if (!q)
            return;
        if (q->has_request_id && q->request_id != r->stream.id)
            goto proof_done;
        if (q->update_secret && !r->stream.updated) {
            uint8_t *source = malloc(32 + q->challenge.len);
            if (!source)
                goto proof_done;
            memcpy(source, r->stream.peer.secret, 32);
            memcpy(source + 32, q->challenge.data, q->challenge.len);
            sl_remote_peer replacement = r->stream.peer;
            bool ok = !IHS_CryptoSHA256(source, 32 + q->challenge.len, replacement.secret) &&
                      r->cb.save_key && r->cb.save_key(&replacement, r->ctx);
            erase(source, 32 + q->challenge.len);
            free(source);
            if (!ok) {
                erase(&replacement, sizeof(replacement));
                r->stream.active = false;
                if (r->cb.stream_result)
                    r->cb.stream_result(IHS_StreamingFailed, NULL, r->ctx);
                goto proof_done;
            }
            r->stream.peer = replacement;
            for (size_t i = 0; i < r->count; ++i)
                if (r->peers[i].client_id == replacement.client_id)
                    r->peers[i] = replacement;
            erase(&replacement, sizeof(replacement));
            r->stream.updated = true;
        }
        size_t capacity = q->challenge.len + 32;
        uint8_t *encrypted = malloc(capacity);
        if (encrypted) {
            CMsgRemoteDeviceProofResponse a = CMSG_REMOTE_DEVICE_PROOF_RESPONSE__INIT;
            if (!IHS_CryptoSymmetricEncrypt(q->challenge.data, q->challenge.len,
                                            r->stream.peer.secret, 32, encrypted, &capacity)) {
                a.response = (ProtobufCBinaryData){capacity, encrypted};
                a.has_request_id = a.has_updated_secret = true;
                a.request_id = r->stream.id;
                a.updated_secret = q->update_secret;
                send_message(r, r->stream.peer.steam_id, k_ERemoteDeviceProofResponse, &a.base);
            }
            erase(encrypted, capacity);
            free(encrypted);
        }
    proof_done:
        cmsg_remote_device_proof_request__free_unpacked(q, NULL);
    } else if (h->msg_type == k_ERemoteDeviceStreamingResponse) {
        if (r->pairing == PAIR_KNOWN)
            return;
        CMsgRemoteDeviceStreamingResponse *a =
            cmsg_remote_device_streaming_response__unpack(NULL, size, data);
        if (!a)
            return;
        if (a->request_id != r->stream.id || !a->request_id) {
            if (a->result == k_ERemoteDeviceStreamingInProgress) {
                CMsgRemoteDeviceStreamingCancelRequest cancel =
                    CMSG_REMOTE_DEVICE_STREAMING_CANCEL_REQUEST__INIT;
                cancel.request_id = a->request_id;
                send_message(r, r->stream.peer.steam_id, k_ERemoteDeviceStreamingCancelRequest,
                             &cancel.base);
            }
        } else if (a->result == k_ERemoteDeviceStreamingUnauthorized) {
            r->pairing = PAIR_KNOWN;
            r->stream.next_send = 0;
        } else if (a->result != k_ERemoteDeviceStreamingBusy &&
                   a->result != k_ERemoteDeviceStreamingInProgress) {
            sl_remote_material material = {.client_id = h->client_id,
                                           .steam_id = r->stream.peer.steam_id,
                                           .transport = a->transport,
                                           .port = a->port,
                                           .key_size = 128,
                                           .cert = a->cert,
                                           .stun_servers = a->relay_server};
            IHS_StreamingResult result = (IHS_StreamingResult)a->result;
            if (result == IHS_StreamingSuccess &&
                (!a->has_encrypted_session_key || a->port > UINT16_MAX ||
                 (a->transport == k_EStreamTransportUDP && (!a->has_port || a->port == 0)) ||
                 IHS_CryptoSymmetricDecrypt(a->encrypted_session_key.data,
                                            a->encrypted_session_key.len, r->stream.peer.secret, 32,
                                            material.key, &material.key_size) ||
                 !material.key_size))
                result = IHS_StreamingFailed;
            r->stream.active = false;
            if (r->cb.stream_result)
                r->cb.stream_result(result, result == IHS_StreamingSuccess ? &material : NULL,
                                    r->ctx);
            erase(&material, sizeof(material));
        }
        cmsg_remote_device_streaming_response__free_unpacked(a, NULL);
    }
}
