#include "authorization_kx.h"
#include "crypto.h"
#include "endianness.h"
#include "protobuf/discovery.pb-c.h"
#include "remote_protocol.h"
#include "remote_wire.h"
#include "services/auth_store.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct fixture {
    sl_remote *remote;
    uint8_t sent[128][8192];
    size_t sizes[128], count;
    unsigned connected, disconnected, codes, saves, paired, failed, hosts, offline, streams;
    bool save_ok;
    char code[5];
    sl_remote_peer saved;
    IHS_StreamingResult result;
    uint8_t stream_key[128];
    size_t stream_key_size;
    int stream_transport;
    const char *profile;
    unsigned crash_stage;
} fixture;
static unsigned sent_control_kind(fixture *, size_t, uint32_t *);
static bool send_frame(const uint8_t *p, size_t size, void *ctx) {
    fixture *f = ctx;
    assert(f->count < 128 && size <= sizeof(f->sent[0]));
    memcpy(f->sent[f->count], p, size);
    f->sizes[f->count++] = size;
    if (f->crash_stage == 2 && p[0] == 0x3a && sent_control_kind(f, f->count - 1, NULL) == 8)
        _exit(72); /* Abrupt exit after proof enqueue; no normal teardown. */
    return true;
}
static void connected(bool ready, void *ctx) {
    fixture *f = ctx;
    if (ready)
        ++f->connected;
    else
        ++f->disconnected;
}
static void code(const char *pin, void *ctx) {
    fixture *f = ctx;
    ++f->codes;
    memcpy(f->code, pin, 5);
}
static bool save_key(const sl_remote_peer *peer, void *ctx) {
    fixture *f = ctx;
    ++f->saves;
    f->saved = *peer;
    if (f->profile && f->save_ok) {
        sl_auth_store store;
        assert(sl_auth_load(&store, f->profile) == 0);
        assert(store.registry.count == 1);
        memcpy(store.registry.hosts[0].secret, peer->secret, 32);
        assert(sl_auth_save(&store, f->profile));
        memset(&store, 0, sizeof(store));
        if (f->crash_stage == 1)
            _exit(71); /* Saved, but protocol has not built/enqueued its proof. */
    }
    return f->save_ok;
}
static void paired(const sl_remote_peer *peer, void *ctx) {
    fixture *f = ctx;
    assert(f->saves && !memcmp(peer->secret, f->saved.secret, 32));
    ++f->paired;
}
static void failed(IHS_AuthorizationResult result, void *ctx) {
    (void)result;
    ++((fixture *)ctx)->failed;
}
static void host(const sl_remote_host *h, void *ctx) {
    fixture *f = ctx;
    assert(h->info.clientId == 77 && h->steam_id == 88);
    assert(h->address_count == 10 && !strcmp(h->addresses[0], "192.0.2.1"));
    assert(!strcmp(h->addresses[1], "not an address") &&
           !strcmp(h->addresses[9], "192.0.2.9"));
    assert(!strcmp(h->public_address, "192.0.2.1")); /* Keep duplicate's source marker. */
    /* A cloud address has NOT become a verified UDP route. */
    assert(h->info.address.port == 0);
    ++f->hosts;
}
static void offline(uint64_t id, void *ctx) {
    assert(id == 77);
    ++((fixture *)ctx)->offline;
}
static void stream_result(IHS_StreamingResult result, const sl_remote_material *m, void *ctx) {
    fixture *f = ctx;
    ++f->streams;
    f->result = result;
    if (m) {
        f->stream_key_size = m->key_size;
        memcpy(f->stream_key, m->key, m->key_size);
        f->stream_transport = m->transport;
    }
}
static fixture *create(void) {
    fixture *f = calloc(1, sizeof(*f));
    assert(f);
    f->save_ok = true;
    uint8_t secret[32] = {1, 2, 3};
    IHS_ClientConfig config = {
        .deviceId = 0x123456789abcdefULL, .secretKey = secret, .deviceName = "Synthetic client"};
    sl_remote_callbacks cb = {.send = send_frame,
                              .connected = connected,
                              .host = host,
                              .offline = offline,
                              .pair_code = code,
                              .save_key = save_key,
                              .paired = paired,
                              .pair_failed = failed,
                              .stream_result = stream_result};
    f->remote = sl_remote_create(&config, &cb, f);
    assert(f->remote);
    return f;
}
static sl_proto_field field(const void *data, size_t size, unsigned number) {
    sl_proto_reader r = {data, size, 0, false};
    sl_proto_field f, result = {0};
    while (sl_proto_next(&r, &f))
        if (f.number == number)
            result = f;
    assert(sl_proto_done(&r));
    return result;
}
static sl_proto_field sent(fixture *f, size_t index, unsigned number) {
    assert(index < f->count);
    sl_proto_field body = field(f->sent[index], f->sizes[index], number);
    assert(body.number == number && body.wire == 2);
    return body;
}
static void control_key(fixture *f, size_t index, const uint8_t secret[32]) {
    sl_proto_field cloud = sent(f, index, 7);
    sl_proto_field packet = field(cloud.bytes, cloud.size, 4);
    uint32_t hs;
    assert(packet.size >= 16);
    IHS_ReadUInt32LE(packet.bytes+8, &hs);
    assert(hs <= packet.size-16);
    sl_proto_field token = field(packet.bytes+12, hs, 5);
    assert(token.number == 5 && token.wire == 2 && token.size == 32);
    assert(field(packet.bytes+12, hs, 1).value == 0x123456789abcdefULL);
    uint8_t plain[64];
    size_t size = sizeof(plain);
    assert(!IHS_CryptoSymmetricDecrypt(token.bytes, token.size, secret, 32, plain, &size) && size == 8);
    uint64_t device;
    IHS_ReadUInt64LE(plain, &device);
    assert(device == 0x123456789abcdefULL);
}
static bool response(fixture *f, unsigned kind, int result, const void *body, size_t size) {
    uint8_t packet[16384];
    sl_proto_writer w = {packet, 0, sizeof(packet), false};
    sl_proto_uint(&w, 1, (uint64_t)result);
    sl_proto_bytes(&w, kind, body, size);
    assert(!w.invalid);
    return sl_remote_receive(f->remote, packet, w.size);
}
static void open_session(fixture *f, uint64_t id) {
    assert(sl_remote_open(f->remote));
    assert(f->sizes[f->count - 1] == 2 && !memcmp(f->sent[f->count - 1], "\x0a\0", 2));
    uint8_t data[32];
    sl_proto_writer w = {data, 0, sizeof(data), false};
    sl_proto_fixed64(&w, 1, id);
    sl_proto_uint(&w, 2, 1);
    assert(response(f, 2, 1, data, w.size));
    assert(sl_remote_ready(f->remote));
}
static void reply(fixture *f, unsigned kind, const ProtobufCMessage *msg) {
    CMsgRemoteClientBroadcastHeader header = CMSG_REMOTE_CLIENT_BROADCAST_HEADER__INIT;
    header.has_client_id = header.has_msg_type = true;
    header.client_id = 77;
    header.msg_type = (ERemoteClientBroadcastMsg)kind;
    uint8_t packet[8192], body[8400];
    static const uint8_t magic[] = {255, 255, 255, 255, 33, 76, 95, 160};
    memcpy(packet, magic, 8);
    size_t hs = protobuf_c_message_pack(&header.base, packet + 12);
    IHS_WriteUInt32LE(packet + 8, hs);
    size_t ms = protobuf_c_message_pack(msg, packet + 16 + hs);
    IHS_WriteUInt32LE(packet + 12 + hs, ms);
    sl_proto_writer w = {body, 0, sizeof(body), false};
    sl_proto_bytes(&w, 1, packet, 16 + hs + ms);
    assert(response(f, 6, 1, body, w.size));
}
static void start_pair(fixture *f) {
    assert(sl_remote_pair(f->remote));
    uint8_t pin[] = {8, 0xd2, 0x09}; /* 1234 */
    assert(response(f, 3, 1, pin, sizeof(pin)));
    assert(f->codes && !strcmp(f->code, "1234"));
    assert(response(f, 4, 1, NULL, 0));
}
static void pair_host(fixture *f) {
    start_pair(f);
    sl_proto_field outer = sent(f, f->count - 1, 3);
    sl_proto_field body = field(outer.bytes, outer.size, 3);
    CMsgRemoteDeviceAuthorizationRequest *request =
        cmsg_remote_device_authorization_request__unpack(NULL, body.size, body.bytes);
    assert(request && request->has_auth_key && request->auth_key.len == 32);
    uint8_t pin_hash[32], client_pub[32], host_priv[32] = {9}, host_pub[32], auth[32], secret[32];
    assert(!IHS_CryptoSHA256((const uint8_t *)"1234", 4, pin_hash));
    for (unsigned i = 0; i < 32; ++i)
        client_pub[i] = request->auth_key.data[i] ^ pin_hash[i];
    assert(!IHS_CryptoX25519PublicKey(host_priv, host_pub));
    assert(!IHS_CryptoKeyExchange(host_priv, client_pub, secret));
    for (unsigned i = 0; i < 32; ++i)
        auth[i] = host_pub[i] ^ pin_hash[i];
    uint8_t id[8], token[64];
    size_t token_size = sizeof(token);
    IHS_WriteUInt64LE(id, 0x123456789abcdefULL);
    assert(!IHS_CryptoSymmetricEncrypt(id, 8, secret, 32, token, &token_size));
    CMsgRemoteDeviceAuthorizationResponse a = CMSG_REMOTE_DEVICE_AUTHORIZATION_RESPONSE__INIT;
    a.result = k_ERemoteDeviceAuthorizationSuccess;
    a.has_steamid = a.has_auth_key = a.has_device_token = true;
    a.steamid = 88;
    a.auth_key = (ProtobufCBinaryData){32, auth};
    a.device_token = (ProtobufCBinaryData){token_size, token};
    size_t confirmed = f->count;
    reply(f, 4, &a.base);
    assert(f->paired == 1 && f->saves == 1 && !memcmp(secret, f->saved.secret, 32));
    assert(sent_control_kind(f, confirmed, NULL) == k_ERemoteDeviceAuthorizationConfirmed);
    control_key(f, confirmed, secret); /* New key is installed BEFORE Confirmed. */
    /* A late success must not re-authorize or save the key a second time. */
    reply(f, 4, &a.base);
    assert(f->paired == 1 && f->saves == 1);
    cmsg_remote_device_authorization_request__free_unpacked(request, NULL);
}
static void lifecycle(void) {
    fixture *f = create();
    assert(!sl_remote_pair(f->remote));
    sl_remote_peer peer = {.client_id = 77, .steam_id = 88, .secret = {1}};
    assert(sl_remote_watch(f->remote, &peer, 1));
    open_session(f, 1001);
    sl_proto_field b = sent(f, f->count - 1, 5);
    assert(field(b.bytes, b.size, 1).value == 1001);
    assert(field(b.bytes, b.size, 2).wire == 1);
    assert(field(b.bytes, b.size, 4).value == 1);
    size_t count = f->count;
    assert(sl_remote_watch(f->remote, &peer, 1) && f->count == count);
    sl_remote_close(f->remote);
    open_session(f, 2002);
    b = sent(f, f->count - 1, 5);
    assert(field(b.bytes, b.size, 1).value == 2002 && f->disconnected == 1);
    CMsgRemoteClientBroadcastStatus status = CMSG_REMOTE_CLIENT_BROADCAST_STATUS__INIT;
    char *addresses[] = {"192.0.2.1", "not an address", "192.0.2.2", "192.0.2.3",
        "192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7", "192.0.2.8", "192.0.2.9"};
    status.hostname = "Synthetic host";
    status.n_ip_addresses = 10;
    status.ip_addresses = addresses;
    status.public_ip_address = "192.0.2.1";
    reply(f, 1, &status.base);
    assert(f->hosts == 1);
    uint8_t off[64];
    sl_proto_writer w = {off, 0, sizeof(off), false};
    sl_proto_fixed64(&w, 1, 1001);
    sl_proto_fixed64(&w, 2, 88);
    sl_proto_fixed64(&w, 3, 77);
    assert(response(f, 7, 1, off, w.size) && !f->offline);
    IHS_WriteUInt64LE(off + 1, 2002);
    assert(response(f, 7, 1, off, w.size) && f->offline == 1);
    assert(sl_remote_watch(f->remote, NULL, 0));
    sent(f, f->count - 1, 6);
    sl_remote_destroy(f->remote);
    free(f);
}
static void cancel_and_failure(void) {
    fixture *f = create();
    open_session(f, 1);
    assert(sl_remote_pair(f->remote));
    sl_remote_cancel(f->remote);
    assert(!sl_remote_pair(f->remote));
    uint8_t pin[] = {8, 1};
    assert(response(f, 3, 1, pin, sizeof(pin)) && !f->codes);
    sent(f, f->count - 1, 4);
    assert(!sl_remote_pair(f->remote));
    assert(response(f, 5, 1, NULL, 0));
    assert(response(f, 5, 1, NULL, 0));
    start_pair(f);
    sl_remote_close(f->remote);
    assert(f->failed == 1);
    open_session(f, 2);
    /* Reconnect restores subscriptions, never a stale PIN/publication. */
    assert(!f->paired && f->codes == 1);
    start_pair(f);
    CMsgRemoteDeviceAuthorizationResponse a = CMSG_REMOTE_DEVICE_AUTHORIZATION_RESPONSE__INIT;
    uint8_t key[32] = {1};
    a.result = k_ERemoteDeviceAuthorizationInProgress;
    a.has_auth_key = true;
    a.auth_key = (ProtobufCBinaryData){32, key};
    reply(f, 4, &a.base);
    assert(f->failed == 2 && !f->saves);
    sl_remote_update(f->remote, 100);
    assert(sl_remote_pair(f->remote));
    sl_remote_cancel(f->remote);
    sl_remote_update(f->remote, 119);
    assert(!sl_remote_failed(f->remote));
    sl_remote_update(f->remote, 120);
    assert(sl_remote_failed(f->remote));
    sl_remote_close(f->remote);
    open_session(f, 3);
    assert(sl_remote_pair(f->remote));
    sl_remote_destroy(f->remote);
    free(f);
}
static uint32_t stream_request_id(fixture *f) {
    sl_proto_field out = sent(f, f->count - 1, 7);
    sl_proto_field packet = field(out.bytes, out.size, 4);
    uint32_t hs, ms;
    IHS_ReadUInt32LE(packet.bytes + 8, &hs);
    IHS_ReadUInt32LE(packet.bytes + 12 + hs, &ms);
    CMsgRemoteDeviceStreamingRequest *request =
        cmsg_remote_device_streaming_request__unpack(NULL, ms, packet.bytes + 16 + hs);
    assert(request && request->request_id && request->n_supported_transport == 1 &&
           request->supported_transport[0] == k_EStreamTransportUDP);
    sl_proto_field outer_token = field(packet.bytes+12, hs, 5);
    assert(outer_token.size == 32 && request->device_token.len == 32 &&
           memcmp(outer_token.bytes, request->device_token.data, 32));
    if (request->has_pin) {
        uint8_t plaintext[64];
        size_t length = sizeof(plaintext);
        assert(!IHS_CryptoSymmetricDecrypt(request->pin.data, request->pin.len, f->saved.secret, 32,
                                           plaintext, &length));
        assert(length == 4 && !memcmp(plaintext, "5678", 4));
    }
    uint32_t id = request->request_id;
    cmsg_remote_device_streaming_request__free_unpacked(request, NULL);
    return id;
}
static unsigned sent_control_kind(fixture *f, size_t index, uint32_t *id) {
    sl_proto_field out = sent(f, index, 7);
    sl_proto_field packet = field(out.bytes, out.size, 4);
    uint32_t hs;
    IHS_ReadUInt32LE(packet.bytes + 8, &hs);
    if (id)
        *id = (uint32_t)field(packet.bytes + 16 + hs, packet.size - 16 - hs, 1).value;
    return (unsigned)field(packet.bytes + 12, hs, 2).value;
}
static void retired_stream_requests(void) {
    fixture *f = create();
    sl_remote_peer peer = {.client_id = 77, .steam_id = 88, .secret = {1}};
    assert(sl_remote_watch(f->remote, &peer, 1));
    open_session(f, 40);
    IHS_StreamingRequest request = {0};
    assert(sl_remote_stream(f->remote, 77, &request));
    sl_remote_update(f->remote, 100);
    uint32_t id = stream_request_id(f);
    control_key(f, f->count-1, peer.secret);
    sl_remote_cancel(f->remote);
    uint32_t canceled_id;
    assert(sent_control_kind(f, f->count - 1, &canceled_id) == 10 && canceled_id == id);
    control_key(f, f->count-1, peer.secret);
    size_t before = f->count;
    CMsgRemoteDeviceStreamingResponse late = CMSG_REMOTE_DEVICE_STREAMING_RESPONSE__INIT;
    late.request_id = id;
    late.result = k_ERemoteDeviceStreamingInProgress;
    reply(f, 6, &late.base);
    assert(f->count == before + 1 && !f->streams);
    assert(sent_control_kind(f, f->count - 1, &canceled_id) == 10 && canceled_id == id);
    CMsgRemoteDeviceProofRequest proof = CMSG_REMOTE_DEVICE_PROOF_REQUEST__INIT;
    uint8_t challenge = 1;
    proof.challenge = (ProtobufCBinaryData){1, &challenge};
    proof.has_update_secret = true;
    proof.update_secret = true;
    reply(f, 7, &proof.base);
    assert(sent_control_kind(f, f->count - 1, NULL) == 8 && !f->saves);
    sl_remote_destroy(f->remote);
    free(f);
}
static void reordered_pairing_rpcs(void) {
    fixture *f = create();
    open_session(f, 55);
    assert(sl_remote_pair(f->remote));
    uint8_t pin[] = {8, 1};
    assert(response(f, 3, 1, pin, sizeof(pin)) && f->codes == 1);
    sl_remote_cancel(f->remote);
    /* Cancel ack overtakes SetPairingInfo ack. A new attempt stays blocked
     * until every unidentifiable service response has drained. */
    assert(response(f, 5, 1, NULL, 0));
    assert(!sl_remote_pair(f->remote));
    assert(response(f, 4, 1, NULL, 0));
    assert(sl_remote_pair(f->remote));
    /* Duplicate old Set/Cancel failures must not fail the new Start RPC. */
    assert(response(f, 4, 2, NULL, 0) && response(f, 5, 2, NULL, 0));
    assert(!f->failed && !f->saves && f->codes == 1);
    assert(response(f, 3, 1, pin, sizeof(pin)) && f->codes == 2);
    assert(response(f, 4, 1, NULL, 0));
    sl_remote_cancel(f->remote);
    assert(response(f, 5, 1, NULL, 0));
    sl_remote_destroy(f->remote);
    free(f);
}
static void retry_after_cancel_and_rotation(void) {
    fixture *f = create();
    sl_remote_peer peer = {.client_id = 77, .steam_id = 88, .secret = {1, 2, 3}};
    assert(sl_remote_watch(f->remote, &peer, 1));
    open_session(f, 60);
    IHS_StreamingRequest request = {0};
    assert(sl_remote_stream(f->remote, 77, &request));
    sl_remote_update(f->remote, 100);
    uint32_t old_id = stream_request_id(f);
    sl_remote_cancel(f->remote);
    assert(sl_remote_stream(f->remote, 77, &request));
    sl_remote_update(f->remote, 101);
    uint32_t id = stream_request_id(f);
    assert(id != old_id);
    uint8_t challenge[] = {2, 7, 1, 8};
    CMsgRemoteDeviceProofRequest proof = CMSG_REMOTE_DEVICE_PROOF_REQUEST__INIT;
    proof.has_request_id = proof.has_update_secret = true;
    proof.request_id = old_id;
    proof.update_secret = true;
    proof.challenge = (ProtobufCBinaryData){sizeof(challenge), challenge};
    size_t count = f->count;
    reply(f, 7, &proof.base);
    assert(f->count == count && !f->saves);
    CMsgRemoteDeviceStreamingResponse response = CMSG_REMOTE_DEVICE_STREAMING_RESPONSE__INIT;
    response.request_id = old_id;
    response.result = k_ERemoteDeviceStreamingSuccess;
    reply(f, 6, &response.base);
    assert(!f->streams && f->count == count);
    response.result = k_ERemoteDeviceStreamingInProgress;
    reply(f, 6, &response.base);
    uint32_t canceled;
    assert(sent_control_kind(f, f->count - 1, &canceled) == 10 && canceled == old_id);
    proof.request_id = id;
    reply(f, 7, &proof.base);
    assert(f->saves == 1);
    uint8_t key[32];
    memcpy(key, f->saved.secret, 32);
    sl_remote_close(f->remote);
    open_session(f, 61);
    sl_remote_update(f->remote, 102);
    assert(stream_request_id(f) == id);
    control_key(f, f->count-1, key); /* Retained through a new CM session. */
    /* The same transaction survives CM replacement. Duplicate proof must not
     * rotate again, and the response must decrypt with the persisted key. */
    reply(f, 7, &proof.base);
    assert(f->saves == 1 && !memcmp(key, f->saved.secret, 32));
    sl_proto_field out = sent(f, f->count - 1, 7), packet = field(out.bytes, out.size, 4);
    uint32_t hs, ms;
    IHS_ReadUInt32LE(packet.bytes + 8, &hs);
    IHS_ReadUInt32LE(packet.bytes + 12 + hs, &ms);
    CMsgRemoteDeviceProofResponse *wire =
        cmsg_remote_device_proof_response__unpack(NULL, ms, packet.bytes + 16 + hs);
    uint8_t plain[64];
    size_t size = sizeof(plain);
    assert(wire && wire->request_id == id && wire->updated_secret &&
           !IHS_CryptoSymmetricDecrypt(wire->response.data, wire->response.len, key, 32, plain,
                                       &size) &&
           size == sizeof(challenge) && !memcmp(plain, challenge, size));
    cmsg_remote_device_proof_response__free_unpacked(wire, NULL);
    uint8_t session_key[16] = {4}, encrypted[64];
    size = sizeof(encrypted);
    assert(
        !IHS_CryptoSymmetricEncrypt(session_key, sizeof(session_key), key, 32, encrypted, &size));
    response.request_id = id;
    response.result = k_ERemoteDeviceStreamingSuccess;
    response.has_encrypted_session_key = response.has_port = true;
    response.port = 27031;
    response.encrypted_session_key = (ProtobufCBinaryData){size, encrypted};
    reply(f, 6, &response.base);
    reply(f, 6, &response.base);
    assert(f->streams == 1 && f->result == IHS_StreamingSuccess &&
           f->stream_key_size == sizeof(session_key) &&
           !memcmp(f->stream_key, session_key, sizeof(session_key)));
    sl_remote_destroy(f->remote);
    free(f);
}
static void known_host_reauthorization(void) {
    fixture *f = create();
    sl_remote_peer peers[] = {{.client_id = 77, .steam_id = 88, .secret = {1, 2, 3}},
                              {.client_id = 78, .steam_id = 88, .secret = {4, 5, 6}}};
    open_session(f, 30);
    size_t count = f->count;
    assert(sl_remote_watch(f->remote, peers, 2) && f->count == count + 1);
    IHS_StreamingRequest q = {.maxResolution = {1280, 720}, .audioChannelCount = 2};
    assert(sl_remote_stream(f->remote, 77, &q));
    sl_remote_update(f->remote, 100);
    uint32_t id = stream_request_id(f);
    CMsgRemoteDeviceStreamingResponse a = CMSG_REMOTE_DEVICE_STREAMING_RESPONSE__INIT;
    a.request_id = id;
    a.result = k_ERemoteDeviceStreamingUnauthorized;
    reply(f, 6, &a.base);
    assert(!f->streams && !f->failed && !f->codes);
    sl_remote_update(f->remote, 101);
    sl_proto_field out = sent(f, f->count - 1, 7);
    sl_proto_field packet = field(out.bytes, out.size, 4);
    uint32_t hs, ms;
    IHS_ReadUInt32LE(packet.bytes + 8, &hs);
    IHS_ReadUInt32LE(packet.bytes + 12 + hs, &ms);
    CMsgRemoteDeviceAuthorizationRequest *request =
        cmsg_remote_device_authorization_request__unpack(NULL, ms, packet.bytes + 16 + hs);
    assert(request && request->request_id == id && request->auth_key.len == 32);
    control_key(f, f->count-1, peers[0].secret);
    uint8_t decrypted[64], masked_key[32];
    size_t decrypted_size = sizeof(decrypted);
    assert(!IHS_CryptoSymmetricDecrypt(request->device_token.data, request->device_token.len,
                                       peers[0].secret, 32, decrypted, &decrypted_size) &&
           decrypted_size == 8);
    uint64_t device_id;
    IHS_ReadUInt64LE(decrypted, &device_id);
    assert(device_id == 0x123456789abcdefULL);
    memcpy(masked_key, request->auth_key.data, 32);
    cmsg_remote_device_authorization_request__free_unpacked(request, NULL);
    CMsgRemoteDeviceAuthorizationResponse auth = CMSG_REMOTE_DEVICE_AUTHORIZATION_RESPONSE__INIT;
    auth.result = k_ERemoteDeviceAuthorizationInProgress;
    auth.has_steamid = true;
    auth.steamid = 88;
    reply(f, 4, &auth.base);
    count = f->count;
    sl_remote_update(f->remote, 103);
    assert(f->count == count && !f->failed);
    sl_remote_close(f->remote);
    open_session(f, 31);
    sl_remote_update(f->remote, 104);
    out = sent(f, f->count - 1, 7);
    assert(field(out.bytes, out.size, 1).value == 31);
    packet = field(out.bytes, out.size, 4);
    IHS_ReadUInt32LE(packet.bytes + 8, &hs);
    IHS_ReadUInt32LE(packet.bytes + 12 + hs, &ms);
    request = cmsg_remote_device_authorization_request__unpack(NULL, ms, packet.bytes + 16 + hs);
    assert(request && request->request_id == id && !memcmp(masked_key, request->auth_key.data, 32));
    cmsg_remote_device_authorization_request__free_unpacked(request, NULL);
    auth.result = k_ERemoteDeviceAuthorizationSuccess;
    reply(f, 4, &auth.base);
    assert(f->saves == 1 && !f->paired && !f->codes);
    sl_remote_update(f->remote, 105);
    assert(stream_request_id(f) == id);
    sl_remote_cancel(f->remote);
    sl_remote_destroy(f->remote);
    free(f);
}
static void pairing_and_rotation(void) {
    fixture *f = create();
    open_session(f, 3);
    pair_host(f);
    IHS_StreamingRequest q = {.maxResolution = {1280, 720}, .audioChannelCount = 2};
    strcpy(q.pin, "5678");
    assert(sl_remote_stream(f->remote, 77, &q));
    sl_remote_update(f->remote, 100);
    uint32_t id = stream_request_id(f);
    size_t count = f->count;
    sl_remote_update(f->remote, 100);
    assert(f->count == count);
    CMsgRemoteDeviceStreamingResponse a = CMSG_REMOTE_DEVICE_STREAMING_RESPONSE__INIT;
    a.request_id = id;
    a.result = k_ERemoteDeviceStreamingBusy;
    reply(f, 6, &a.base);
    sl_remote_update(f->remote, 101);
    assert(stream_request_id(f) == id && !f->streams);
    control_key(f, f->count-1, f->saved.secret);
    CMsgRemoteDeviceProofRequest proof = CMSG_REMOTE_DEVICE_PROOF_REQUEST__INIT;
    uint8_t challenge[] = {0, 1, 2, 3, 4, 5};
    proof.challenge = (ProtobufCBinaryData){sizeof(challenge), challenge};
    proof.has_request_id = proof.has_update_secret = true;
    proof.request_id = id + 1;
    proof.update_secret = true;
    reply(f, 7, &proof.base);
    assert(f->saves == 1);
    proof.request_id = id;
    uint8_t source[38], expected[32];
    memcpy(source, f->saved.secret, 32);
    memcpy(source + 32, challenge, 6);
    assert(!IHS_CryptoSHA256(source, sizeof(source), expected));
    reply(f, 7, &proof.base);
    assert(f->saves == 2 && !memcmp(expected, f->saved.secret, 32));
    control_key(f, f->count-1, expected);
    reply(f, 7, &proof.base);
    assert(f->saves == 2);
    uint8_t key[16] = {7, 8, 9}, encrypted[64];
    size_t encrypted_size = sizeof(encrypted);
    assert(!IHS_CryptoSymmetricEncrypt(key, sizeof(key), expected, 32, encrypted, &encrypted_size));
    a.result = k_ERemoteDeviceStreamingSuccess;
    a.has_encrypted_session_key = a.has_port = true;
    a.port = 27031;
    a.encrypted_session_key = (ProtobufCBinaryData){encrypted_size, encrypted};
    reply(f, 6, &a.base);
    assert(f->streams == 1 && f->result == IHS_StreamingSuccess && f->stream_key_size == 16 &&
           !memcmp(key, f->stream_key, 16));
    sl_remote_destroy(f->remote);
    free(f);
}
static void sns_network_test_material(void) {
    fixture *f = create();
    sl_remote_peer peer = {.client_id = 77, .steam_id = 88, .secret = {1}};
    assert(sl_remote_watch(f->remote, &peer, 1));
    open_session(f, 44);
    IHS_StreamingRequest q = {0};
    sl_remote_stream_options options = {.network_test = true, .sns = true};
    assert(sl_remote_stream_ex(f->remote, 77, &q, &options));
    sl_remote_update(f->remote, 100);
    sl_proto_field out = sent(f, f->count - 1, 7);
    sl_proto_field packet = field(out.bytes, out.size, 4);
    uint32_t hs, ms;
    IHS_ReadUInt32LE(packet.bytes + 8, &hs);
    IHS_ReadUInt32LE(packet.bytes + 12 + hs, &ms);
    CMsgRemoteDeviceStreamingRequest *request =
        cmsg_remote_device_streaming_request__unpack(NULL, ms, packet.bytes + 16 + hs);
    assert(request && request->has_network_test && request->network_test);
    assert(request->n_supported_transport == 1 && request->supported_transport[0] == k_EStreamTransportSDR);
    uint32_t id = request->request_id;
    cmsg_remote_device_streaming_request__free_unpacked(request, NULL);
    uint8_t key[16] = {7}, encrypted[64];
    size_t length = sizeof(encrypted);
    assert(!IHS_CryptoSymmetricEncrypt(key, sizeof(key), peer.secret, 32, encrypted, &length));
    CMsgRemoteDeviceStreamingResponse a = CMSG_REMOTE_DEVICE_STREAMING_RESPONSE__INIT;
    a.request_id = id;
    a.result = k_ERemoteDeviceStreamingSuccess;
    a.has_transport = true;
    a.transport = k_EStreamTransportSDR;
    a.has_encrypted_session_key = true;
    a.encrypted_session_key = (ProtobufCBinaryData){length, encrypted};
    a.cert = "synthetic-cert";
    /* Official capture 042 returns port=0 for SDR. It is not a UDP route. */
    a.has_port = true;
    a.port = 0;
    reply(f, 6, &a.base);
    assert(f->streams == 1 && f->result == IHS_StreamingSuccess && f->stream_transport == 4);
    assert(f->stream_key_size == sizeof(key) && !memcmp(f->stream_key, key, sizeof(key)));
    assert(sl_remote_stream(f->remote, 77, &q));
    sl_remote_update(f->remote, 101);
    a.request_id = stream_request_id(f);
    a.transport = k_EStreamTransportUDP;
    reply(f, 6, &a.base);
    assert(f->streams == 2 && f->result == IHS_StreamingFailed);
    sl_remote_destroy(f->remote);
    free(f);
}
static void rotation_restart(void) {
    /* Synthetic host inputs, real crypto + production disk store + abrupt child
     * process exit. This proves local persistence, not host rollback policy. */
    uint8_t challenge[] = {4, 3, 2, 1}, old[32] = {1, 2, 3}, expected[32], source[36];
    memcpy(source, old, 32);
    memcpy(source + 32, challenge, sizeof(challenge));
    assert(!IHS_CryptoSHA256(source, sizeof(source), expected));
    for (unsigned stage = 0; stage <= 2; ++stage) {
        char directory[] = "/tmp/nsl-proof-restart-XXXXXX";
        assert(mkdtemp(directory));
        sl_auth_store store = {.device_id = 0x123456789abcdefULL, .bitrate_kbps = 6000};
        sl_host_registry_init(&store.registry);
        store.registry.count = 1;
        store.registry.hosts[0] =
            (sl_host){.id = 1, .client_id = 77, .account = 88, .paired = true, .has_secret = true};
        memcpy(store.secret, old, 32);
        memcpy(store.registry.hosts[0].secret, old, 32);
        assert(sl_auth_save(&store, directory));
        pid_t child = fork();
        assert(child >= 0);
        if (!child) {
            fixture *f = create();
            f->profile = directory;
            f->crash_stage = stage;
            f->save_ok = stage != 0;
            sl_remote_peer peer = {.client_id = 77, .steam_id = 88};
            memcpy(peer.secret, old, 32);
            assert(sl_remote_watch(f->remote, &peer, 1));
            open_session(f, 70);
            IHS_StreamingRequest q = {0};
            assert(sl_remote_stream(f->remote, 77, &q));
            sl_remote_update(f->remote, 100);
            CMsgRemoteDeviceProofRequest proof = CMSG_REMOTE_DEVICE_PROOF_REQUEST__INIT;
            proof.challenge = (ProtobufCBinaryData){sizeof(challenge), challenge};
            proof.has_request_id = proof.has_update_secret = true;
            proof.request_id = stream_request_id(f);
            proof.update_secret = true;
            size_t before = f->count;
            reply(f, 7, &proof.base);
            /* A failed save must emit neither a proof nor stream material. */
            assert(stage == 0 && f->streams == 1 && f->result == IHS_StreamingFailed &&
                   f->count == before);
            _exit(70);
        }
        int status;
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
               WEXITSTATUS(status) == (int)(70 + stage));
        assert(sl_auth_load(&store, directory) == 0);
        const uint8_t *key = stage ? expected : old;
        sl_host *h = &store.registry.hosts[0];
        assert(h->paired && h->has_secret && h->client_id == 77 && h->account == 88 &&
               store.device_id == 0x123456789abcdefULL && !memcmp(h->secret, key, 32));
        fixture *restarted = create();
        sl_remote_peer peer = {.client_id = h->client_id, .steam_id = h->account};
        memcpy(peer.secret, h->secret, 32);
        assert(sl_remote_watch(restarted->remote, &peer, 1));
        open_session(restarted, 71);
        IHS_StreamingRequest request = {0};
        assert(sl_remote_stream(restarted->remote, 77, &request));
        sl_remote_update(restarted->remote, 101);
        uint32_t id = stream_request_id(restarted);
        /* Validate the new request token with the actual reloaded key. */
        sl_proto_field out = sent(restarted, restarted->count - 1, 7);
        sl_proto_field packet = field(out.bytes, out.size, 4);
        uint32_t hs, ms;
        IHS_ReadUInt32LE(packet.bytes + 8, &hs);
        IHS_ReadUInt32LE(packet.bytes + 12 + hs, &ms);
        CMsgRemoteDeviceStreamingRequest *wire =
            cmsg_remote_device_streaming_request__unpack(NULL, ms, packet.bytes + 16 + hs);
        uint8_t token[64];
        size_t length = sizeof(token);
        uint64_t device;
        assert(wire &&
               !IHS_CryptoSymmetricDecrypt(wire->device_token.data, wire->device_token.len, key, 32,
                                           token, &length) &&
               length == 8);
        IHS_ReadUInt64LE(token, &device);
        assert(device == store.device_id);
        cmsg_remote_device_streaming_request__free_unpacked(wire, NULL);
        uint8_t session_key[16] = {9, 8, 7}, encrypted[64];
        length = sizeof(encrypted);
        assert(!IHS_CryptoSymmetricEncrypt(session_key, sizeof(session_key), key, 32, encrypted,
                                           &length));
        CMsgRemoteDeviceStreamingResponse response = CMSG_REMOTE_DEVICE_STREAMING_RESPONSE__INIT;
        response.request_id = id;
        response.result = k_ERemoteDeviceStreamingSuccess;
        response.has_port = response.has_encrypted_session_key = true;
        response.port = 27031;
        response.encrypted_session_key = (ProtobufCBinaryData){length, encrypted};
        reply(restarted, 6, &response.base);
        assert(restarted->streams == 1 && restarted->result == IHS_StreamingSuccess &&
               restarted->stream_key_size == sizeof(session_key) &&
               !memcmp(restarted->stream_key, session_key, sizeof(session_key)) &&
               !restarted->saves);
        sl_remote_destroy(restarted->remote);
        free(restarted);
        char path[256];
        snprintf(path, sizeof(path), "%s/profile.bin", directory);
        assert(!unlink(path) && !rmdir(directory));
        memset(&store, 0, sizeof(store));
    }
}
static void wire(void) {
    char accept[29];
    assert(sl_ws_accept("dGhlIHNhbXBsZSBub25jZQ==", accept));
    assert(!strcmp(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    const char response[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                            "Connection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: "
                            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    assert(sl_ws_upgrade_valid((const uint8_t *)response, sizeof(response) - 1, accept));
    assert(!sl_ws_upgrade_valid((const uint8_t *)response, sizeof(response) - 2, accept));
    accept[0] = 'A';
    assert(!sl_ws_upgrade_valid((const uint8_t *)response, sizeof(response) - 1, accept));
    uint8_t raw[512], payload[128] = {0}, mask[] = {1, 2, 3, 4};
    assert(sl_ws_encode(raw, sizeof(raw), 2, payload, 128, mask) == 136);
    assert(raw[0] == 0x82 && raw[1] == 0xfe && raw[2] == 0 && raw[3] == 128);
    sl_ws_frame f;
    assert(sl_ws_decode(raw, 136, &f) == -1); /* Masked server frame. */
    const uint8_t server[] = {0x82, 3, 1, 2, 3};
    for (size_t i = 0; i < sizeof(server); ++i)
        assert(sl_ws_decode(server, i, &f) == 0);
    assert(sl_ws_decode(server, sizeof(server), &f) == 1 && f.size == 3);
    const uint8_t bad[] = {0x89, 126, 0, 126};
    assert(sl_ws_decode(bad, sizeof(bad), &f) == -1);
    const uint8_t overflow[] = {8, 255, 255, 255, 255, 255, 255, 255, 255, 255, 2};
    sl_proto_reader r = {overflow, sizeof(overflow), 0, false};
    sl_proto_field p;
    assert(!sl_proto_next(&r, &p) && !sl_proto_done(&r));
}
int main(void) {
    rotation_restart();
    reordered_pairing_rpcs();
    retry_after_cancel_and_rotation();
    sns_network_test_material();
    wire();
    lifecycle();
    cancel_and_failure();
    pairing_and_rotation();
    known_host_reauthorization();
    retired_stream_requests();
    puts("PASS cloud framing, session replacement, subscriptions, cancellation, pairing crypto, "
         "proof rotation and retries");
    return 0;
}
