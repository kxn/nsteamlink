/* Transparent diagnostic observations. No allocation, I/O, waits or retained
 * protobuf pointers. Requests, producer admission, actual socket attempts and
 * the peer's accepted negotiation are distinct facts; none is an FEC ACK.
 * A fixed ledger is published BEFORE the original queue can expose a head to
 * the sender. Entries are never reused during a one-session probe. */
#pragma once
#include "ihs_udp.h"
#include "session/channels/ch_control.h"
#include "session/session_pri.h"
#include <stdatomic.h>
#include <string.h>

enum { PROBE_CONFIG_SLOTS = 32, PROBE_CONFIG_HEAD_BYTES = 1472 };
typedef struct probe_config_entry {
    atomic_bool ready;
    const IHS_UDPSocket *socket;
    uint16_t id;
    uint8_t local, peer, kind, fec;
    size_t bytes;
    uint8_t body[PROBE_CONFIG_HEAD_BYTES];
} probe_config_entry;
static probe_config_entry probe_config_entries[PROBE_CONFIG_SLOTS];
static atomic_uint probe_config_used, probe_config_overflow, probe_peer_config;
static atomic_uint_fast64_t probe_config_calls[2], probe_config_admitted[2];
static atomic_uint_fast64_t probe_config_queued[2], probe_config_sent[2], probe_config_failed[2];
static atomic_uint probe_config_fec[2];      /* bit2 presence marker, bit1 has, bit0 value */
static atomic_uint probe_config_sent_fec[2]; /* bitmap of has/value pairs actually sent */
typedef struct probe_config_scope {
    IHS_Session *session;
    unsigned kind;
    uint8_t fec;
} probe_config_scope;
static _Thread_local const probe_config_scope *probe_config_current;

bool __real_IHS_SessionChannelControlSend(IHS_SessionChannel *, EStreamControlMessage,
                                          const ProtobufCMessage *, int32_t);
bool __wrap_IHS_SessionChannelControlSend(IHS_SessionChannel *channel, EStreamControlMessage type,
                                          const ProtobufCMessage *message, int32_t id) {
    const CStreamingClientConfig *config = NULL;
    unsigned kind = type == k_EStreamControlNegotiationSetConfig ? 0 : 1;
    if (!channel->session->networkTest.mode && message) {
        if (!kind && message->descriptor == &cnegotiation_set_config_msg__descriptor)
            config = ((const CNegotiationSetConfigMsg *)message)->streaming_client_config;
        else if (type == k_EStreamControlSetStreamingClientConfig &&
                 message->descriptor == &cset_streaming_client_config__descriptor)
            config = ((const CSetStreamingClientConfig *)message)->config;
    }
    if (!config)
        return __real_IHS_SessionChannelControlSend(channel, type, message, id);
    atomic_fetch_add_explicit(&probe_config_calls[kind], 1, memory_order_relaxed);
    uint8_t fec = 4u | !!config->has_enable_unreliable_fec << 1 | !!config->enable_unreliable_fec;
    atomic_store_explicit(&probe_config_fec[kind], fec, memory_order_relaxed);
    const probe_config_scope scope = {.session = channel->session, .kind = kind, .fec = fec};
    const probe_config_scope *previous = probe_config_current;
    probe_config_current = &scope;
    bool result = __real_IHS_SessionChannelControlSend(channel, type, message, id);
    probe_config_current = previous;
    if (result)
        atomic_fetch_add_explicit(&probe_config_admitted[kind], 1, memory_order_relaxed);
    return result;
}
IHS_SendAdmission __real_IHS_SessionQueuePacketResult(IHS_Session *, IHS_SessionPacket *, bool);
IHS_SendAdmission __wrap_IHS_SessionQueuePacketResult(IHS_Session *s, IHS_SessionPacket *p,
                                                      bool retransmit) {
    const probe_config_scope *scope = probe_config_current;
    bool watched = scope && scope->session == s && p->header.channelId == 1 &&
                   p->header.type == IHS_SessionPacketTypeReliable && !p->header.autoPacketId;
    if (watched) {
        unsigned index = atomic_fetch_add_explicit(&probe_config_used, 1, memory_order_relaxed);
        if (index < PROBE_CONFIG_SLOTS && p->body.data && p->body.size &&
            p->body.size <= PROBE_CONFIG_HEAD_BYTES) {
            probe_config_entry *entry = &probe_config_entries[index];
            entry->socket = s->base.socket;
            entry->id = p->header.packetId;
            entry->local = p->header.srcConnectionId;
            entry->peer = p->header.dstConnectionId;
            entry->kind = scope->kind;
            entry->fec = scope->fec;
            entry->bytes = p->body.size;
            memcpy(entry->body, IHS_BufferPointer(&p->body), p->body.size);
            atomic_store_explicit(&entry->ready, true, memory_order_release);
        } else
            atomic_fetch_add_explicit(&probe_config_overflow, 1, memory_order_relaxed);
    }
    IHS_SendAdmission result = __real_IHS_SessionQueuePacketResult(s, p, retransmit);
    if (watched && result == IHS_SendAdmissionAccepted)
        atomic_fetch_add_explicit(&probe_config_queued[scope->kind], 1, memory_order_relaxed);
    return result;
}
static void probe_config_socket(const IHS_UDPSocket *socket, const IHS_UDPPacket *packet,
                                bool sent) {
    if (!packet->buffer.data || packet->buffer.size <= IHS_PACKET_HEADER_SIZE)
        return;
    const uint8_t *b = IHS_BufferPointer(&packet->buffer);
    if (b[4] != 1 || (b[0] & 127) != IHS_SessionPacketTypeReliable)
        return; /* continuation type6 can start with arbitrary ciphertext */
    size_t overhead = IHS_PACKET_HEADER_SIZE + ((b[0] & 128) ? 4u : 0u);
    if (packet->buffer.size <= overhead)
        return;
    for (unsigned i = 0; i < PROBE_CONFIG_SLOTS; ++i) {
        const probe_config_entry *entry = &probe_config_entries[i];
        if (atomic_load_explicit(&entry->ready, memory_order_acquire) && entry->socket == socket &&
            entry->local == b[2] && entry->peer == b[3] &&
            entry->id == (unsigned)(b[7] | (unsigned)b[8] << 8) &&
            entry->bytes == packet->buffer.size - overhead &&
            !memcmp(entry->body, b + IHS_PACKET_HEADER_SIZE, entry->bytes)) {
            atomic_fetch_add_explicit(sent ? &probe_config_sent[entry->kind]
                                           : &probe_config_failed[entry->kind],
                                      1, memory_order_relaxed);
            if (sent)
                atomic_fetch_or_explicit(&probe_config_sent_fec[entry->kind],
                                         1u << (entry->fec & 3u), memory_order_relaxed);
            break;
        }
    }
}
void __real_IHS_SessionChannelControlOnNegotiation(IHS_SessionChannel *, EStreamControlMessage,
                                                   IHS_Buffer *, const IHS_SessionPacketHeader *);
void __wrap_IHS_SessionChannelControlOnNegotiation(IHS_SessionChannel *channel,
                                                   EStreamControlMessage type, IHS_Buffer *payload,
                                                   const IHS_SessionPacketHeader *header) {
    bool watched = !channel->session->networkTest.mode &&
                   type == k_EStreamControlNegotiationSetConfig &&
                   channel->session->state.connectionState == IHS_SessionConnectionStateNegotiating;
    __real_IHS_SessionChannelControlOnNegotiation(channel, type, payload, header);
    if (watched && channel->session->state.connectionState == IHS_SessionConnectionStateStarting)
        atomic_fetch_add_explicit(&probe_peer_config, 1, memory_order_relaxed);
}
