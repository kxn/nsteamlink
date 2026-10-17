/* Read-only observers around the normal IHS calls. Only the debug product
 * links these adapters; private test drivers keep their own independent hooks. */
#include "ihs_udp.h"
#include "packet_diagnostics.h"
#include "session/channels/ch_data.h"
#include <string.h>
static uint64_t peer_key(const IHS_SocketAddress *address) {
    if (address->ip.family != IHS_IPAddressFamilyIPv4)
        return 0;
    uint32_t ip;
    memcpy(&ip, address->ip.v4.data, sizeof(ip));
    return ((uint64_t)ip << 16) | address->port;
}
bool __real_IHS_SessionConnect(IHS_Session *);
bool __wrap_IHS_SessionConnect(IHS_Session *session) {
    sl_packet_diagnostics_begin(peer_key(&IHS_SessionGetInfo(session)->address));
    return __real_IHS_SessionConnect(session);
}
int __real_IHS_UDPSocketReceive(IHS_UDPSocket *, IHS_UDPPacket *);
int __wrap_IHS_UDPSocketReceive(IHS_UDPSocket *socket, IHS_UDPPacket *packet) {
    int result = __real_IHS_UDPSocketReceive(socket, packet);
    if (result > 0) {
        IHS_SessionPacketHeader header;
        bool parsed = packet->buffer.size >= IHS_PACKET_HEADER_SIZE &&
                      IHS_SessionPacketHeaderParse(&header, IHS_BufferPointer(&packet->buffer));
        bool media = parsed && (header.type == IHS_SessionPacketTypeUnreliable ||
                                header.type == IHS_SessionPacketTypeUnreliableFrag);
        sl_packet_diagnostics_raw(peer_key(&packet->address), parsed ? header.channelId : 32,
                                  media);
    }
    return result;
}
void __real_IHS_SessionChannelDataReceived(IHS_SessionChannel *, IHS_SessionPacket *);
void __wrap_IHS_SessionChannelDataReceived(IHS_SessionChannel *channel, IHS_SessionPacket *packet) {
    if (packet->header.type == IHS_SessionPacketTypeUnreliable ||
        packet->header.type == IHS_SessionPacketTypeUnreliableFrag)
        sl_packet_diagnostics_admit(channel->id);
    __real_IHS_SessionChannelDataReceived(channel, packet);
}
bool __real_IHS_SessionChannelQueuePacket(IHS_SessionChannel *, IHS_SessionPacket *, bool);
bool __wrap_IHS_SessionChannelQueuePacket(IHS_SessionChannel *channel, IHS_SessionPacket *packet,
                                          bool reliable) {
    bool recovery = (channel->type == IHS_SessionChannelTypeDataAudio ||
                     channel->type == IHS_SessionChannelTypeDataVideo) &&
                    packet->header.type == IHS_SessionPacketTypeUnreliable && packet->body.size &&
                    *IHS_BufferPointer(&packet->body) == k_EStreamDataLost;
    bool result = __real_IHS_SessionChannelQueuePacket(channel, packet, reliable);
    if (recovery && result)
        sl_packet_diagnostics_recovery(channel->id);
    return result;
}
