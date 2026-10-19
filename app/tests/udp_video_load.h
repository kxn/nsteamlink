/* Controlled slow-SDK adapter and read-only load observations. No production
 * packet, decoder outcome or clock is substituted. Only this fixture sleeps. */
#include "session/channels/ch_data.h"
#include <errno.h>
#define UDP_LOAD_LIMIT 1024
static bool udpLoadMode;
static unsigned udpLoadDataLost;
static unsigned udpLoadDelayUS, udpLoadSubmittingId, udpLoadSdkCount, udpLoadPictureCount;
static IHS_Session *udpLoadSession;
static atomic_bool udpLoadBusy;
static atomic_uint udpLoadReceived, udpLoadReceivedBusy;
static struct {
    unsigned id;
    size_t size, queued, queuedBytes;
    uint8_t sha[32];
    int result;
    uint64_t elapsed;
} udpLoadSdk[UDP_LOAD_LIMIT];
static struct {
    unsigned id;
    uint8_t md5[16];
} udpLoadPictures[UDP_LOAD_LIMIT];
static uint64_t udpLoadNow(void) {
    struct timespec t;
    assert(!clock_gettime(CLOCK_MONOTONIC, &t));
    return (uint64_t)t.tv_sec * 1000000000 + (uint64_t)t.tv_nsec;
}
static uint64_t udpLoadSDKBegin(size_t size, const uint8_t sha[32]) {
    assert(udpLoadSdkCount < UDP_LOAD_LIMIT);
    unsigned n = udpLoadSdkCount;
    udpLoadSdk[n].id = udpLoadSubmittingId;
    udpLoadSdk[n].size = size;
    memcpy(udpLoadSdk[n].sha, sha, 32);
    IHS_SessionChannelData *ch = (void *)udpLoadSession->channels[3];
    assert(ch);
    IHS_MutexLock(ch->windowLock);
    udpLoadSdk[n].queued = ch->fecQueuedCount;
    udpLoadSdk[n].queuedBytes = ch->fecQueuedBytes;
    IHS_MutexUnlock(ch->windowLock);
    atomic_store(&udpLoadBusy, true);
    uint64_t begin = udpLoadNow();
    struct timespec left = {udpLoadDelayUS / 1000000, (long)(udpLoadDelayUS % 1000000) * 1000};
    if (udpLoadDelayUS)
        while (nanosleep(&left, &left) && errno == EINTR) {
        }
    IHS_MutexLock(ch->windowLock);
    udpLoadSdk[n].queued = ch->fecQueuedCount;
    udpLoadSdk[n].queuedBytes = ch->fecQueuedBytes;
    IHS_MutexUnlock(ch->windowLock);
    return begin;
}
static void udpLoadSDKEnd(uint64_t begin, int result) {
    udpLoadSdk[udpLoadSdkCount].result = result;
    udpLoadSdk[udpLoadSdkCount++].elapsed = udpLoadNow() - begin;
    atomic_store(&udpLoadBusy, false);
}
void __real_IHS_SessionChannelDataReceiveReliableFrame(IHS_SessionChannel *, IHS_SessionFrame *);
void __wrap_IHS_SessionChannelDataReceiveReliableFrame(IHS_SessionChannel *channel,
                                                       IHS_SessionFrame *frame) {
    if (udpLoadMode && channel->id == 3) {
        atomic_fetch_add(&udpLoadReceived, 1);
        if (atomic_load(&udpLoadBusy))
            atomic_fetch_add(&udpLoadReceivedBusy, 1);
    }
    __real_IHS_SessionChannelDataReceiveReliableFrame(channel, frame);
}
static void udpLoadPixel(unsigned id, const uint8_t md5[16]) {
    assert(udpLoadPictureCount < UDP_LOAD_LIMIT);
    udpLoadPictures[udpLoadPictureCount].id = id;
    memcpy(udpLoadPictures[udpLoadPictureCount++].md5, md5, 16);
}
static FILE *udpLoadReplay;
static void udpLoadSend(int socket, const struct sockaddr_in *address, uint8_t local,
                        const char *filename, bool crc, bool last) {
    if (filename) {
        assert(!udpLoadReplay);
        udpLoadReplay = fopen(filename, "rb");
        assert(udpLoadReplay);
    }
    assert(udpLoadReplay);
    unsigned count = 0;
    for (;;) {
        uint8_t bytes[4];
        assert(fread(bytes, 1, 4, udpLoadReplay) == 4);
        uint32_t size = 0;
        for (unsigned n = 0; n < 4; ++n)
            size |= (uint32_t)bytes[n] << (8 * n);
        if (!size)
            break;
        uint8_t wire[2048];
        assert(size >= 13 && size <= sizeof(wire));
        assert(fread(wire, 1, size, udpLoadReplay) == size);
        assert(wire[4] == 3 && ((wire[0] & 128) != 0) == crc);
        wire[3] = local;
        if (crc) {
            uint32_t value = IHS_CRC32C(wire, size - 4);
            for (unsigned i = 0; i < 4; ++i)
                wire[size - 4 + i] = (uint8_t)(value >> (8 * i));
        }
        assert(sendto(socket, wire, size, 0, (const struct sockaddr *)address, sizeof(*address)) ==
               (ssize_t)size);
        ++count;
    }
    assert(count);
    if (last) {
        assert(fgetc(udpLoadReplay) == EOF && !ferror(udpLoadReplay));
        assert(!fclose(udpLoadReplay));
        udpLoadReplay = NULL;
    }
}
static void udpLoadReport(void) {
    assert(!udpLoadReplay && !atomic_load(&udpLoadBusy));
    printf(",\"load\":{\"datalost\":%u,\"received\":%u,\"received_while_sdk\":%u,\"sdk\":[",
           udpLoadDataLost, atomic_load(&udpLoadReceived), atomic_load(&udpLoadReceivedBusy));
    for (unsigned n = 0; n < udpLoadSdkCount; ++n) {
        printf("%s{\"id\":%u,\"size\":%zu,\"result\":%d,\"elapsed_ns\":%llu,\"queued\":%zu,"
               "\"queued_bytes\":%zu,\"sha256\":\"",
               n ? "," : "", udpLoadSdk[n].id, udpLoadSdk[n].size, udpLoadSdk[n].result,
               (unsigned long long)udpLoadSdk[n].elapsed, udpLoadSdk[n].queued,
               udpLoadSdk[n].queuedBytes);
        for (unsigned j = 0; j < 32; ++j)
            printf("%02x", udpLoadSdk[n].sha[j]);
        printf("\"}");
    }
    printf("],\"pictures\":[");
    for (unsigned n = 0; n < udpLoadPictureCount; ++n) {
        printf("%s{\"id\":%u,\"md5\":\"", n ? "," : "", udpLoadPictures[n].id);
        for (unsigned j = 0; j < 16; ++j)
            printf("%02x", udpLoadPictures[n].md5[j]);
        printf("\"}");
    }
    printf("]}");
}
