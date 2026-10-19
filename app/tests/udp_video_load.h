/* Controlled slow-SDK adapter and read-only load observations. No production
 * packet, decoder outcome or clock is substituted. Only this fixture sleeps. */
#include "session/channels/ch_data.h"
#include "session/frame_tracker.h"
#include <errno.h>
#define UDP_LOAD_LIMIT 1024
static bool udpLoadMode;
static unsigned udpLoadDataLost, udpLoadNacks, udpLoadFault, udpLoadRepairSize;
static int udpLoadHole = -1;
static bool udpLoadRepaired;
static uint8_t udpLoadRepair[2048];
static atomic_uint udpLoadRetired;
static atomic_uint_fast64_t udpLoadRetiredCapacity;
static _Thread_local unsigned udpLoadEnqueueDepth;
static unsigned udpLoadRxIds[UDP_LOAD_LIMIT], udpLoadConsumedIds[UDP_LOAD_LIMIT], udpLoadConsumed;
static struct {
    size_t size;
    uint8_t wire[96];
} udpLoadFeedbacks[256];
static unsigned udpLoadDelayUS, udpLoadSubmittingId, udpLoadSdkCount, udpLoadPictureCount;
static IHS_Session *udpLoadSession;
static atomic_bool udpLoadBusy;
static atomic_uint udpLoadReceived, udpLoadReceivedBusy;
static struct {
    unsigned id, consumed;
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
    udpLoadSdk[n].consumed = udpLoadConsumed;
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
        unsigned n = atomic_fetch_add(&udpLoadReceived, 1);
        assert(n < UDP_LOAD_LIMIT && frame->body.size >= 3);
        const uint8_t *body = IHS_BufferPointer(&frame->body);
        udpLoadRxIds[n] = body[1] | (unsigned)body[2] << 8;
        if (atomic_load(&udpLoadBusy))
            atomic_fetch_add(&udpLoadReceivedBusy, 1);
    }
    ++udpLoadEnqueueDepth;
    __real_IHS_SessionChannelDataReceiveReliableFrame(channel, frame);
    --udpLoadEnqueueDepth;
}
IHS_FrameBeginResult __real_IHS_FrameTrackerBeginInput(IHS_FrameTracker *, uint64_t, uint16_t,
                                                       const IHS_FrameReceive *,
                                                       IHS_FrameTicket **);
IHS_FrameBeginResult __wrap_IHS_FrameTrackerBeginInput(IHS_FrameTracker *tracker, uint64_t epoch,
                                                       uint16_t id,
                                                       const IHS_FrameReceive *received,
                                                       IHS_FrameTicket **out) {
    if (udpLoadMode) {
        assert(udpLoadConsumed < UDP_LOAD_LIMIT);
        udpLoadConsumedIds[udpLoadConsumed++] = id;
    }
    return __real_IHS_FrameTrackerBeginInput(tracker, epoch, id, received, out);
}
void __real_IHS_BufferClear(IHS_Buffer *, bool);
void __wrap_IHS_BufferClear(IHS_Buffer *body, bool release) {
    /* Producer enqueue owns windowLock here. Count actual retired complete
     * bodies, excluding the worker/stop paths and all initially empty buffers. */
    if (udpLoadMode && udpLoadEnqueueDepth && release && body->size &&
        IHS_BufferPointer(body)[0] == 1) {
        atomic_fetch_add(&udpLoadRetired, 1);
        atomic_fetch_add(&udpLoadRetiredCapacity, body->capacity);
    }
    __real_IHS_BufferClear(body, release);
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
        unsigned id = wire[7] | (unsigned)wire[8] << 8;
        if (udpLoadFault && (wire[0] & 127) != 11 && (int)id == udpLoadHole) {
            assert(!udpLoadRepairSize);
            memcpy(udpLoadRepair, wire, size);
            udpLoadRepairSize = size;
        } else
            assert(sendto(socket, wire, size, 0, (const struct sockaddr *)address,
                          sizeof(*address)) == (ssize_t)size);
        ++count;
    }
    assert(count);
    if (last) {
        assert(fgetc(udpLoadReplay) == EOF && !ferror(udpLoadReplay));
        assert(!fclose(udpLoadReplay));
        udpLoadReplay = NULL;
    }
}
static bool udpLoadRequested(const uint8_t *wire, size_t size, unsigned id) {
    if (size < 19)
        return false;
    uint16_t base = (uint16_t)(wire[7] | (unsigned)wire[8] << 8);
    uint16_t confirmed = (uint16_t)(wire[17] | (unsigned)wire[18] << 8);
    if ((int16_t)(id - confirmed) > 0 && (int16_t)(base - id) > 0)
        return true;
    unsigned offset = (uint16_t)(id - base);
    return offset < (size - 19) * 8 && !(wire[19 + offset / 8] & (1u << (offset % 8)));
}
static void udpLoadOnFeedback(int socket, const struct sockaddr_in *address, const uint8_t *wire,
                              size_t size, bool crc) {
    if ((wire[0] & 127) != 10 || wire[4] != 3)
        return;
    assert(size <= sizeof(udpLoadFeedbacks[0].wire));
    unsigned n = udpLoadNacks++;
    if (n < 256) {
        udpLoadFeedbacks[n].size = size;
        memcpy(udpLoadFeedbacks[n].wire, wire, size);
    }
    size_t plain = size;
    if (crc) {
        assert(size >= 17);
        uint32_t value = 0;
        for (unsigned i = 0; i < 4; ++i)
            value |= (uint32_t)wire[size - 4 + i] << (8 * i);
        assert(value == IHS_CRC32C(wire, size - 4));
        plain -= 4;
    }
    if (udpLoadFault == 1 && !udpLoadRepaired && udpLoadRepairSize &&
        udpLoadRequested(wire, plain, (unsigned)udpLoadHole)) {
        udpLoadRepair[1] = 1;
        if (crc) {
            uint32_t value = IHS_CRC32C(udpLoadRepair, udpLoadRepairSize - 4);
            for (unsigned i = 0; i < 4; ++i)
                udpLoadRepair[udpLoadRepairSize - 4 + i] = (uint8_t)(value >> (8 * i));
        }
        assert(sendto(socket, udpLoadRepair, udpLoadRepairSize, 0, (const struct sockaddr *)address,
                      sizeof(*address)) == (ssize_t)udpLoadRepairSize);
        udpLoadRepaired = true;
    }
}
static void udpLoadReport(void) {
    assert(!udpLoadReplay && !atomic_load(&udpLoadBusy));
    printf(",\"load\":{\"datalost\":%u,\"received\":%u,\"received_while_sdk\":%u,\"sdk\":[",
           udpLoadDataLost, atomic_load(&udpLoadReceived), atomic_load(&udpLoadReceivedBusy));
    for (unsigned n = 0; n < udpLoadSdkCount; ++n) {
        printf("%s{\"id\":%u,\"size\":%zu,\"result\":%d,\"elapsed_ns\":%llu,\"queued\":%zu,"
               "\"queued_bytes\":%zu,\"consumed\":%u,\"sha256\":\"",
               n ? "," : "", udpLoadSdk[n].id, udpLoadSdk[n].size, udpLoadSdk[n].result,
               (unsigned long long)udpLoadSdk[n].elapsed, udpLoadSdk[n].queued,
               udpLoadSdk[n].queuedBytes, udpLoadSdk[n].consumed);
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
    printf("],\"retired\":%u,\"retired_capacity\":%llu,\"nacks\":%u,\"repaired\":%s,\"rx_ids\":[",
           atomic_load(&udpLoadRetired), (unsigned long long)atomic_load(&udpLoadRetiredCapacity),
           udpLoadNacks, udpLoadRepaired ? "true" : "false");
    for (unsigned n = 0; n < atomic_load(&udpLoadReceived); ++n)
        printf("%s%u", n ? "," : "", udpLoadRxIds[n]);
    printf("],\"consumed_ids\":[");
    for (unsigned n = 0; n < udpLoadConsumed; ++n)
        printf("%s%u", n ? "," : "", udpLoadConsumedIds[n]);
    printf("],\"feedback\":[");
    for (unsigned n = 0; n < udpLoadNacks && n < 256; ++n) {
        printf("%s\"", n ? "," : "");
        for (size_t j = 0; j < udpLoadFeedbacks[n].size; ++j)
            printf("%02x", udpLoadFeedbacks[n].wire[j]);
        printf("\"");
    }
    printf("]}");
}
