/* Actual production file read/write and public Session snapshot integration.
 * File failures are driven by real filesystem objects in the Python checker.
 * Session collector/finish boundaries are explicit, not a network/Host test. */
#include "ihslib.h"
#include "network_stats_file.h"
#include "session/session_pri.h"
#include "test_session.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *fault;
static unsigned allocation, renames;
void *__real_malloc(size_t);
void *__wrap_malloc(size_t size) {
    if (fault && !strncmp(fault, "alloc", 5) && ++allocation == (unsigned)atoi(fault + 5))
        return NULL;
    return __real_malloc(size);
}
int __real_fclose(FILE *);
int __wrap_fclose(FILE *file) {
    int result = __real_fclose(file);
    if (fault && !strcmp(fault, "close")) {
        errno = EIO;
        return EOF;
    }
    return result;
}
int __real_rename(const char *, const char *);
int __wrap_rename(const char *from, const char *to) {
    if (fault && !strcmp(fault, "rollback")) {
        ++renames;
        if (renames == 1 || renames == 3) {
            errno = renames == 1 ? EEXIST : EIO;
            return -1;
        }
    } else if (fault && !strcmp(fault, "rename")) {
        errno = EIO;
        return -1;
    }
    return __real_rename(from, to);
}

static uint8_t *unhex(const char *hex, size_t *size) {
    *size = !strcmp(hex, "-") ? 0 : strlen(hex) / 2;
    assert(!strcmp(hex, "-") || strlen(hex) % 2 == 0);
    uint8_t *bytes = malloc(*size + 1);
    assert(bytes);
    for (size_t i = 0; i < *size; ++i) {
        unsigned byte;
        assert(sscanf(hex + i * 2, "%2x", &byte) == 1);
        bytes[i] = byte;
    }
    return bytes;
}
static void print_average(bool ok, sl_network_stats_average average) {
    unsigned char *bits = (void *)&average;
    printf("{\"ok\":%s,\"average\":\"", ok ? "true" : "false");
    for (unsigned i = 0; i < 12; ++i)
        printf("%02x", bits[i]);
    puts("\"}");
}
static uint32_t little32(const uint8_t *p) {
    return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
int main(int argc, char **argv) {
    assert(argc >= 4);
    const char *mode = argv[1], *directory = argv[2];
    size_t size;
    if (!strcmp(mode, "load")) {
        assert(argc == 5);
        sl_network_stats_average average;
        uint8_t *bits = unhex(argv[3], &size);
        assert(size == sizeof(average) && size == 12);
        memcpy(&average, bits, size);
        free(bits);
        bool ok = sl_network_stats_load(directory, atoi(argv[4]) ? &average : NULL);
        print_average(ok, average);
    } else if (!strcmp(mode, "action")) {
        assert(argc == 5);
        unsigned requested = strtoul(argv[3], NULL, 0);
        bool readable = requested == 0 ? sl_network_stats_load(directory, NULL) : false;
        unsigned action = sl_network_stats_connect_action(requested, atoi(argv[4]), readable);
        printf("{\"action\":%u,\"test\":%s}\n", action, action ? "true" : "false");
    } else if (!strcmp(mode, "save")) {
        assert(argc == 5);
        sl_network_stats_average average;
        uint8_t *bits = unhex(argv[3], &size);
        assert(size == 12);
        memcpy(&average, bits, size);
        free(bits);
        bits = unhex(argv[4], &size);
        assert(!(size % 8));
        size_t count = size / 8;
        IHS_NetworkTestSample *samples = malloc(count * sizeof(*samples) + 1);
        assert(samples);
        for (size_t i = 0; i < count; ++i)
            samples[i] =
                (IHS_NetworkTestSample){little32(bits + i * 8), little32(bits + i * 8 + 4)};
        free(bits);
        bool ok = sl_network_stats_save(directory, &average, samples, count);
        free(samples);
        printf("{\"ok\":%s}\n", ok ? "true" : "false");
    } else if (!strcmp(mode, "guard")) {
        /* Guard failures leave the old final file in place. */
        sl_network_stats_average average = {1, 2, 3};
        IHS_NetworkTestSample sample = {15000, 65};
        fault = argv[3];
        bool ok = sl_network_stats_save(directory, &average, &sample,
                                        !strcmp(fault, "overflow") ? SIZE_MAX : 1);
        fault = NULL;
        printf("{\"ok\":%s}\n", ok ? "true" : "false");
    } else if (!strcmp(mode, "session")) {
        /* Real collector and public snapshot/copy API; transport/finish entry
         * is explicitly driven, no RX/send background workers launched. */
        IHS_Init();
        IHS_Session *s = IHS_TestSessionCreate();
        assert(s);
        IHS_TimerTaskStopImmediate(s->retransmission.timer);
        assert(!sl_network_stats_save_session(directory, s));
        assert(IHS_SessionConfigureNetworkTest(s, IHS_NetworkTestBandwidth, 15000));
        IHS_SessionNetworkTestBegin(s);
        assert(!sl_network_stats_save_session(directory, s));
        IHS_SessionNetworkTestTarget(s, 15000);
        unsigned count = strtoul(argv[3], NULL, 0);
        assert(count && count <= 2000);
        for (unsigned i = 0; i < count; ++i) {
            if (i == 300)
                IHS_SessionNetworkTestTarget(s, 100000);
            assert(IHS_MediaNetworkStatsRecord(&s->mediaNetworkStats, count == 1 ? 599 : i, 1000,
                                               66536));
        }
        s->networkTest.phase = 5; /* Completed run-loop entry; §119 tests its triggers. */
        IHS_SessionNetworkTestUpdate(s, 66536);
        IHS_SessionNetworkTestFinalize(s);
        IHS_NetworkTestResult result;
        IHS_SessionGetNetworkTestResult(s, &result);
        assert(result.status == IHS_NetworkTestComplete && result.samples == count);
        bool ok = sl_network_stats_save_session(directory, s);
        IHS_SessionMediaNetworkStats stats;
        IHS_SessionGetMediaNetworkStats(s, &stats);
        sl_network_stats_average average = {stats.lossPercent, stats.meanNetworkMs,
                                            stats.deviationMs};
        if (count == 1)
            assert(result.lossPercent == 0 && average.loss_percent > 99.9f);
        IHS_SessionDestroy(s);
        IHS_Quit();
        print_average(ok, average);
    } else
        assert(!"unknown operation");
    return 0;
}
