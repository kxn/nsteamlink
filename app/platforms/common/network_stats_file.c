/* Official shell Load/SaveNetworkStats and Panel ctor, protocol reference §121.
 * All allocation, formatting and filesystem access belongs to runtime worker. */
#include "network_stats_file.h"
#include "crc32.h"
#include "protobuf/remoteplay.pb-c.h"
#include <errno.h>
#include <ihslib/session.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool path_for(char path[512], const char *dir, const char *name) {
    if (!dir)
        return false;
    int n = snprintf(path, 512, "%s/%s", dir, name);
    return n >= 0 && n < 512;
}
static bool varint(const uint8_t *wire, size_t length, size_t *pos, uint64_t *value) {
    *value = 0;
    for (unsigned shift = 0; shift < 70 && *pos < length; shift += 7) {
        uint8_t byte = wire[(*pos)++];
        if (shift == 63 && byte > 1)
            return false;
        *value |= (uint64_t)(byte & 127) << shift;
        if (!(byte & 128))
            return true;
    }
    return false;
}
static bool skip(const uint8_t *wire, size_t length, size_t *pos, uint32_t tag, unsigned depth) {
    uint64_t value;
    size_t n;
    switch (tag & 7) {
    case 0:
        return varint(wire, length, pos, &value);
    case 1:
        n = 8;
        break;
    case 2:
        if (!varint(wire, length, pos, &value) || value > length - *pos)
            return false;
        n = (size_t)value;
        break;
    case 3:
        /* Bounded recursion is a local parser resource guard. */
        if (depth == 100)
            return false;
        while (*pos < length) {
            if (!varint(wire, length, pos, &value) || value > UINT32_MAX || !(value >> 3))
                return false;
            if ((value & 7) == 4)
                return (value >> 3) == (tag >> 3);
            if (!skip(wire, length, pos, (uint32_t)value, depth + 1))
                return false;
        }
        return false;
    case 5:
        n = 4;
        break;
    default:
        return false;
    }
    if (n > length - *pos)
        return false;
    *pos += n;
    return true;
}
static void parse_prefix(const uint8_t *wire, size_t length, sl_network_stats_average *out) {
    uint32_t values[3] = {0};
    size_t pos = 0;
    while (pos < length) {
        uint64_t value;
        if (!varint(wire, length, &pos, &value) || value > UINT32_MAX || !(value >> 3))
            break;
        unsigned field = (uint32_t)value >> 3;
        if ((value & 7) == 5 && field >= 1 && field <= 3) {
            size_t n = length - pos < 4 ? length - pos : 4;
            uint32_t bits = 0;
            for (size_t i = 0; i < n; ++i)
                bits |= (uint32_t)wire[pos + i] << (8 * i);
            values[field - 1] = bits;
            pos += n;
            if (n != 4)
                break;
        } else if (!skip(wire, length, &pos, (uint32_t)value, 0))
            break;
    }
    /* Preserve NaN payload, signed zero and partial fixed32 bit patterns. */
    memcpy(&out->loss_percent, values, 4);
    memcpy(&out->mean_ms, values + 1, 4);
    memcpy(&out->deviation_ms, values + 2, 4);
}
bool sl_network_stats_load(const char *directory, sl_network_stats_average *output) {
    char path[512];
    if (!path_for(path, directory, "streaming_stats.bin"))
        return false;
    FILE *file = fopen(path, "rb");
    if (!file)
        return false;
    bool ok = false;
    uint8_t *wire = NULL;
    long length;
    if (!fseek(file, 0, SEEK_END) && (length = ftell(file)) >= 0 && length <= INT32_MAX &&
        !fseek(file, 0, SEEK_SET)) {
        wire = malloc((size_t)length + 1);
        if (wire && fread(wire, 1, (size_t)length, file) == (size_t)length && fgetc(file) == EOF &&
            !ferror(file))
            ok = true;
    }
    if (fclose(file))
        ok = false;
    if (ok) {
        sl_network_stats_average unused;
        parse_prefix(wire, (size_t)length, output ? output : &unused);
    }
    free(wire);
    return ok;
}
unsigned sl_network_stats_connect_action(unsigned requested, bool video, bool readable) {
    return requested == 0 && video && !readable ? 3 : requested;
}
static void little32(uint8_t *out, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i)
        out[i] = (uint8_t)(value >> (i * 8));
}
static int64_t signed32(uint32_t value) {
    return value > INT32_MAX ? (int64_t)value - INT64_C(4294967296) : value;
}
static float milliseconds(uint32_t ticks) {
    bool negative = (ticks & UINT32_C(0x80000000)) != 0;
    uint32_t magnitude = negative ? 0u - ticks : ticks;
    float fraction = (float)((magnitude & 65535u) * 1000u) / 65536.0f;
    float whole = (float)((magnitude >> 16) * 1000u);
    float ms = fraction + whole;
    return negative ? -ms : ms;
}
static char *sample_text(const IHS_NetworkTestSample *samples, size_t count) {
    /* A changed-target row is at most 12+13+2 bytes; keep checked spare space
     * for separators, CRC and terminator. Raw CRC input is endian explicit. */
    if (count > (SIZE_MAX - 32) / 32 || (count && !samples))
        return NULL;
    size_t capacity = count * 32 + 32;
    uint8_t *raw = malloc(count ? count * 8 : 1);
    char *text = malloc(capacity);
    if (!raw || !text) {
        free(raw);
        free(text);
        return NULL;
    }
    for (size_t i = 0; i < count; ++i) {
        little32(raw + i * 8, samples[i].targetKbps);
        little32(raw + i * 8 + 4, samples[i].networkTicks);
    }
    int n = snprintf(text, capacity, "%" PRIu32 "=", IHS_CRC32(raw, count * 8));
    free(raw);
    if (n < 0 || (size_t)n >= capacity) {
        free(text);
        return NULL;
    }
    size_t used = (size_t)n;
    uint32_t previous = 0;
    for (size_t i = 0; i < count; ++i) {
        uint32_t target = samples[i].targetKbps;
        if (!target)
            continue;
        if (target != previous) {
            n = snprintf(text + used, capacity - used, "%s%" PRId64 ":%.2f", previous ? ";" : "",
                         signed32(target), (double)milliseconds(samples[i].networkTicks));
        } else {
            n = snprintf(text + used, capacity - used, ",%.2f",
                         (double)milliseconds(samples[i].networkTicks));
        }
        if (n < 0 || (size_t)n >= capacity - used) {
            free(text);
            return NULL;
        }
        used += (size_t)n;
        previous = target;
    }
    if (previous)
        text[used++] = ';';
    text[used] = 0;
    return text;
}
static bool publish(const char *temporary, const char *path, const char *backup) {
    if (!rename(temporary, path))
        return true;
    if (errno != EEXIST && errno != ENOTEMPTY)
        return false;
    if (remove(backup) && errno != ENOENT)
        return false;
    if (rename(path, backup))
        return false;
    if (!rename(temporary, path)) {
        remove(backup);
        return true;
    }
    int saved = errno;
    rename(backup, path);
    errno = saved;
    return false;
}
bool sl_network_stats_save(const char *directory, const sl_network_stats_average *average,
                           const IHS_NetworkTestSample *samples, size_t count) {
    char path[512], temporary[512], backup[512];
    if (!average || !path_for(path, directory, "streaming_stats.bin") ||
        !path_for(temporary, directory, "streaming_stats.tmp") ||
        !path_for(backup, directory, "streaming_stats.bak") ||
        (mkdir(directory, 0700) && errno != EEXIST))
        return false;
    char *text = sample_text(samples, count);
    if (!text)
        return false;
    CStreamingSessionStats stats = CSTREAMING_SESSION_STATS__INIT;
    stats.has_frame_loss_percentage = stats.has_average_network_time_ms =
        stats.has_stddev_network_time_ms = true;
    memcpy(&stats.frame_loss_percentage, &average->loss_percent, 4);
    memcpy(&stats.average_network_time_ms, &average->mean_ms, 4);
    memcpy(&stats.stddev_network_time_ms, &average->deviation_ms, 4);
    stats.test_data = text;
    size_t length = cstreaming_session_stats__get_packed_size(&stats);
    uint8_t *wire = malloc(length);
    if (!wire) {
        free(text);
        return false;
    }
    cstreaming_session_stats__pack(&stats, wire);
    free(text);
    FILE *file = fopen(temporary, "wb");
    bool ok = false;
    if (file) {
        ok = fwrite(wire, 1, length, file) == length;
        if (fflush(file))
            ok = false;
        if (ok && fsync(fileno(file)) && errno != ENOSYS && errno != EINVAL)
            ok = false;
        if (fclose(file))
            ok = false;
        if (ok)
            ok = publish(temporary, path, backup);
        if (!ok)
            remove(temporary);
    }
    free(wire);
    return ok;
}
bool sl_network_stats_save_session(const char *directory, IHS_Session *session) {
    if (!session)
        return false;
    IHS_NetworkTestResult result;
    IHS_SessionMediaNetworkStats stats;
    IHS_SessionGetNetworkTestResult(session, &result);
    IHS_SessionGetMediaNetworkStats(session, &stats);
    if (result.status != IHS_NetworkTestComplete || !result.valid || !stats.valid ||
        !stats.finalized || result.samples > SIZE_MAX / sizeof(IHS_NetworkTestSample))
        return false;
    IHS_NetworkTestSample *samples = malloc(result.samples ? result.samples * sizeof(*samples) : 1);
    if (!samples)
        return false;
    size_t count = 0;
    while (count < result.samples) {
        size_t got = IHS_SessionReadNetworkTestSamples(session, count, samples + count,
                                                       result.samples - count);
        if (!got || got > result.samples - count)
            break;
        count += got;
    }
    sl_network_stats_average average = {stats.lossPercent, stats.meanNetworkMs, stats.deviationMs};
    bool ok = count == result.samples && sl_network_stats_save(directory, &average, samples, count);
    free(samples);
    return ok;
}
