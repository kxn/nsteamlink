/* Diagnostics-only Switch six-axis probe. No Steam session. It exercises the
 * same libnx handles and sensor_math conversion as app/platforms/switch/sensors.c
 * and prints machine-readable records over nxlink. Physical axis/sign remains a
 * property of the device; this probe records what the SDK actually returns. */
#include "platform/sensor_math.h"

#include <switch.h>

#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define RUN_MS        20000u
#define POLL_US       5000u
#define LOG_PERIOD_MS 100u

typedef struct probe_handle {
    const char *name;
    HidNpadStyleTag tag;
    int count;
    HidSixAxisSensorHandle handle[2];
    int started[2];
    unsigned long long samples;
    unsigned long long last_sn;
    float av_min[3], av_max[3], acc_min[3], acc_max[3];
    bool range_valid;
    bool no_data_logged;
} probe_handle;

static int log_fd = -1;

static void log_line(const char *format, ...) {
    char line[512];
    va_list args;
    va_start(args, format);
    int n = vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    if (n < 0) {
        return;
    }
    if ((size_t)n >= sizeof(line)) {
        n = sizeof(line) - 1;
    }
    if (log_fd >= 0) {
        ssize_t written = write(log_fd, line, (size_t)n);
        if (written == n) {
            static const char newline = '\n';
            (void)write(log_fd, &newline, 1);
        }
    }
}

static uint64_t now_ms(void) {
    return armTicksToNs(armGetSystemTick()) / 1000000ull;
}

static const char *style_name(u64 style) {
    switch (style) {
    case HidNpadStyleTag_NpadHandheld:
        return "handheld";
    case HidNpadStyleTag_NpadFullKey:
        return "fullkey";
    case HidNpadStyleTag_NpadJoyDual:
        return "joydual";
    case HidNpadStyleTag_NpadJoyLeft:
        return "joyleft";
    case HidNpadStyleTag_NpadJoyRight:
        return "joyright";
    default:
        return "unknown";
    }
}

static void start_handle(probe_handle *h, HidNpadIdType id) {
    Result rc = hidGetSixAxisSensorHandles(h->handle, h->count, id, h->tag);
    log_line("HANDLE name=%s style=%s id=%d count=%d get_rc=0x%08x", h->name, style_name(h->tag),
             (int)id, h->count, (unsigned)rc);
    if (R_FAILED(rc)) {
        return;
    }
    for (int i = 0; i < h->count; ++i) {
        rc = hidStartSixAxisSensor(h->handle[i]);
        h->started[i] = R_SUCCEEDED(rc);
        log_line("START name=%s index=%d rc=0x%08x ok=%d", h->name, i, (unsigned)rc, h->started[i]);
    }
}

static void stop_handles(probe_handle *handles, size_t count) {
    for (size_t h = 0; h < count; ++h) {
        for (int i = 0; i < handles[h].count; ++i) {
            if (handles[h].started[i]) {
                Result rc = hidStopSixAxisSensor(handles[h].handle[i]);
                log_line("STOP name=%s index=%d rc=0x%08x", handles[h].name, i, (unsigned)rc);
                handles[h].started[i] = 0;
            }
        }
    }
}

static bool read_latest(probe_handle *h, int index, HidSixAxisSensorState *out, u64 *out_sn) {
    HidSixAxisSensorState states[17];
    size_t n =
        hidGetSixAxisSensorStates(h->handle[index], states, sizeof(states) / sizeof(states[0]));
    if (n == 0) {
        return false;
    }
    size_t best = 0;
    for (size_t i = 1; i < n; ++i) {
        if (states[i].sampling_number > states[best].sampling_number) {
            best = i;
        }
    }
    *out = states[best];
    *out_sn = states[best].sampling_number;
    return true;
}

static void update_range(probe_handle *h, const float av[3], const float acc[3]) {
    if (!h->range_valid) {
        memcpy(h->av_min, av, sizeof(h->av_min));
        memcpy(h->av_max, av, sizeof(h->av_max));
        memcpy(h->acc_min, acc, sizeof(h->acc_min));
        memcpy(h->acc_max, acc, sizeof(h->acc_max));
        h->range_valid = true;
        return;
    }
    for (int i = 0; i < 3; ++i) {
        if (av[i] < h->av_min[i])
            h->av_min[i] = av[i];
        if (av[i] > h->av_max[i])
            h->av_max[i] = av[i];
        if (acc[i] < h->acc_min[i])
            h->acc_min[i] = acc[i];
        if (acc[i] > h->acc_max[i])
            h->acc_max[i] = acc[i];
    }
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    consoleInit(NULL);
    if (R_FAILED(socketInitializeDefault())) {
        consoleExit(NULL);
        return 1;
    }
    log_fd = nxlinkConnectToHost(false, false);
    if (log_fd < 0) {
        consoleExit(NULL);
        socketExit();
        return 1;
    }

    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    PadState pad;
    padInitializeDefault(&pad);

    probe_handle handles[] = {
        {.name = "handheld", .tag = HidNpadStyleTag_NpadHandheld, .count = 1},
        {.name = "fullkey", .tag = HidNpadStyleTag_NpadFullKey, .count = 1},
        {.name = "joydual", .tag = HidNpadStyleTag_NpadJoyDual, .count = 2},
        {.name = "joyleft", .tag = HidNpadStyleTag_NpadJoyLeft, .count = 1},
        {.name = "joyright", .tag = HidNpadStyleTag_NpadJoyRight, .count = 1},
    };
    const size_t handle_count = sizeof(handles) / sizeof(handles[0]);

    log_line("SIXAXIS_PROBE begin run_ms=%u poll_us=%u", RUN_MS, POLL_US);
    log_line("NPAD handheld_style=0x%x no1_style=0x%x handheld_type=%u no1_type=%u",
             (unsigned)hidGetNpadStyleSet(HidNpadIdType_Handheld),
             (unsigned)hidGetNpadStyleSet(HidNpadIdType_No1),
             (unsigned)hidGetNpadDeviceType(HidNpadIdType_Handheld),
             (unsigned)hidGetNpadDeviceType(HidNpadIdType_No1));

    /* All styles are requested so a connected Pro Controller / Joy-Con pair is
     * usable without changing the build. Only the active style has samples. */
    HidNpadIdType ids[] = {HidNpadIdType_Handheld, HidNpadIdType_No1, HidNpadIdType_No1,
                           HidNpadIdType_No1, HidNpadIdType_No1};
    for (size_t i = 0; i < handle_count; ++i) {
        start_handle(&handles[i], ids[i]);
    }

    uint64_t start = now_ms();
    uint64_t next_log = 0;
    /* Do not gate the fixed-length capture on appletMainLoop(): a netloader
     * launch can report a non-focused applet while HID shared memory is still
     * readable. The probe stops itself after RUN_MS and always cleans up. */
    log_line("LOOP_ENTER applet_main_loop=%d t=0", appletMainLoop() ? 1 : 0);
    while (now_ms() - start < RUN_MS) {
        padUpdate(&pad);
        u64 style = padGetStyleSet(&pad);
        u64 attr = padGetAttributes(&pad);
        uint64_t t = now_ms() - start;
        if (t >= next_log) {
            next_log = t + LOG_PERIOD_MS;
            log_line("STATE t=%llu style=0x%llx attr=0x%llx dtype_h=%u dtype_1=%u",
                     (unsigned long long)t, (unsigned long long)style, (unsigned long long)attr,
                     (unsigned)hidGetNpadDeviceType(HidNpadIdType_Handheld),
                     (unsigned)hidGetNpadDeviceType(HidNpadIdType_No1));
            for (size_t h = 0; h < handle_count; ++h) {
                for (int i = 0; i < handles[h].count; ++i) {
                    if (!handles[h].started[i]) {
                        continue;
                    }
                    HidSixAxisSensorState st;
                    u64 sn = 0;
                    if (!read_latest(&handles[h], i, &st, &sn)) {
                        if (!handles[h].no_data_logged && t > 1000) {
                            handles[h].no_data_logged = true;
                            log_line("NODATA t=%llu name=%s index=%d", (unsigned long long)t,
                                     handles[h].name, i);
                        }
                        continue;
                    }
                    if (sn != handles[h].last_sn) {
                        /* sampling_number is monotonic within a session; count
                         * the actual samples between 100ms log rows. */
                        if (handles[h].last_sn != 0 && sn > handles[h].last_sn) {
                            handles[h].samples += sn - handles[h].last_sn;
                        } else {
                            handles[h].samples++;
                        }
                        handles[h].last_sn = sn;
                    }
                    const float av[3] = {st.angular_velocity.x, st.angular_velocity.y,
                                         st.angular_velocity.z};
                    const float acc[3] = {st.acceleration.x, st.acceleration.y, st.acceleration.z};
                    float gyro[3], accel[3];
                    sl_sensor_math_from_libnx(av, acc, gyro, accel);
                    update_range(&handles[h], av, acc);
                    log_line("SAMPLE t=%llu name=%s index=%d sn=%llu dt=%llu "
                             "av=%.6f,%.6f,%.6f acc=%.6f,%.6f,%.6f "
                             "sdl_gyro=%.6f,%.6f,%.6f sdl_accel=%.6f,%.6f,%.6f",
                             (unsigned long long)t, handles[h].name, i, (unsigned long long)sn,
                             (unsigned long long)st.delta_time, (double)av[0], (double)av[1],
                             (double)av[2], (double)acc[0], (double)acc[1], (double)acc[2],
                             (double)gyro[0], (double)gyro[1], (double)gyro[2], (double)accel[0],
                             (double)accel[1], (double)accel[2]);
                }
            }
        }
        svcSleepThread(POLL_US * 1000ull);
    }
    log_line("LOOP_EXIT t=%llu", (unsigned long long)(now_ms() - start));

    for (size_t h = 0; h < handle_count; ++h) {
        if (!handles[h].range_valid) {
            log_line("SUMMARY name=%s samples=%llu range=absent", handles[h].name,
                     handles[h].samples);
            continue;
        }
        log_line("SUMMARY name=%s samples=%llu rate_hz=%.1f "
                 "av_min=%.6f,%.6f,%.6f av_max=%.6f,%.6f,%.6f "
                 "acc_min=%.6f,%.6f,%.6f acc_max=%.6f,%.6f,%.6f",
                 handles[h].name, handles[h].samples,
                 (double)handles[h].samples * 1000.0 / (double)RUN_MS, (double)handles[h].av_min[0],
                 (double)handles[h].av_min[1], (double)handles[h].av_min[2],
                 (double)handles[h].av_max[0], (double)handles[h].av_max[1],
                 (double)handles[h].av_max[2], (double)handles[h].acc_min[0],
                 (double)handles[h].acc_min[1], (double)handles[h].acc_min[2],
                 (double)handles[h].acc_max[0], (double)handles[h].acc_max[1],
                 (double)handles[h].acc_max[2]);
    }
    log_line("SIXAXIS_PROBE end");

    stop_handles(handles, handle_count);
    hidExit();
    if (log_fd >= 0) {
        close(log_fd);
        log_fd = -1;
    }
    socketExit();
    consoleExit(NULL);
    return 0;
}
