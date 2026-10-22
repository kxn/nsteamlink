/* On-screen six-axis visualizer for manual hardware checks.
 *
 * It uses the same libnx handles and sensor_math conversion as the product
 * path. The screen shows raw libnx values and the SDL-frame values that are
 * sent to Steam, with a guided REST/YAW/PITCH/ROLL sequence so axis and sign
 * can be checked without a game. No Steam session is opened. */
#include "platform/sensor_math.h"

#include <switch.h>

#include <arpa/inet.h>

#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CYCLE_MS 21000u
#define CYCLES   3
#define RUN_MS   (CYCLE_MS * CYCLES)
#define POLL_US  5000u
#define DRAW_MS  100u

typedef struct view_handle {
    const char *name;
    HidNpadStyleTag tag;
    int count;
    HidSixAxisSensorHandle handle[2];
    int started[2];
    unsigned long long samples;
    u64 last_sn;
    float av_min[3], av_max[3], acc_min[3], acc_max[3];
    bool range_valid;
} view_handle;

static int log_fd = -1;

static void log_line(const char *format, ...) {
    if (log_fd < 0) {
        return;
    }
    char line[256];
    va_list args;
    va_start(args, format);
    int n = vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    if (n > 0) {
        if ((size_t)n >= sizeof(line))
            n = sizeof(line) - 1;
        (void)write(log_fd, line, (size_t)n);
        (void)write(log_fd, "\n", 1);
    }
}

static uint64_t now_ms(void) {
    return armTicksToNs(armGetSystemTick()) / 1000000ull;
}

static const char *style_name(u64 style) {
    if (style & HidNpadStyleTag_NpadHandheld)
        return "handheld";
    if (style & HidNpadStyleTag_NpadFullKey)
        return "fullkey";
    if (style & HidNpadStyleTag_NpadJoyDual)
        return "joydual";
    if (style & HidNpadStyleTag_NpadJoyLeft)
        return "joyleft";
    if (style & HidNpadStyleTag_NpadJoyRight)
        return "joyright";
    return "none";
}

static void start_handle(view_handle *h, HidNpadIdType id) {
    Result rc = hidGetSixAxisSensorHandles(h->handle, h->count, id, h->tag);
    if (R_FAILED(rc)) {
        return;
    }
    for (int i = 0; i < h->count; ++i) {
        rc = hidStartSixAxisSensor(h->handle[i]);
        h->started[i] = R_SUCCEEDED(rc);
    }
}

static void stop_handles(view_handle *handles, size_t count) {
    for (size_t h = 0; h < count; ++h) {
        for (int i = 0; i < handles[h].count; ++i) {
            if (handles[h].started[i]) {
                hidStopSixAxisSensor(handles[h].handle[i]);
                handles[h].started[i] = 0;
            }
        }
    }
}

static bool read_handle(view_handle *h, int index, HidSixAxisSensorState *out) {
    if (index < 0 || index >= h->count || !h->started[index]) {
        return false;
    }
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
    if (states[best].sampling_number != 0 && states[best].sampling_number == h->last_sn) {
        return false;
    }
    if (h->last_sn != 0 && states[best].sampling_number > h->last_sn) {
        h->samples += states[best].sampling_number - h->last_sn;
    } else {
        h->samples++;
    }
    h->last_sn = states[best].sampling_number;
    *out = states[best];
    return true;
}

static void range_update(view_handle *h, const float av[3], const float acc[3]) {
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

static void range_reset(view_handle *h) {
    h->range_valid = false;
}

/* 25-column signed bar centered at |. */
static void bar(char *out, size_t size, float value, float limit) {
    enum { WIDTH = 25, CENTER = WIDTH / 2 };
    char cells[WIDTH + 1];
    memset(cells, '-', WIDTH);
    cells[WIDTH] = '\0';
    cells[CENTER] = '|';
    float v = value / limit;
    if (v > 1.0f)
        v = 1.0f;
    if (v < -1.0f)
        v = -1.0f;
    int cells_n = (int)(fabsf(v) * CENTER + 0.5f);
    if (v >= 0) {
        for (int i = 1; i <= cells_n && CENTER + i < WIDTH; ++i)
            cells[CENTER + i] = '#';
    } else {
        for (int i = 1; i <= cells_n && CENTER - i >= 0; ++i)
            cells[CENTER - i] = '#';
    }
    snprintf(out, size, "[%s]", cells);
}

static void draw_line(const char *format, ...) {
    char line[160];
    va_list args;
    va_start(args, format);
    int n = vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    if (n < 0)
        return;
    if ((size_t)n > 78)
        line[78] = '\0';
    printf("%-78s\n", line);
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    consoleInit(NULL);
    if (R_FAILED(socketInitializeDefault())) {
        consoleExit(NULL);
        return 1;
    }
    if (__nxlink_host.s_addr) {
        log_fd = nxlinkConnectToHost(false, false);
    }

    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    PadState pad;
    padInitializeDefault(&pad);

    view_handle handles[] = {
        {.name = "handheld", .tag = HidNpadStyleTag_NpadHandheld, .count = 1},
        {.name = "fullkey", .tag = HidNpadStyleTag_NpadFullKey, .count = 1},
        {.name = "joydual", .tag = HidNpadStyleTag_NpadJoyDual, .count = 2},
        {.name = "joyleft", .tag = HidNpadStyleTag_NpadJoyLeft, .count = 1},
        {.name = "joyright", .tag = HidNpadStyleTag_NpadJoyRight, .count = 1},
    };
    const size_t handle_count = sizeof(handles) / sizeof(handles[0]);
    HidNpadIdType ids[] = {HidNpadIdType_Handheld, HidNpadIdType_No1, HidNpadIdType_No1,
                           HidNpadIdType_No1, HidNpadIdType_No1};
    for (size_t i = 0; i < handle_count; ++i) {
        start_handle(&handles[i], ids[i]);
    }

    const uint64_t start = now_ms();
    uint64_t next_draw = 0;
    int phase = -1;
    int cycle = -1;
    view_handle *active = NULL;
    view_handle *last_active = NULL;
    bool have_latest = false;
    float last_av[3] = {0}, last_acc[3] = {0};
    static const char *phase_name[] = {"REST", "YAW", "PITCH", "ROLL", "SUMMARY"};
    static const uint64_t phase_end_ms[] = {3000, 8000, 13000, 18000, CYCLE_MS};
    static const char *phase_hint[] = {
        "Hold still / lay flat (do not rotate)",
        "YAW: rotate left/right around the vertical axis",
        "PITCH: tilt forward/back (nod)",
        "ROLL: tilt left/right (steering wheel)",
        "Look at the ranges below",
    };

    printf("\x1b[2J");
    while (now_ms() - start < RUN_MS) {
        padUpdate(&pad);
        u64 style = padGetStyleSet(&pad);
        uint64_t elapsed = now_ms() - start;
        int new_cycle = (int)(elapsed / CYCLE_MS);
        uint64_t in_cycle = elapsed % CYCLE_MS;
        int new_phase = 4;
        for (int i = 0; i < 5; ++i) {
            if (in_cycle < phase_end_ms[i]) {
                new_phase = i;
                break;
            }
        }

        if (style & HidNpadStyleTag_NpadHandheld)
            active = &handles[0];
        else if (style & HidNpadStyleTag_NpadFullKey)
            active = &handles[1];
        else if (style & HidNpadStyleTag_NpadJoyDual)
            active = &handles[2];
        else if (style & HidNpadStyleTag_NpadJoyLeft)
            active = &handles[3];
        else if (style & HidNpadStyleTag_NpadJoyRight)
            active = &handles[4];
        else
            active = NULL;

        if (new_phase != phase || new_cycle != cycle || active != last_active) {
            if (phase >= 0 && active && active->range_valid) {
                log_line("PHASE_SUMMARY cycle=%d phase=%s name=%s "
                         "av_min=%.6f,%.6f,%.6f av_max=%.6f,%.6f,%.6f "
                         "acc_min=%.6f,%.6f,%.6f acc_max=%.6f,%.6f,%.6f",
                         cycle + 1, phase_name[phase], active->name, (double)active->av_min[0],
                         (double)active->av_min[1], (double)active->av_min[2],
                         (double)active->av_max[0], (double)active->av_max[1],
                         (double)active->av_max[2], (double)active->acc_min[0],
                         (double)active->acc_min[1], (double)active->acc_min[2],
                         (double)active->acc_max[0], (double)active->acc_max[1],
                         (double)active->acc_max[2]);
            }
            phase = new_phase;
            cycle = new_cycle;
            last_active = active;
            if (active)
                range_reset(active);
        }

        if (active) {
            int index = 0;
            if (active->tag == HidNpadStyleTag_NpadJoyDual && active->started[1])
                index = 1;
            HidSixAxisSensorState st;
            if (read_handle(active, index, &st)) {
                have_latest = true;
                last_av[0] = st.angular_velocity.x;
                last_av[1] = st.angular_velocity.y;
                last_av[2] = st.angular_velocity.z;
                last_acc[0] = st.acceleration.x;
                last_acc[1] = st.acceleration.y;
                last_acc[2] = st.acceleration.z;
                range_update(active, last_av, last_acc);
            }
        }

        if (elapsed >= next_draw) {
            next_draw = elapsed + DRAW_MS;
            float gyro[3] = {0}, accel[3] = {0};
            if (have_latest) {
                sl_sensor_math_from_libnx(last_av, last_acc, gyro, accel);
            }
            float rate =
                active ? (float)active->samples * 1000.0f / (float)(elapsed ? elapsed : 1) : 0;
            uint64_t phase_end = (uint64_t)cycle * CYCLE_MS + phase_end_ms[phase];
            uint64_t left_ms = phase_end > elapsed ? phase_end - elapsed : 0;
            printf("\x1b[1;1H");
            draw_line("NSteamLink SixAxis Viewer");
            draw_line("style=%s type=%u active=%s samples=%llu approx_rate=%.1f Hz",
                      style_name(style), (unsigned)hidGetNpadDeviceType(HidNpadIdType_Handheld),
                      active ? active->name : "none", active ? active->samples : 0ULL,
                      (double)rate);
            draw_line("cycle %d/%d   phase %s   %llu ms left   (+ exits)", cycle + 1, CYCLES,
                      phase_name[phase], (unsigned long long)left_ms);
            draw_line("");
            draw_line(">>> %s <<<", phase_hint[phase]);
            draw_line("");
            draw_line("RAW libnx gyro (rev/s)                SDL gyro (rad/s)");
            for (int i = 0; i < 3; ++i) {
                char b1[32], b2[32];
                bar(b1, sizeof(b1), last_av[i], 0.8f);
                bar(b2, sizeof(b2), gyro[i], 5.0f);
                draw_line("%c %+.3f %s   %c %+.3f %s", "XYZ"[i], (double)last_av[i], b1, "XYZ"[i],
                          (double)gyro[i], b2);
            }
            draw_line("");
            draw_line("RAW libnx accel (g)                   SDL accel (m/s2)");
            for (int i = 0; i < 3; ++i) {
                char b1[32], b2[32];
                bar(b1, sizeof(b1), last_acc[i], 1.5f);
                bar(b2, sizeof(b2), accel[i], 15.0f);
                draw_line("%c %+.3f %s   %c %+.3f %s", "XYZ"[i], (double)last_acc[i], b1, "XYZ"[i],
                          (double)accel[i], b2);
            }
            draw_line("");
            if (phase == 4 && active && active->range_valid) {
                draw_line("PHASE SUMMARY (min .. max)");
                for (int i = 0; i < 3; ++i) {
                    draw_line("av.%c %+.3f .. %+.3f    acc.%c %+.3f .. %+.3f", "XYZ"[i],
                              (double)active -> av_min[i], (double)active -> av_max[i], "XYZ"[i],
                              (double)active -> acc_min[i], (double)active -> acc_max[i]);
                }
            } else {
                draw_line("Watch which RAW axis bar moves during each phase.");
                draw_line("YAW -> Z, PITCH -> X, ROLL -> Y (expected libnx frame).");
            }
            draw_line("");
            draw_line("REST: bars centered. YAW/PITCH/ROLL: move the console.");
            consoleUpdate(NULL);
        }

        if (padGetButtonsDown(&pad) & HidNpadButton_Plus) {
            break;
        }
        svcSleepThread(POLL_US * 1000ull);
    }

    stop_handles(handles, handle_count);
    if (active && active->range_valid) {
        log_line("FINAL name=%s av_min=%.6f,%.6f,%.6f av_max=%.6f,%.6f,%.6f", active->name,
                 (double)active->av_min[0], (double)active->av_min[1], (double)active->av_min[2],
                 (double)active->av_max[0], (double)active->av_max[1], (double)active->av_max[2]);
    }
    log_line("VIEW_END");
    if (log_fd >= 0) {
        close(log_fd);
        log_fd = -1;
    }
    hidExit();
    socketExit();
    consoleExit(NULL);
    return 0;
}
