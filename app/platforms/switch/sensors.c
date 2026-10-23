#include "platform/sensors.h"
#include "platform/sensor_math.h"
#include "platform/system.h"

#include <ihslib/hid/sdl.h>
#include <switch.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The host only needs one IMU sample per wire report. SDL's Switch driver polls
 * pads from SDL_PollEvent; this module follows the same ownership rule and is
 * called from pump_sdl_events on the media thread. */
#define SENSOR_SAMPLE_INTERVAL_MS 4u
#define SENSOR_RETRY_MS           5000u

typedef struct sensor_runtime {
    bool started;
    bool failed;
    uint64_t retry_at;
    int joystick_id;
    HidNpadIdType npad_id;
    u64 style;
    u32 device_type;
    HidSixAxisSensorHandle handles[2];
    unsigned started_mask;
    int handle_count;
    int active_index;
    u64 last_sampling_number;
    uint64_t last_sample_ms;
    bool logged_first;
} sensor_runtime;

static sensor_runtime s;

static bool resolve_target(int joystick_id, HidNpadIdType *out_id, u64 *out_style,
                           HidNpadStyleTag *out_tag, int *out_count) {
    HidNpadIdType id = (HidNpadIdType)(HidNpadIdType_No1 + joystick_id);
    u64 style = hidGetNpadStyleSet(id);
    /* Slot 0 is also the handheld pseudo-pad. Prefer the explicit Handheld id so
     * the six-axis handle matches the same source as rumble.c. */
    if (joystick_id == 0 &&
        (hidGetNpadStyleSet(HidNpadIdType_Handheld) & HidNpadStyleTag_NpadHandheld)) {
        id = HidNpadIdType_Handheld;
        style = hidGetNpadStyleSet(id);
    }

    HidNpadStyleTag tag;
    int count;
    if (style & HidNpadStyleTag_NpadFullKey) {
        tag = HidNpadStyleTag_NpadFullKey;
        count = 1;
    } else if (style & HidNpadStyleTag_NpadHandheld) {
        tag = HidNpadStyleTag_NpadHandheld;
        count = 1;
    } else if (style & HidNpadStyleTag_NpadJoyDual) {
        tag = HidNpadStyleTag_NpadJoyDual;
        count = 2; /* left/right Joy-Con have separate IMUs */
    } else if (style & HidNpadStyleTag_NpadJoyLeft) {
        tag = HidNpadStyleTag_NpadJoyLeft;
        count = 1;
    } else if (style & HidNpadStyleTag_NpadJoyRight) {
        tag = HidNpadStyleTag_NpadJoyRight;
        count = 1;
    } else {
        return false;
    }

    *out_id = id;
    *out_style = style;
    *out_tag = tag;
    *out_count = count;
    return true;
}

static void log_line(const char *prefix, Result rc) {
    char line[128];
    snprintf(line, sizeof(line), "sensors: %s rc=%08x", prefix, (unsigned)rc);
    sl_system_log(line);
}

static void stop_started(void) {
    for (int i = 0; i < s.handle_count; ++i) {
        if (s.started_mask & (1u << i)) {
            hidStopSixAxisSensor(s.handles[i]);
        }
    }
    if (s.started) {
        sl_system_log("sensors: stopped");
    }
    memset(&s, 0, sizeof(s));
    s.active_index = -1;
}

static bool start_target(int joystick_id, HidNpadIdType id, u64 style, HidNpadStyleTag tag,
                         int count) {
    Result rc = hidGetSixAxisSensorHandles(s.handles, count, id, tag);
    if (R_FAILED(rc)) {
        log_line("hidGetSixAxisSensorHandles", rc);
        return false;
    }
    s.joystick_id = joystick_id;
    s.npad_id = id;
    s.style = style;
    s.device_type = hidGetNpadDeviceType(id);
    s.handle_count = count;
    s.started_mask = 0;
    for (int i = 0; i < count; ++i) {
        rc = hidStartSixAxisSensor(s.handles[i]);
        if (R_FAILED(rc)) {
            log_line("hidStartSixAxisSensor", rc);
            continue;
        }
        s.started_mask |= 1u << i;
    }
    if (s.started_mask == 0) {
        return false;
    }
    s.started = true;
    s.active_index = -1;
    s.last_sampling_number = 0;
    s.last_sample_ms = 0;
    char line[128];
    snprintf(line, sizeof(line), "sensors: started style=%llx type=%u handles=%u",
             (unsigned long long)style, (unsigned)s.device_type, s.started_mask);
    sl_system_log(line);
    return true;
}

/* 1 = new sample, 0 = same sample as last time, -1 = handle has no data. */
static int read_handle(int index, HidSixAxisSensorState *out) {
    if (index < 0 || index >= s.handle_count || (s.started_mask & (1u << index)) == 0) {
        return -1;
    }
    HidSixAxisSensorState states[17];
    size_t count =
        hidGetSixAxisSensorStates(s.handles[index], states, sizeof(states) / sizeof(states[0]));
    if (count == 0) {
        return -1;
    }
    size_t best = 0;
    for (size_t i = 1; i < count; ++i) {
        if (states[i].sampling_number > states[best].sampling_number) {
            best = i;
        }
    }
    if (states[best].sampling_number != 0 &&
        states[best].sampling_number == s.last_sampling_number && index == s.active_index) {
        return 0;
    }
    s.last_sampling_number = states[best].sampling_number;
    s.active_index = index;
    *out = states[best];
    return 1;
}

static void log_first_sample(const HidSixAxisSensorState *st) {
    if (s.logged_first) {
        return;
    }
    s.logged_first = true;
    char line[192];
    snprintf(line, sizeof(line), "sensors: sample av=(%.3f %.3f %.3f) rev/s acc=(%.3f %.3f %.3f) g",
             (double)st->angular_velocity.x, (double)st->angular_velocity.y,
             (double)st->angular_velocity.z, (double)st->acceleration.x, (double)st->acceleration.y,
             (double)st->acceleration.z);
    sl_system_log(line);
}

void sl_sensors_stop(void) {
    stop_started();
}

void sl_sensors_poll(IHS_Session *session, int joystick_id) {
    if (session == NULL || joystick_id < 0 || joystick_id > 7) {
        stop_started();
        return;
    }

    HidNpadIdType id;
    u64 style;
    HidNpadStyleTag tag;
    int count;
    if (!resolve_target(joystick_id, &id, &style, &tag, &count)) {
        stop_started();
        return;
    }

    if (s.started && (s.joystick_id != joystick_id || s.npad_id != id || s.style != style)) {
        stop_started();
    }

    uint64_t now = sl_system_now();
    if (!s.started) {
        if (s.failed && now < s.retry_at) {
            return;
        }
        if (!start_target(joystick_id, id, style, tag, count)) {
            stop_started();
            s.failed = true;
            s.retry_at = now + SENSOR_RETRY_MS;
            return;
        }
        s.failed = false;
    }

    if (s.last_sample_ms != 0 && now - s.last_sample_ms < SENSOR_SAMPLE_INTERVAL_MS) {
        return;
    }
    s.last_sample_ms = now;

    HidSixAxisSensorState st;
    int read;
    if (s.style & HidNpadStyleTag_NpadJoyDual) {
        /* Both Joy-Con have their own IMU; use the right one when present, the
         * same source SDL exposes for a combined Joy-Con pair. A duplicate on
         * the active handle is not a reason to switch to the other one. */
        read = read_handle(1, &st);
        if (read < 0) {
            read = read_handle(0, &st);
        }
    } else {
        read = read_handle(0, &st);
    }
    if (read <= 0) {
        return;
    }

    log_first_sample(&st);

    const float av[3] = {st.angular_velocity.x, st.angular_velocity.y, st.angular_velocity.z};
    const float acc[3] = {st.acceleration.x, st.acceleration.y, st.acceleration.z};
    float gyro[3], accel[3];
    sl_sensor_math_from_libnx(av, acc, gyro, accel);
    IHS_HIDSDLInjectSensor(session, (SDL_JoystickID)joystick_id, gyro, accel);
}
