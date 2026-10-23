#pragma once

#include <stdbool.h>

typedef struct IHS_Session IHS_Session;

/* Media/SDL thread only. Samples the platform IMU for the selected gamepad and
 * injects it into the session's HID state; the existing 8 ms HID flush sends
 * the resulting delta/full report. Caller must keep the session alive until
 * this call returns (the media owner holds its HID lifecycle lease). No-op on
 * platforms without a native sensor source. */
void sl_sensors_poll(IHS_Session *session, int joystick_id);

/* Media/SDL thread only. Idempotent; stops any started native sensor handles. */
void sl_sensors_stop(void);
