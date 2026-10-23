#include "platform/sensors.h"

/* Desktop SDL backends already deliver SDL_CONTROLLERSENSORUPDATE events for
 * supported controllers; the generic ihslib event path handles those. */
void sl_sensors_poll(IHS_Session *session, int joystick_id) {
    (void)session;
    (void)joystick_id;
}

void sl_sensors_stop(void) {
}
