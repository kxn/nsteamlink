#include "platform/sensor_math.h"

#include <assert.h>
#include <math.h>

static void near(float actual, float expected) {
    assert(fabsf(actual - expected) < 1e-4f);
}

int main(void) {
    const float rev_to_rad = 6.28318530717958647692f;
    const float gravity = 9.80665f;
    const float av[3] = {1.0f, 2.0f, 3.0f};  /* revolutions/second */
    const float acc[3] = {0.1f, 0.2f, 0.3f}; /* g */
    float gyro[3], accel[3];

    /* Inverse of yuzu/Ryujinx's SDL -> Switch shared-memory mapping:
     *   sdl_gyro  = ( av.x,  av.z, -av.y) * 2π
     *   sdl_accel = (-acc.x, -acc.z, acc.y) * g */
    sl_sensor_math_from_libnx(av, acc, gyro, accel);
    near(gyro[0], 1.0f * rev_to_rad);
    near(gyro[1], 3.0f * rev_to_rad);
    near(gyro[2], -2.0f * rev_to_rad);
    near(accel[0], -0.1f * gravity);
    near(accel[1], -0.3f * gravity);
    near(accel[2], 0.2f * gravity);

    return 0;
}
