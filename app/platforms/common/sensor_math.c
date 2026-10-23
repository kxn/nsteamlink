#include "platform/sensor_math.h"

/* Switch's HID service reports angular velocity in revolutions/second
 * (Nintendo_Switch_Reverse_Engineering/imu_sensor_notes.md: "Internally Switch
 * uses revolutions per second instead of degrees"). SDL's sensor API uses
 * rad/s, so 1 rev/s = 2π rad/s. */
#define NSL_REV_PER_SEC_TO_RAD_PER_SEC 6.28318530717958647692f
/* libnx acceleration is in g; SDL exposes m/s². */
#define NSL_STANDARD_GRAVITY 9.80665f

void sl_sensor_math_from_libnx(const float angular_velocity_rev_s[3], const float acceleration_g[3],
                               float gyro_rad_s[3], float accel_m_s2[3]) {
    /* Inverse of the SDL -> Switch mapping used by yuzu's SDL driver
     * (src/input_common/drivers/sdl_driver.cpp):
     *   switch_gyro =  ( sdl_x, -sdl_z,  sdl_y) / 2π
     *   switch_accel = (-sdl_x,  sdl_z, -sdl_y) / g
     * Ryujinx uses the same axis permutation in NpadController::Update.
     * Inverting gives the SDL-standard values below. */
    gyro_rad_s[0] = angular_velocity_rev_s[0] * NSL_REV_PER_SEC_TO_RAD_PER_SEC;
    gyro_rad_s[1] = angular_velocity_rev_s[2] * NSL_REV_PER_SEC_TO_RAD_PER_SEC;
    gyro_rad_s[2] = -angular_velocity_rev_s[1] * NSL_REV_PER_SEC_TO_RAD_PER_SEC;

    accel_m_s2[0] = -acceleration_g[0] * NSL_STANDARD_GRAVITY;
    accel_m_s2[1] = -acceleration_g[2] * NSL_STANDARD_GRAVITY;
    accel_m_s2[2] = acceleration_g[1] * NSL_STANDARD_GRAVITY;
}
