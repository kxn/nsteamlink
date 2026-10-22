#pragma once

/* Convert libnx's native six-axis units/frame into the frame and units that
 * SDL's controller-sensor API (and the Steam Link Generic Gamepad wire format)
 * expect.
 *
 * libnx/Nintendo: angular velocity in revolutions/second, acceleration in g.
 * The Switch HID service exposes one controller-frame orientation for Pro
 * Controller, Joy-Con and handheld, so the mapping is controller-type
 * independent. SDL exposes gyro in rad/s and acceleration in m/s².
 *
 * The Switch-frame -> SDL-frame mapping is the inverse of the one both yuzu
 * and Ryujinx use when they feed SDL motion into the emulated Switch shared
 * memory (yuzu sdl_driver.cpp: gyro=(x, -z, y), accel=(-x, z, -y)).
 */
void sl_sensor_math_from_libnx(const float angular_velocity_rev_s[3], const float acceleration_g[3],
                               float gyro_rad_s[3], float accel_m_s2[3]);
