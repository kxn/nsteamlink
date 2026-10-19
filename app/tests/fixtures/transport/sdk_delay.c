#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <time.h>
static int (*real_submit)(void *, const void *);
static uint32_t delay_us;
uint64_t nsl_probe_state[4]; /* main fixture observes only while all threads stop */
void nsl_probe_config(void *function, uint32_t delay) {
    real_submit = function;
    delay_us = delay;
}
int nsl_probe_submit(void *ctx, const void *packet) {
    nsl_probe_state[0] = 1;
    ++nsl_probe_state[1];
    struct timespec remaining = {delay_us / 1000000, (delay_us % 1000000) * 1000};
    if (delay_us) {
        while (nanosleep(&remaining, &remaining) && errno == EINTR) {
        }
        nsl_probe_state[3] += delay_us;
    }
    int result = real_submit(ctx, packet);
    ++nsl_probe_state[2];
    nsl_probe_state[0] = 0;
    return result;
}
