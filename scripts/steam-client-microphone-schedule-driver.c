/* External caller only: original APIs and wall clock; no Source code patches. */
#include <stdint.h>
#include <unistd.h>
typedef void (*start_fn)(void *, int, int, int, void *);
typedef void (*send_fn)(void *, const void *, unsigned long);
typedef void (*stop_fn)(void *);
typedef void (*rate_fn)(void *, int, int);
typedef uint32_t (*clock_fn)(void);
static void record(uint32_t *trace, void *client, uint32_t *shaper, uintptr_t base) {
    trace[0] = ((clock_fn)(base + 0x1a4530))();
    trace[1] = shaper[3];
    trace[2] = shaper[1];
    trace[3] = *((uint8_t *)client + 627);
    trace[4] = *(uint16_t *)((char *)client + 0x1f6f4);
}
int nsl_mic_reorder(void *client, uintptr_t base, const void *data, uint32_t *trace) {
    void *connection = *(void **)((char *)client + 280);
    void *socket = *(void **)connection;
    uint32_t *shaper = *(uint32_t **)((char *)socket + 64);
    int oldrate = shaper[1];
    record(trace, client, shaper, base);
    ((rate_fn)(base + 0x19fd00))(shaper, 1, 16384);
    ((stop_fn)(base + 0x31bd50))(client);
    record(trace + 5, client, shaper, base);
    ((start_fn)(base + 0x31b480))(client, 3, 48000, 2, 0);
    record(trace + 10, client, shaper, base);
    ((send_fn)(base + 0x31ae90))(client, data, 4);
    record(trace + 15, client, shaper, base);
    ((start_fn)(base + 0x31b480))(client, 3, 48000, 2, 0);
    record(trace + 20, client, shaper, base);
    uint32_t until = shaper[3];
    unsigned attempts = 0;
    while ((int32_t)(((clock_fn)(base + 0x1a4530))() - until) < 0) {
        if (++attempts > 100000)
            return 1;
        usleep(20);
    }
    record(trace + 25, client, shaper, base);
    ((send_fn)(base + 0x31ae90))(client, data, 4);
    record(trace + 30, client, shaper, base);
    ((rate_fn)(base + 0x19fd00))(shaper, 1, oldrate);
    record(trace + 35, client, shaper, base);
    return 0;
}
