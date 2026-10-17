#include "audio_jitter.h"
#include <assert.h>
#include <mbedtls/sha256.h>
#include <mbedtls/version.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t bits(float f) {
    uint32_t v;
    memcpy(&v, &f, 4);
    return v;
}
static void digest(const void *data, size_t size) {
    unsigned char out[32];
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    assert(!mbedtls_sha256(data, size, out, 0));
#else
    assert(!mbedtls_sha256_ret(data, size, out, 0));
#endif
    putchar('"');
    for (unsigned i = 0; i < sizeof(out); ++i)
        printf("%02x", out[i]);
    putchar('"');
}
static void signal(float *out, int count, int channels, int offset, const char *kind) {
    for (int n = 0; n < count; ++n)
        for (int ch = 0; ch < channels; ++ch) {
            float value;
            if (!strcmp(kind, "zero"))
                value = 0.0f;
            else if (!strcmp(kind, "constant"))
                value = (ch + 1) / 16.0f;
            else if (!strcmp(kind, "cancel"))
                value = (((offset + n) * 37 % 257) - 128) / 256.0f * (ch & 1 ? -1 : 1);
            else
                value = ((((offset + n) * 37 + ch * 71) % 257) - 128) / 256.0f;
            out[n * channels + ch] = value;
        }
}
int main(int argc, char **argv) {
    assert(argc == 3);
    sl_audio_jitter j;
    assert(sl_audio_jitter_init(&j, atoi(argv[1]), atoi(argv[2])));
    float *input = calloc(65536 * 8, sizeof(float));
    float *output = calloc(65536 * 8 + 8, sizeof(float));
    assert(input && output);
    printf("{\"params\":[");
    for (int i = 0; i < 10; ++i)
        printf("%s%d", i ? "," : "", j.params[i]);
    printf("],\"table_sha256\":");
    digest(j.table, sizeof(j.table));
    printf(",\"observed\":[");
    char op[16], kind[16];
    int count, offset;
    unsigned row = 0;
    while (scanf("%15s %d %15s %d", op, &count, kind, &offset) == 4) {
        assert(count >= 0 && count <= 65536);
        size_t size = (size_t)count * j.channels * sizeof(float);
        int result;
        if (!strcmp(op, "push")) {
            signal(input, count, j.channels, offset, kind);
            result = sl_audio_jitter_push(&j, input, count);
            size = 0;
        } else {
            assert(!strcmp(op, "pop") || !strcmp(op, "play"));
            memset(output, 0xa5, size + 32);
            result = sl_audio_jitter_pop(&j, output, count);
            size = (size_t)result * j.channels * sizeof(float);
            const unsigned char *tail = (const unsigned char *)output + size;
            for (size_t i = 0; i < (size_t)(count - result) * j.channels * 4 + 32; ++i)
                assert(tail[i] == 0xa5);
        }
        printf("%s{\"result\":%d,\"output_sha256\":", row++ ? "," : "", result);
        digest(output, size);
        printf(",\"state\":{");
#define I(name, value) printf("\"" name "\":%u,", (uint32_t)(value))
        I("channels", j.channels);
        I("capacity", SL_AUDIO_JITTER_CAPACITY);
        I("sentinel", SL_AUDIO_JITTER_CAPACITY);
        I("write", j.write);
        I("read", j.read);
        I("tracked_write", j.tracked_write);
        I("attempts", j.attempts);
        I("fade_bits", bits(j.fade));
        I("fade_step_bits", bits(j.fade_step));
        I("cross_bits", bits(j.cross));
        I("cross_step_bits", bits(j.cross_step));
        I("alternate_read", j.alternate_read);
        I("dropped", j.dropped);
        I("missing", j.missing);
        I("last_queued", j.last_queued);
        I("min", j.min);
        I("max", j.max);
        I("mean", j.mean);
        I("variance", j.variance);
        I("expands", j.expands);
        I("shrinks", j.shrinks);
        I("underflow_fades", j.underflow_fades);
        I("running_min", j.running_min);
        I("running_max", j.running_max);
        I("observations", j.observations);
        I("interval", j.interval);
        I("running_mean_bits", bits(j.running_mean));
        I("running_m2_bits", bits(j.running_m2));
        I("adjustment", j.adjustment);
        I("queued", sl_audio_jitter_queued(&j));
        printf("\"priming\":%s,\"overrun\":%s,\"ring_sha256\":", j.priming ? "true" : "false",
               j.overrun ? "true" : "false");
        digest(j.ring, (size_t)SL_AUDIO_JITTER_CAPACITY * j.channels * sizeof(float));
        printf("}}");
#undef I
    }
    puts("]}");
    free(input);
    free(output);
    sl_audio_jitter_destroy(&j);
    return 0;
}
