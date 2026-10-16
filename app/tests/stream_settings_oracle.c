/* Actual settings file and session-load path for fixed official byte vectors. */
#include "stream_settings.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    assert(argc == 4);
    IHS_Init();
    sl_auth_store profile = {.bitrate_kbps = 6000};
    sl_stream_settings settings;
    assert(sl_stream_settings_init(&settings, &profile));
    size_t n = strlen(argv[3]);
    if (!strcmp(argv[3], "-"))
        n = 0;
    assert(!(n & 1));
    uint8_t *initial = malloc(n / 2 + 1);
    assert(initial);
    for (size_t i = 0; i < n / 2; ++i) {
        unsigned byte;
        assert(sscanf(argv[3] + i * 2, "%2x", &byte) == 1);
        initial[i] = byte;
    }
    sl_stream_settings_receive(NULL, initial, n / 2, &settings);
    free(initial);
    assert(sl_stream_settings_drain(&settings));
    int status = !strcmp(argv[2], "load") ? sl_stream_settings_load(&settings, argv[1])
                                          : (sl_stream_settings_save(&settings, argv[1]) ? 0 : -1);
    const uint8_t secret[32] = {0};
    const IHS_ClientConfig client = {
        .deviceId = 1, .deviceName = "settings-test", .secretKey = secret};
    const IHS_SessionInfo info = {.sessionKeyLen = 32,
                                  .address = {.ip.v4 = {IHS_IPAddressFamilyIPv4, {127, 0, 0, 1}}}};
    IHS_Session *session = IHS_SessionCreate(&client, &info);
    assert(session);
    assert(sl_stream_settings_apply(&settings, session));
    size_t size = IHS_SessionGetStreamingClientConfig(session, NULL, 0);
    uint8_t *wire = malloc(size + 1);
    assert(wire);
    assert(IHS_SessionGetStreamingClientConfig(session, wire, size) == size);
    printf("{\"status\":%d,\"config\":\"", status);
    for (size_t i = 0; i < size; ++i)
        printf("%02x", wire[i]);
    puts("\"}");
    free(wire);
    IHS_SessionDestroy(session);
    sl_stream_settings_destroy(&settings);
    IHS_Quit();
    return 0;
}
