/* Real config/profile files, actual protobuf and save/load helpers. No Steam
 * or device claim. A temporary diagnostic preference must not discard other
 * config changes or newly persisted identity/host keys. */
#include "live_media_fec_settings.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void put(const char *path, const uint8_t *bytes, size_t size) {
    FILE *f = fopen(path, "wb");
    assert(f && fwrite(bytes, 1, size, f) == size && !fclose(f));
}
static void check_wire(const char *path, const CStreamingClientConfig *config) {
    size_t size = cstreaming_client_config__get_packed_size(config);
    uint8_t *want = malloc(size + 1), *got = malloc(size + 1);
    assert(want && got);
    cstreaming_client_config__pack(config, want);
    FILE *f = fopen(path, "rb");
    assert(f && fread(got, 1, size + 1, f) == size && !memcmp(want, got, size) && !fclose(f));
    free(want);
    free(got);
}
static void missing_or_bad_file(void) {
    for (int mode = -1; mode <= 1; ++mode)
        for (unsigned legacy = 0; legacy < 2; ++legacy) {
            char dir[] = "/tmp/nsl-live-fec-missing-XXXXXX", file[512];
            assert(mkdtemp(dir));
            snprintf(file, sizeof(file), "%s/streaming_settings.bin", dir);
            sl_auth_store store = {.unreliable_fec = legacy};
            probe_fec_mode = mode;
            probe_fec_original_set = false;
            probe_fec_loads = probe_fec_saves = probe_fec_profiles = probe_fec_io_errors = 0;
            assert(probe_fec_preview(&store, dir));
            assert(probe_fec_original_set && probe_fec_original_has == !!legacy &&
                   probe_fec_original_value == !!legacy);
            assert(store.unreliable_fec == (mode < 0 ? !!legacy : mode != 0));
            assert(access(file, F_OK) != 0); /* preview itself never writes */
            sl_stream_settings settings;
            assert(sl_stream_settings_init(&settings, &store));
            assert(sl_stream_settings_load(&settings, dir) == 1 && settings.dirty);
            assert(sl_stream_settings_save(&settings, dir));
            CStreamingClientConfig original = *settings.config;
            original.has_enable_unreliable_fec = legacy;
            original.enable_unreliable_fec = legacy;
            check_wire(file, &original);
            sl_stream_settings_destroy(&settings);
            /* Invalid protobuf: explicit mode must stop without replacing it;
             * saved mode follows product preview's retained legacy fallback. */
            const uint8_t bad[] = {0xff};
            put(file, bad, sizeof(bad));
            store.unreliable_fec = legacy;
            probe_fec_original_set = false;
            probe_fec_loads = probe_fec_saves = probe_fec_profiles = probe_fec_io_errors = 0;
            assert(probe_fec_preview(&store, dir) == (mode < 0));
            assert(!probe_fec_original_set && store.unreliable_fec == !!legacy);
            assert(probe_fec_io_errors == (unsigned)(mode >= 0));
            FILE *f = fopen(file, "rb");
            assert(f && fgetc(f) == 0xff && fgetc(f) == EOF && !fclose(f));
            assert(!unlink(file) && !rmdir(dir));
        }
}
int main(void) {
    missing_or_bad_file();
    for (int mode = -1; mode <= 1; ++mode)
        for (unsigned original = 0; original < 3; ++original) {
            char dir[] = "/tmp/nsl-live-fec-XXXXXX", file[512], profile[512], bad[512];
            assert(mkdtemp(dir));
            snprintf(file, sizeof(file), "%s/streaming_settings.bin", dir);
            snprintf(profile, sizeof(profile), "%s/profile.bin", dir);
            snprintf(bad, sizeof(bad), "%s/not-a-directory", dir);
            /* field25 absent/false/true plus an unknown field, all retained. */
            uint8_t wire[] = {0xc8, 0x01, original == 2, 0x98, 0x06, 0x7b};
            put(file, wire + (original ? 0 : 3), original ? sizeof(wire) : 3);
            sl_auth_store store = {.device_id = 123, .sound = true};
            strcpy(store.device_name, "diagnostic-file-fixture");
            memset(store.secret, 0x5a, sizeof(store.secret));
            probe_fec_mode = mode;
            probe_fec_original_set = false;
            probe_fec_loads = probe_fec_saves = probe_fec_profiles = probe_fec_io_errors = 0;
            assert(probe_fec_preview(&store, dir));
            assert(store.unreliable_fec == (mode < 0 ? original == 2 : mode != 0));
            sl_stream_settings settings;
            assert(sl_stream_settings_init(&settings, &store));
            assert(sl_stream_settings_load(&settings, dir) == 0);
            assert(settings.config->enable_unreliable_fec == store.unreliable_fec);
            settings.config->has_desired_bitrate_kbps = true;
            settings.config->desired_bitrate_kbps = 33333; /* normal later update */
            settings.dirty = true;
            assert(sl_stream_settings_save(&settings, dir));
            assert(settings.config->enable_unreliable_fec == store.unreliable_fec);
            CStreamingClientConfig expected = *settings.config;
            if (mode >= 0) {
                expected.has_enable_unreliable_fec = original != 0;
                expected.enable_unreliable_fec = original == 2;
            }
            check_wire(file, &expected);
            /* Simulate current authorization updates, never restore an old
             * profile snapshot merely to put a preference back. */
            store.secret[0] ^= 0x37;
            store.registry.count = 1;
            store.registry.hosts[0].id = 12;
            store.registry.hosts[0].paired = true;
            store.registry.hosts[0].has_secret = true;
            memset(store.registry.hosts[0].secret, 0xa5, 32);
            assert(sl_auth_save(&store, dir));
            sl_auth_store reloaded;
            assert(sl_auth_load(&reloaded, dir) == 0);
            assert(reloaded.device_id == store.device_id &&
                   !memcmp(reloaded.secret, store.secret, 32) &&
                   !memcmp(reloaded.registry.hosts[0].secret, store.registry.hosts[0].secret, 32));
            assert(reloaded.unreliable_fec == (original == 2));
            assert(store.unreliable_fec == (mode < 0 ? original == 2 : mode != 0));
            put(bad, wire, sizeof(wire));
            assert(!sl_stream_settings_save(&settings, bad));
            assert(settings.config->enable_unreliable_fec == store.unreliable_fec);
            assert(!sl_auth_save(&store, bad));
            if (mode >= 0)
                assert(probe_fec_loads == 2 && probe_fec_saves == 2 && probe_fec_profiles == 2 &&
                       probe_fec_io_errors == 2);
            else
                assert(!probe_fec_loads && !probe_fec_saves && !probe_fec_profiles &&
                       !probe_fec_io_errors);
            sl_stream_settings_destroy(&settings);
            assert(!unlink(file) && !unlink(profile) && !unlink(bad) && !rmdir(dir));
        }
    return 0;
}
