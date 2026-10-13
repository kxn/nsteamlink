#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Self-update from the project's GitHub releases (D-060). Only the release
 * NRO listed in the release's SHA256SUMS is ever installed. */
#define SL_UPDATE_REPOSITORY  "kxn/nsteamlink"
#define SL_UPDATE_API         "https://api.github.com/repos/" SL_UPDATE_REPOSITORY "/releases/latest"
#define SL_UPDATE_DOWNLOADS   "https://github.com/" SL_UPDATE_REPOSITORY "/releases/download/"
#define SL_UPDATE_MAX_TARGETS 2

typedef struct sl_update_release {
    char version[16]; /* X.Y.Z, without the tag's leading v */
    char nro_name[128], nro_url[512], sums_url[512];
    uint64_t nro_size;
} sl_update_release;

/* Pure helpers, shared with the tests. */
bool sl_update_parse_release(const unsigned char *json, size_t size, sl_update_release *out);
/* Strict X.Y.Z comparison; false when either side isn't X.Y.Z. */
bool sl_update_newer(const char *candidate, const char *current);
bool sl_update_find_digest(const unsigned char *sums, size_t size, const char *name,
                           uint8_t digest[32]);

typedef enum sl_update_state {
    SL_UPDATE_CHECKING,
    SL_UPDATE_CURRENT, /* up to date, or the check failed: nothing to offer */
    SL_UPDATE_AVAILABLE,
    SL_UPDATE_INSTALLING,
    SL_UPDATE_INSTALLED,
    SL_UPDATE_FAILED,
} sl_update_state;
typedef enum sl_update_error {
    SL_UPDATE_OK,
    SL_UPDATE_ERROR_DOWNLOAD,
    SL_UPDATE_ERROR_VERIFY,
    SL_UPDATE_ERROR_WRITE,
} sl_update_error;
typedef struct sl_update_status {
    sl_update_state state;
    sl_update_error error;
    char version[16];
} sl_update_status;

/* Test seams: production passes NULL and uses verified HTTPS. fetch returns
 * malloc-owned data; download writes the body to an open file and reports
 * whether it completed within the limit. */
typedef bool (*sl_update_fetch_fn)(const char *url, size_t limit, unsigned char **data,
                                   size_t *size, void *context);
typedef bool (*sl_update_download_fn)(const char *url, uint64_t limit, int fd, void *context);

typedef struct sl_updater sl_updater;
/* Starts the check on a joinable worker. targets are the NRO files to
 * replace (the launched one and the HOME shortcut's); at least one. */
sl_updater *sl_updater_create(const char *current_version, const char *const *targets,
                              int target_count, sl_update_fetch_fn fetch,
                              sl_update_download_fn download, void *context);
/* Copies the status when it changed since the last call. */
bool sl_updater_poll(sl_updater *, sl_update_status *out);
/* Starts the install of an available update. */
bool sl_updater_install(sl_updater *);
void sl_updater_request_stop(sl_updater *);
bool sl_updater_finished(sl_updater *);
void sl_updater_destroy(sl_updater *);
