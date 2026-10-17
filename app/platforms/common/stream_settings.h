#pragma once
#include "services/auth_store.h"
#include "services/stream_preferences.h"
#include <ihslib/session.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

struct CStreamingClientConfig;
typedef struct sl_stream_settings {
    /* Configuration/file access belongs to the runtime worker. Producers only
     * publish a borrowed-wire copy or a UI edit into this bounded mailbox. */
    struct CStreamingClientConfig *config;
    bool dirty;
    pthread_mutex_t lock;
    uint8_t *pending;
    size_t pending_size;
    uint64_t sequence, config_order, edit_order[3], applied_revision, ui_revision;
    atomic_uint_fast64_t published_revision;
    unsigned edit_mask;
    sl_stream_preferences previous_ui, edit;
} sl_stream_settings;

bool sl_stream_settings_init(sl_stream_settings *, const sl_auth_store *legacy);
void sl_stream_settings_destroy(sl_stream_settings *); /* Producers must have stopped. */
/* 0 loaded; 1 missing; -1 I/O; -2 invalid proto. Failure retains the current value. */
int sl_stream_settings_load(sl_stream_settings *, const char *directory);
bool sl_stream_settings_save(sl_stream_settings *, const char *directory);
void sl_stream_settings_project(const sl_stream_settings *, sl_auth_store *view);
/* Initial application load, before the UI exists. Does not write a file. */
void sl_stream_settings_preview(sl_auth_store *view, const char *directory);
/* Session saveClientConfig callback: no file I/O or session access. */
void sl_stream_settings_receive(IHS_Session *, const uint8_t *, size_t, void *context);
/* Called for UI snapshots. Only actual changes relative to the last UI view
 * edit protocol fields; language/host/identity saves leave the full proto alone. */
void sl_stream_settings_note_ui(sl_stream_settings *, const sl_auth_store *);
/* Consume latest complete config and UI changes in producer order. */
bool sl_stream_settings_drain(sl_stream_settings *);
/* Call before registering session callbacks and connecting: file load itself
 * does not emit a delegate notification, save, or control message. */
bool sl_stream_settings_apply(const sl_stream_settings *, IHS_Session *);

uint64_t sl_stream_settings_revision(const sl_stream_settings *);

void sl_stream_settings_ack_ui(sl_stream_settings *, const sl_stream_preferences *,
                               uint64_t revision);

typedef struct sl_stream_request_limits {
    uint32_t width, height, fps;
    bool hevc;
} sl_stream_request_limits;
bool sl_stream_settings_apply_limited(const sl_stream_settings *, IHS_Session *,
                                      const sl_stream_request_limits *);
