#pragma once
#include "ui/ui_model.h"
typedef struct sl_runtime sl_runtime;
typedef enum sl_event_type {
    SL_EVENT_HOST,
    SL_EVENT_CODE,
    SL_EVENT_SAVING,
    SL_EVENT_AUTHORIZED,
    SL_EVENT_PIN,
    SL_EVENT_FAILURE,
    SL_EVENT_FIRST_FRAME,
    SL_EVENT_STOPPED,
    SL_EVENT_ACTIVITY,
    SL_EVENT_NETWORK,
    SL_EVENT_CLOSED
} sl_event_type;
typedef struct sl_runtime_event {
    sl_event_type type;
    uint64_t generation, account;
    sl_host host;
    sl_game game;
    char text[192];
} sl_runtime_event;
typedef struct sl_debug_snapshot {
    uint64_t sampled_at;
    uint32_t frames;
    char title[96], values[6][64];
} sl_debug_snapshot;
sl_runtime *sl_runtime_create(const sl_auth_store *store);
bool sl_runtime_submit(sl_runtime *, const sl_command *, const sl_auth_store *store);
bool sl_runtime_poll(sl_runtime *, sl_runtime_event *);
void sl_runtime_debug(sl_runtime *, sl_debug_snapshot *);
void sl_runtime_destroy(sl_runtime *);
void sl_log(const char *message);
bool sl_log_start(void);
void sl_log_finish(void);
