#pragma once
#include "ui/ui_model.h"
typedef enum sl_key {
    SL_KEY_A,
    SL_KEY_B,
    SL_KEY_X,
    SL_KEY_Y,
    SL_KEY_MINUS,
    SL_KEY_GUIDE,
    SL_KEY_PLUS,
    SL_KEY_L3,
    SL_KEY_R3,
    SL_KEY_L,
    SL_KEY_R,
    SL_KEY_UP,
    SL_KEY_DOWN,
    SL_KEY_LEFT,
    SL_KEY_RIGHT,
    SL_KEY_COUNT
} sl_key;
typedef enum sl_input_type {
    SL_BUTTON,
    SL_AXIS,
    SL_TOUCH_DOWN,
    SL_TOUCH_MOVE,
    SL_TOUCH_UP,
    SL_FOCUS_LOST
} sl_input_type;
typedef struct sl_input_event {
    sl_input_type type;
    bool immediate;
    int device, code, value;
    int64_t finger;
    float x, y;
} sl_input_event;
typedef void (*sl_input_send_fn)(const sl_input_event *, void *);
typedef void (*sl_input_neutral_fn)(void *);
typedef struct sl_input_router {
    sl_ui_model *ui;
    sl_input_send_fn send;
    sl_input_neutral_fn neutral;
    void *context;
    uint32_t held, release;
    uint8_t axis_release;
    int axes[6];
    bool remote, combo, combo_used, debug_used;
    uint64_t first_at, combo_at, debug_at, repeat_at;
    sl_action repeat;
    sl_input_event pending[8];
    int pending_count;
    struct {
        bool used, remote;
        int64_t id;
        int control;
        sl_page page;
        float x, y;
    } touches[8];
} sl_input_router;
void sl_input_init(sl_input_router *, sl_ui_model *, sl_input_send_fn, sl_input_neutral_fn, void *);
void sl_input_event_handle(sl_input_router *, const sl_input_event *, uint64_t now);
void sl_input_tick(sl_input_router *, uint64_t now);
void sl_input_sync(sl_input_router *);
