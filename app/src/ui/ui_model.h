#pragma once
#include "services/auth_store.h"

typedef enum sl_page {
    SL_HOME,
    SL_PAIRING,
    SL_SAVING,
    SL_CONNECTING,
    SL_PIN,
    SL_STREAM,
    SL_MENU,
    SL_OPTIONS,
    SL_SETTINGS,
    SL_ADVANCED,
    SL_MANUAL,
    SL_INFO,
    SL_QUALITY,
    SL_HELP,
    SL_HOTKEY,
    SL_FORGET,
    SL_DISCONNECT,
    SL_EXIT,
    SL_STOPPING,
    SL_ERROR,
    SL_CLOSING
} sl_page;
typedef enum sl_action {
    SL_NONE,
    SL_ACCEPT,
    SL_BACK,
    SL_LEFT,
    SL_RIGHT,
    SL_UP,
    SL_DOWN,
    SL_PREV_HOST,
    SL_NEXT_HOST,
    SL_SELECT_HOST,
    SL_START,
    SL_RECENT,
    SL_OPEN_MENU,
    SL_DEBUG,
    SL_OPEN_OPTIONS,
    SL_OPEN_INFO,
    SL_OPEN_SETTINGS,
    SL_OPEN_ADVANCED,
    SL_OPEN_MANUAL,
    SL_OPEN_QUALITY,
    SL_OPEN_HELP,
    SL_OPEN_HOTKEY,
    SL_OPEN_FORGET,
    SL_CONFIRM_FORGET,
    SL_OPEN_DISCONNECT,
    SL_CONFIRM_STOP,
    SL_CONFIRM_EXIT,
    SL_DIGIT,
    SL_ERASE,
    SL_SUBMIT,
    SL_SET_QUALITY,
    SL_SOUND,
    SL_RETRY
} sl_action;
typedef enum sl_command_type {
    SL_CMD_NONE,
    SL_CMD_PAIR,
    SL_CMD_STREAM,
    SL_CMD_CANCEL,
    SL_CMD_STOP,
    SL_CMD_EXIT,
    SL_CMD_SAVE,
    SL_CMD_MANUAL
} sl_command_type;
typedef struct sl_command {
    sl_command_type type;
    uint64_t generation;
    sl_host host;
    uint64_t game_id;
    uint32_t quality;
    char text[64];
} sl_command;
typedef struct sl_control {
    int id, x, y, w, h;
    sl_action action;
    int arg;
    bool primary;
    char label[160];
} sl_control;
typedef struct sl_label {
    int x, y, size;
    bool center;
    char text[192];
} sl_label;
typedef struct sl_layout {
    sl_control controls[48];
    int count;
    sl_label labels[16];
    int label_count;
    bool fullscreen, dialog;
    char title[128];
} sl_layout;
typedef struct sl_ui_model {
    sl_auth_store store;
    sl_page page, stack[8];
    int focus_stack[8];
    bool repair_attempted;
    int depth;
    bool streaming, debug, network_ok, closing;
    int focus;
    uint64_t now, generation, entered_at, stream_started_at, pair_code_at;
    sl_command intent, command;
    char input[64], pairing_code[5], error[192];
    sl_layout layout;
} sl_ui_model;
void sl_ui_init(sl_ui_model *m, const sl_auth_store *store);
void sl_ui_layout(sl_ui_model *m);
void sl_ui_action(sl_ui_model *m, sl_action action, int arg);
void sl_ui_tick(sl_ui_model *m, uint64_t now);
void sl_ui_error(sl_ui_model *m, const char *message);
void sl_ui_connected(sl_ui_model *m);
void sl_ui_stopped(sl_ui_model *m, bool unexpected);
bool sl_ui_take_command(sl_ui_model *m, sl_command *out);
int sl_ui_hit(const sl_layout *layout, int x, int y);
void sl_ui_activate(sl_ui_model *m, int id);
bool sl_ui_remote(const sl_ui_model *m);

bool sl_ui_pair_prompt_visible(const sl_ui_model *model);
