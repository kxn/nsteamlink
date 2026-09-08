#include "input_router.h"
#include <stdlib.h>
#include <string.h>
#define BIT(k)    (1u << (k))
#define MENU_KEYS (BIT(SL_KEY_MINUS) | BIT(SL_KEY_PLUS))
static void send(sl_input_router *r, const sl_input_event *e) {
    if (r->send)
        r->send(e, r->context);
}
static void flush(sl_input_router *r) {
    for (int i = 0; i < r->pending_count; ++i) {
        r->pending[i].immediate = true;
        send(r, &r->pending[i]);
    }
    r->pending_count = 0;
    r->first_at = r->combo_at = 0;
    r->combo = false;
}
void sl_input_init(sl_input_router *r, sl_ui_model *m, sl_input_send_fn fn,
                   sl_input_neutral_fn neutral, void *ctx) {
    memset(r, 0, sizeof(*r));
    r->ui = m;
    r->send = fn;
    r->neutral = neutral;
    r->context = ctx;
}
void sl_input_sync(sl_input_router *r) {
    bool remote = sl_ui_remote(r->ui);
    if (remote != r->remote) {
        if (r->remote) {
            if (r->neutral)
                r->neutral(r->context);
            for (int i = 0; i < 8; ++i)
                if (r->touches[i].used && r->touches[i].remote) {
                    sl_input_event e = {.type = SL_TOUCH_UP,
                                        .finger = r->touches[i].id,
                                        .x = r->touches[i].x,
                                        .y = r->touches[i].y};
                    send(r, &e);
                    r->touches[i].remote = false;
                    r->touches[i].control = 0;
                }
        }
        r->remote = remote;
        r->release |= r->held;
        r->axis_release = 0;
        for (int axis = 0; axis < 6; ++axis)
            if (abs(r->axes[axis]) >= 8000)
                r->axis_release |= BIT(axis);
        r->pending_count = 0;
        r->combo = false;
        r->first_at = r->combo_at = 0;
        r->repeat = SL_NONE;
    }
    if (r->ui->page != SL_MENU) {
        r->debug_at = 0;
        r->debug_used = false;
    }
}
static sl_action key_action(int k) {
    switch (k) {
    case SL_KEY_A:
        return SL_ACCEPT;
    case SL_KEY_B:
        return SL_BACK;
    case SL_KEY_X:
        return SL_OPEN_OPTIONS;
    case SL_KEY_Y:
        return SL_OPEN_INFO;
    case SL_KEY_L:
        return SL_PREV_HOST;
    case SL_KEY_R:
        return SL_NEXT_HOST;
    case SL_KEY_UP:
        return SL_UP;
    case SL_KEY_DOWN:
        return SL_DOWN;
    case SL_KEY_LEFT:
        return SL_LEFT;
    case SL_KEY_RIGHT:
        return SL_RIGHT;
    default:
        return SL_NONE;
    }
}
void sl_input_event_handle(sl_input_router *r, const sl_input_event *e, uint64_t now) {
    sl_input_sync(r);
    if (e->type == SL_FOCUS_LOST) {
        if (r->neutral)
            r->neutral(r->context);
        for (int i = 0; i < 8; ++i)
            if (r->touches[i].used && r->touches[i].remote) {
                sl_input_event up = {.type = SL_TOUCH_UP,
                                     .finger = r->touches[i].id,
                                     .x = r->touches[i].x,
                                     .y = r->touches[i].y};
                send(r, &up);
            }
        memset(r->touches, 0, sizeof(r->touches));
        r->release |= r->held;
        r->axis_release = 0;
        for (int axis = 0; axis < 6; ++axis)
            if (abs(r->axes[axis]) >= 8000)
                r->axis_release |= BIT(axis);
        r->pending_count = 0;
        r->debug_at = r->first_at = r->combo_at = 0;
        r->combo = false;
        r->repeat = SL_NONE;
        if (r->remote)
            sl_ui_action(r->ui, SL_OPEN_MENU, 0);
        sl_input_sync(r);
        return;
    }
    if (e->type == SL_TOUCH_DOWN || e->type == SL_TOUCH_MOVE || e->type == SL_TOUCH_UP) {
        int slot = -1;
        for (int i = 0; i < 8; ++i)
            if (r->touches[i].used && r->touches[i].id == e->finger)
                slot = i;
        if (e->type == SL_TOUCH_DOWN) {
            if (slot >= 0)
                return;
            for (int i = 0; i < 8; ++i)
                if (!r->touches[i].used) {
                    slot = i;
                    break;
                }
            if (slot < 0)
                return;
            r->touches[slot].used = true;
            r->touches[slot].id = e->finger;
            r->touches[slot].control =
                sl_ui_hit(&r->ui->layout, (int)(e->x * 1280), (int)(e->y * 720));
            r->touches[slot].remote = r->remote && !r->touches[slot].control;
            r->touches[slot].page = r->ui->page;
        }
        if (slot < 0)
            return;
        r->touches[slot].x = e->x;
        r->touches[slot].y = e->y;
        if (r->touches[slot].remote)
            send(r, e);
        else if (e->type == SL_TOUCH_UP && r->touches[slot].control &&
                 r->touches[slot].page == r->ui->page &&
                 r->touches[slot].control ==
                     sl_ui_hit(&r->ui->layout, (int)(e->x * 1280), (int)(e->y * 720)))
            sl_ui_activate(r->ui, r->touches[slot].control);
        if (e->type == SL_TOUCH_UP)
            r->touches[slot].used = false;
        sl_input_sync(r);
        return;
    }
    if (e->type == SL_AXIS) {
        if (e->code < 0 || e->code >= 6)
            return;
        r->axes[e->code] = e->value;
        if (r->axis_release & BIT(e->code)) {
            if (abs(e->value) < 8000)
                r->axis_release &= ~BIT(e->code);
            else
                return;
        }
        if (r->remote)
            send(r, e);
        else if (e->code < 2) {
            /* SDL emits X/Y independently, including noise on the centered
             * axis. Derive one direction from the complete stick state. */
            int x = r->axes[0], y = r->axes[1];
            int axis = abs(y) >= abs(x) ? 1 : 0;
            bool vertical = r->repeat == SL_UP || r->repeat == SL_DOWN;
            bool horizontal = r->repeat == SL_LEFT || r->repeat == SL_RIGHT;
            if (vertical && abs(y) >= 12000 && abs(x) < abs(y) + 4000)
                axis = 1;
            else if (horizontal && abs(x) >= 12000 && abs(y) < abs(x) + 4000)
                axis = 0;
            int value = axis ? y : x;
            sl_action direction =
                value > 0 ? (axis ? SL_DOWN : SL_RIGHT) : (axis ? SL_UP : SL_LEFT);
            int threshold = direction == r->repeat ? 12000 : 16000;
            sl_action a = abs(value) >= threshold ? direction : SL_NONE;
            if (a != r->repeat) {
                r->repeat = a;
                r->repeat_at = now + 300;
                if (a)
                    sl_ui_action(r->ui, a, 0);
            }
        }
        return;
    }
    if (e->type != SL_BUTTON || e->code < 0 || e->code >= SL_KEY_COUNT)
        return;
    uint32_t bit = BIT(e->code);
    bool was = (r->held & bit) != 0;
    if (e->value)
        r->held |= bit;
    else
        r->held &= ~bit;
    if (r->release & bit) {
        if (!e->value)
            r->release &= ~bit;
        return;
    }
    if (was == (e->value != 0))
        return;
    if (!r->remote) {
        if (e->code == SL_KEY_X && r->ui->page == SL_MENU) {
            if (e->value) {
                r->debug_at = now;
                r->debug_used = false;
            } else
                r->debug_at = 0;
        } else if (e->value) {
            sl_action a = key_action(e->code);
            if (e->code == SL_KEY_X && (r->ui->page == SL_PIN || r->ui->page == SL_MANUAL))
                a = SL_ERASE;
            sl_ui_action(r->ui, a, 0);
            if (a >= SL_LEFT && a <= SL_DOWN) {
                r->repeat = a;
                r->repeat_at = now + 300;
            }
        } else if (key_action(e->code) == r->repeat)
            r->repeat = SL_NONE;
        sl_input_sync(r);
        return;
    }
    if (bit & MENU_KEYS) {
        if (!r->pending_count && e->value && !((r->held & ~bit) & MENU_KEYS))
            r->first_at = now;
        if (r->first_at || r->pending_count) {
            if (r->pending_count == 8)
                flush(r);
            r->pending[r->pending_count++] = *e;
            if ((r->held & MENU_KEYS) == MENU_KEYS && now - r->first_at <= 100 && !r->combo) {
                r->combo = true;
                r->combo_at = now;
            }
            if (!e->value)
                flush(r);
            return;
        }
    }
    send(r, e);
}
void sl_input_tick(sl_input_router *r, uint64_t now) {
    sl_input_sync(r);
    if (r->remote && r->pending_count) {
        if (r->combo && now - r->combo_at >= 800) {
            sl_ui_action(r->ui, SL_OPEN_MENU, 0);
            sl_input_sync(r);
        } else if (!r->combo && now - r->first_at >= 100)
            flush(r);
    }
    if (r->ui->page == SL_MENU && r->debug_at && !r->debug_used && now - r->debug_at >= 1000) {
        r->debug_used = true;
        sl_ui_action(r->ui, SL_DEBUG, 0);
        sl_input_sync(r);
    }
    if (!r->remote && r->repeat && now >= r->repeat_at) {
        sl_ui_action(r->ui, r->repeat, 0);
        r->repeat_at = now + 160;
    }
}
