#include "ui_model.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void page(sl_ui_model *m, sl_page p) {
    m->leaving = false;
    m->page = p;
    m->focus = 0;
    m->entered_at = m->now;
}
static void push(sl_ui_model *m, sl_page p) {
    if (m->depth < 8) {
        m->focus_stack[m->depth] = m->focus;
        m->stack[m->depth++] = m->page;
    }
    page(m, p);
}
static void back_now(sl_ui_model *m) {
    int focus = m->depth ? m->focus_stack[m->depth - 1] : 0;
    page(m, m->depth ? m->stack[--m->depth] : (m->streaming ? SL_STREAM : SL_HOME));
    m->focus = focus;
    /* The parent was already visible beneath the departing overlay. */
    m->entered_at = m->now >= 220 ? m->now - 220 : 0;
}
float sl_ui_overlay_opacity(const sl_ui_model *m) {
    uint64_t start = m->page == SL_PAIRING ? m->pair_code_at + 1800 : m->entered_at;
    float t = m->now >= start ? (m->now - start) / 220.f : 0.f;
    if (t > 1.f)
        t = 1.f;
    float value = 1.f - (1.f - t) * (1.f - t) * (1.f - t);
    if (m->leaving) {
        t = m->now >= m->leave_at ? (m->now - m->leave_at) / 160.f : 0.f;
        if (t > 1.f)
            t = 1.f;
        value = m->leave_opacity * (1.f - t * t);
    }
    return value;
}
static void back(sl_ui_model *m) {
    if (m->layout.dialog) {
        m->leave_opacity = sl_ui_overlay_opacity(m);
        m->leave_at = m->now;
        m->leaving = true;
    } else
        back_now(m);
}
static sl_host *selected(sl_ui_model *m) {
    int i = m->store.registry.selected;
    return i >= 0 && i < m->store.registry.count ? &m->store.registry.hosts[i] : NULL;
}
void sl_ui_init(sl_ui_model *m, const sl_auth_store *s) {
    memset(m, 0, sizeof(*m));
    m->store = *s;
    m->page = SL_HOME;
    m->network_ok = true;
    sl_ui_layout(m);
}
void sl_ui_error(sl_ui_model *m, const char *message) {
    snprintf(m->error, sizeof(m->error), "%s", message);
    page(m, SL_ERROR);
    sl_ui_layout(m);
}
bool sl_ui_remote(const sl_ui_model *m) {
    return m->streaming && m->page == SL_STREAM;
}
void sl_ui_connected(sl_ui_model *m) {
    m->streaming = true;
    m->stream_started_at = m->now;
    m->debug = false;
    m->depth = 0;
    page(m, SL_STREAM);
    sl_ui_layout(m);
}
void sl_ui_stopped(sl_ui_model *m, bool unexpected) {
    m->streaming = false;
    m->debug = false;
    m->depth = 0;
    if (m->closing)
        page(m, SL_CLOSING);
    else if (unexpected)
        sl_ui_error(m, "连接已断开");
    else
        page(m, SL_HOME);
    sl_ui_layout(m);
}
void sl_ui_tick(sl_ui_model *m, uint64_t now) {
    m->now = now;
    if (m->leaving && now >= m->leave_at + 160)
        back_now(m);
    sl_ui_layout(m);
}
bool sl_ui_take_command(sl_ui_model *m, sl_command *out) {
    if (m->command.type == SL_CMD_NONE)
        return false;
    *out = m->command;
    memset(&m->command, 0, sizeof(m->command));
    return true;
}
static void emit(sl_ui_model *m, sl_command_type type) {
    m->intent.generation = m->generation;
    m->command = m->intent;
    m->command.type = type;
    m->command.generation = m->generation;
    m->command.quality = m->store.quality;
}
static void start(sl_ui_model *m, int game) {
    sl_host *h = selected(m);
    if (!h || !sl_host_online(h, m->now))
        return;
    m->generation++;
    m->repair_attempted = !h->paired;
    memset(&m->intent, 0, sizeof(m->intent));
    m->intent.host = *h;
    m->intent.generation = m->generation;
    if (game >= 0 && game < SL_RECENT_LIMIT && h->paired)
        m->intent.game_id = h->games[game].id;
    m->depth = 0;
    m->input[0] = 0;
    m->pairing_code[0] = 0;
    page(m, h->paired ? SL_CONNECTING : SL_PAIRING);
    emit(m, h->paired ? SL_CMD_STREAM : SL_CMD_PAIR);
}
static void move(sl_ui_model *m, sl_action direction) {
    const sl_control *from = NULL;
    for (int i = 0; i < m->layout.count; ++i)
        if (m->layout.controls[i].id == m->focus)
            from = &m->layout.controls[i];
    if (!from)
        return;
    int best = 0, score = 2147483647, fx = from->x + from->w / 2, fy = from->y + from->h / 2;
    for (int i = 0; i < m->layout.count; ++i) {
        const sl_control *c = &m->layout.controls[i];
        int dx = c->x + c->w / 2 - fx, dy = c->y + c->h / 2 - fy;
        int along = (direction == SL_LEFT    ? -dx
                     : direction == SL_RIGHT ? dx
                     : direction == SL_UP    ? -dy
                                             : dy);
        int across = (direction == SL_LEFT || direction == SL_RIGHT) ? abs(dy) : abs(dx);
        if (along > 0 && along + across * 4 < score) {
            best = c->id;
            score = along + across * 4;
        }
    }
    if (best)
        m->focus = best;
}
void sl_ui_action(sl_ui_model *m, sl_action a, int arg) {
    if (m->page == SL_CLOSING || m->leaving)
        return;
    if (a >= SL_LEFT && a <= SL_DOWN) {
        move(m, a);
        return;
    }
    if (a == SL_ACCEPT) {
        sl_ui_activate(m, m->focus);
        return;
    }
    sl_host *h = selected(m);
    switch (a) {
    case SL_PREV_HOST:
    case SL_NEXT_HOST:
    case SL_SELECT_HOST:
        if (m->page != SL_HOME || !m->store.registry.count)
            break;
        if (h)
            h->focus = m->focus;
        if (a == SL_SELECT_HOST) {
            if (arg < 0 || arg >= m->store.registry.count)
                break;
            m->store.registry.selected = arg;
        } else
            m->store.registry.selected = (m->store.registry.selected +
                                          (a == SL_PREV_HOST ? -1 : 1) + m->store.registry.count) %
                                         m->store.registry.count;
        m->focus = selected(m)->focus;
        break;
    case SL_START:
        if (m->page == SL_HOME)
            start(m, -1);
        break;
    case SL_RECENT:
        if (m->page == SL_HOME)
            start(m, arg);
        break;
    case SL_OPEN_OPTIONS:
        if (m->page == SL_HOME)
            push(m, SL_OPTIONS);
        break;
    case SL_OPEN_INFO:
        if (m->page == SL_HOME && h)
            push(m, SL_INFO);
        break;
    case SL_OPEN_SETTINGS:
        push(m, SL_SETTINGS);
        break;
    case SL_OPEN_ADVANCED:
        push(m, SL_ADVANCED);
        break;
    case SL_OPEN_MANUAL:
        m->input[0] = 0;
        push(m, SL_MANUAL);
        break;
    case SL_OPEN_QUALITY:
        push(m, SL_QUALITY);
        break;
    case SL_OPEN_HELP:
        push(m, SL_HELP);
        break;
    case SL_OPEN_HOTKEY:
        push(m, SL_HOTKEY);
        break;
    case SL_OPEN_FORGET:
        if (h)
            push(m, SL_FORGET);
        break;
    case SL_CONFIRM_FORGET:
        if (m->page == SL_FORGET && h) {
            sl_host_forget(&m->store.registry, h->id);
            m->depth = 0;
            page(m, SL_HOME);
            emit(m, SL_CMD_SAVE);
        }
        break;
    case SL_OPEN_MENU:
        if (sl_ui_remote(m)) {
            m->depth = 0;
            push(m, SL_MENU);
        }
        break;
    case SL_DEBUG:
        if (m->streaming && m->page == SL_MENU) {
            m->debug = !m->debug;
            back(m);
        }
        break;
    case SL_OPEN_DISCONNECT:
        if (m->streaming)
            push(m, SL_DISCONNECT);
        break;
    case SL_CONFIRM_STOP:
        if (m->page == SL_DISCONNECT) {
            ++m->generation;
            page(m, SL_STOPPING);
            emit(m, SL_CMD_STOP);
        }
        break;
    case SL_CONFIRM_EXIT:
        if (m->page == SL_EXIT) {
            ++m->generation;
            m->closing = true;
            page(m, SL_CLOSING);
            emit(m, SL_CMD_EXIT);
        }
        break;
    case SL_BACK:
        if (m->page == SL_HOME)
            push(m, SL_EXIT);
        else if (m->page == SL_PAIRING || m->page == SL_SAVING || m->page == SL_CONNECTING ||
                 m->page == SL_PIN || m->page == SL_ERROR) {
            ++m->generation;
            emit(m, SL_CMD_CANCEL);
            m->depth = 0;
            page(m, SL_STOPPING);
        } else if (m->page != SL_STREAM && m->page != SL_STOPPING)
            back(m);
        break;
    case SL_DIGIT:
        if (m->page == SL_PIN || m->page == SL_MANUAL) {
            size_t n = strlen(m->input), limit = m->page == SL_PIN ? 15 : 15;
            if (n < limit && ((arg >= '0' && arg <= '9') || (m->page == SL_MANUAL && arg == '.'))) {
                m->input[n] = (char)arg;
                m->input[n + 1] = 0;
            }
        }
        break;
    case SL_ERASE:
        if ((m->page == SL_PIN || m->page == SL_MANUAL) && m->input[0])
            m->input[strlen(m->input) - 1] = 0;
        break;
    case SL_SUBMIT:
        if (!m->input[0])
            break;
        if (m->page == SL_PIN) {
            snprintf(m->intent.text, sizeof(m->intent.text), "%s", m->input);
            page(m, SL_CONNECTING);
            emit(m, SL_CMD_STREAM);
        } else if (m->page == SL_MANUAL) {
            ++m->generation;
            memset(&m->intent, 0, sizeof(m->intent));
            snprintf(m->intent.text, sizeof(m->intent.text), "%s", m->input);
            page(m, SL_CONNECTING);
            emit(m, SL_CMD_MANUAL);
        }
        break;
    case SL_SET_QUALITY:
        if (arg >= 0 && arg <= 2) {
            m->store.quality = (uint32_t)arg;
            emit(m, SL_CMD_SAVE);
            back(m);
        }
        break;
    case SL_SOUND:
        m->store.sound = !m->store.sound;
        emit(m, SL_CMD_SAVE);
        break;
    case SL_RETRY:
        if (m->page == SL_ERROR) {
            m->repair_attempted = !m->intent.host.paired;
            m->pairing_code[0] = 0;
            ++m->generation;
            page(m, m->intent.host.paired ? SL_CONNECTING : SL_PAIRING);
            emit(m, m->intent.host.id ? (m->intent.host.paired ? SL_CMD_STREAM : SL_CMD_PAIR)
                                      : SL_CMD_CANCEL);
        }
        break;
    default:
        break;
    }
    sl_ui_layout(m);
}
int sl_ui_hit(const sl_layout *l, int x, int y) {
    x -= l->offset_x;
    y -= l->offset_y;
    for (int i = l->count - 1; i >= 0; --i) {
        const sl_control *c = &l->controls[i];
        if (x >= c->x && y >= c->y && x < c->x + c->w && y < c->y + c->h)
            return c->id;
    }
    return 0;
}
void sl_ui_activate(sl_ui_model *m, int id) {
    if (m->leaving)
        return;
    for (int i = 0; i < m->layout.count; ++i)
        if (m->layout.controls[i].id == id) {
            sl_control c = m->layout.controls[i];
            m->focus = id;
            sl_ui_action(m, c.action, c.arg);
            return;
        }
}

bool sl_ui_pair_prompt_visible(const sl_ui_model *m) {
    return m->page == SL_PAIRING && m->pairing_code[0] && m->now >= m->pair_code_at + 1800;
}
