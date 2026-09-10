#include "platform/shortcut.h"
#include "services/i18n.h"
#include "ui_model.h"
#include <stdio.h>
#include <string.h>
static void text(sl_layout *l, int x, int y, int size, const char *s) {
    if (l->label_count == 16)
        return;
    sl_label *t = &l->labels[l->label_count++];
    t->x = x;
    t->y = y;
    t->size = size;
    snprintf(t->text, sizeof(t->text), "%s", s);
}
static void button(sl_layout *l, int id, int x, int y, int w, int h, const char *s, sl_action a,
                   int arg, bool primary) {
    if (l->count == 48)
        return;
    sl_control *c = &l->controls[l->count++];
    *c = (sl_control){
        .id = id, .x = x, .y = y, .w = w, .h = h, .action = a, .arg = arg, .primary = primary};
    snprintf(c->label, sizeof(c->label), "%s", s);
}
static void row(sl_layout *l, int n, const char *s, sl_action a, int arg) {
    button(l, 100 + n, 320, 205 + n * 88, 640, 72, s, a, arg, false);
}
static void center(sl_layout *l, int y, int size, const char *s) {
    text(l, 64, y, size, s);
    l->labels[l->label_count - 1].center = true;
}
void sl_ui_layout(sl_ui_model *m) {
    sl_layout *l = &m->layout;
    memset(l, 0, sizeof(*l));
    sl_host_registry *r = &m->store.registry;
    sl_host *h = r->selected >= 0 && r->selected < r->count ? &r->hosts[r->selected] : NULL;
    l->fullscreen = m->streaming;
    bool connecting = m->page == SL_CONNECTING || m->page == SL_SAVING ||
                      (m->page == SL_PAIRING && !sl_ui_pair_prompt_visible(m));
    l->dialog = m->page != SL_HOME && m->page != SL_STREAM && !connecting;
    if (m->page == SL_HOME) {
        snprintf(l->title, sizeof(l->title), sl_tr(SL_T_APP_TITLE), NSL_APP_VERSION);
        if (h) {
            int begin = r->selected / 3 * 3, end = begin + 3;
            if (end > r->count)
                end = r->count;
            if (r->count > 1)
                button(l, 1, 40, 86, 64, 72, "LB", SL_PREV_HOST, 0, false);
            int origin = (1280 - (end - begin) * 342 + 16) / 2;
            for (int i = begin; i < end; ++i)
                button(l, 10 + i, origin + (i - begin) * 342, 86, 326, 72,
                       r->hosts[i].name[0] ? r->hosts[i].name : r->hosts[i].address, SL_SELECT_HOST,
                       i, i == r->selected);
            if (r->count > 1)
                button(l, 2, 1176, 86, 64, 72, "RB", SL_NEXT_HOST, 0, false);
            char address[160];
            snprintf(address, sizeof(address), "%s%s · %s",
                     sl_host_online(h, m->now) ? "" : sl_tr(SL_T_LAST_ADDRESS), h->address,
                     h->paired ? sl_tr(SL_T_PAIRED) : sl_tr(SL_T_UNPAIRED));
            center(l, 170, 26, address);
            if (!sl_host_online(h, m->now)) {
                center(l, 300, 44, sl_tr(SL_T_HOST_OFFLINE));
                center(l, 372, 30, sl_tr(SL_T_SEARCHING_AUTO));
            } else if (h->paired && h->games[0].id) {
                text(l, 52, 236, 36, sl_tr(SL_T_RECENT));
                button(l, 30, 956, 220, 272, 72, sl_tr(SL_T_OPEN_STEAM), SL_START, 0, false);
                for (int i = 0; i < sl_ui_game_count(m); ++i)
                    button(l, 40 + i, SL_GAMES_LEFT + i * SL_CARD_STEP - (int)m->games_scroll,
                           SL_CARD_Y, SL_CARD_WIDTH, SL_CARD_HEIGHT, h->games[i].name, SL_RECENT, i,
                           false);
            } else {
                center(l, 284, 44, h->paired ? sl_tr(SL_T_READY) : sl_tr(SL_T_CONNECT_PC));
                if (h->games_running)
                    center(l, 404, 28, sl_tr(SL_T_GAME_RUNNING));
                button(l, 30, 448, 472, 384, 80,
                       h->paired ? sl_tr(SL_T_OPEN_STEAM) : sl_tr(SL_T_PAIR_CONNECT), SL_START, 0,
                       true);
            }
        } else {
            center(l, 292, 44,
                   !m->network_ok                  ? sl_tr(SL_T_NO_NETWORK)
                   : m->now - m->entered_at < 8000 ? sl_tr(SL_T_SEARCHING)
                                                   : sl_tr(SL_T_NO_HOSTS));
            center(l, 368, 30,
                   m->network_ok ? sl_tr(SL_T_OPEN_SAME_NETWORK) : sl_tr(SL_T_SEARCH_WHEN_ONLINE));
        }
        button(l, 3, 1060, 632, 180, 64, sl_tr(SL_T_OPTIONS_KEY), SL_OPEN_OPTIONS, 0, false);
        button(l, 5, 40, 632, 180, 64, sl_tr(SL_T_EXIT_KEY), SL_BACK, 0, false);
        if (h && sl_host_online(h, m->now))
            text(l, 260, 648, 24,
                 sl_ui_game_count(m) ? sl_tr(SL_T_PLAY_KEY) : sl_tr(SL_T_CONNECT_KEY));
    } else if (m->page == SL_STREAM) {
        /* Full video, no persistent local touch target. */
    } else if (connecting) {
        snprintf(l->title, sizeof(l->title), sl_tr(SL_T_APP_TITLE), NSL_APP_VERSION);
        center(l, 276, 44, sl_tr(SL_T_CONNECTING));
        center(l, 354, 30, m->intent.host.name[0] ? m->intent.host.name : m->intent.text);
        button(l, 9, 40, 632, 180, 64, sl_tr(SL_T_CANCEL_KEY), SL_BACK, 0, false);
    } else {
        switch (m->page) {
        case SL_MENU:
            strcpy(l->title, sl_tr(SL_T_PLAY_MENU));
            row(l, 0, sl_tr(SL_T_RESUME), SL_BACK, 0);
            row(l, 1, sl_tr(SL_T_SETTINGS), SL_OPEN_SETTINGS, 0);
            row(l, 2, sl_tr(SL_T_END_GAME), SL_OPEN_END_GAME, 0);
            row(l, 3, sl_tr(SL_T_DISCONNECT), SL_OPEN_DISCONNECT, 0);
            break;
        case SL_OPTIONS:
            strcpy(l->title, sl_tr(SL_T_OPTIONS));
            row(l, 0, sl_tr(SL_T_SETTINGS), SL_OPEN_SETTINGS, 0);
            if (h)
                row(l, 1, sl_tr(SL_T_REMOVE_PC), SL_OPEN_FORGET, 0);
            row(l, h ? 2 : 1, sl_tr(SL_T_SHORTCUT), SL_OPEN_SHORTCUT, 0);
            break;
        case SL_SHORTCUT:
            strcpy(l->title, sl_tr(SL_T_SHORTCUT_QUESTION));
            text(l, 320, 272, 28, sl_tr(SL_T_SHORTCUT_DESCRIPTION));
            text(l, 320, 344, 24, SL_SHORTCUT_PATH);
            row(l, 3, sl_tr(SL_T_SHORTCUT_INSTALL), SL_CONFIRM_SHORTCUT, 0);
            break;
        case SL_INSTALLING:
            strcpy(l->title, sl_tr(SL_T_SHORTCUT_INSTALLING));
            break;
        case SL_INSTALL_RESULT:
            strcpy(l->title, sl_tr(SL_T_SHORTCUT_RESULT));
            text(l, 320, 240, 28, m->error);
            text(l, 320, 360, 24, SL_SHORTCUT_PATH);
            break;
        case SL_SETTINGS:
            strcpy(l->title, sl_tr(SL_T_SETTINGS));
            row(l, 0, sl_tr(SL_T_QUALITY), SL_OPEN_QUALITY, 0);
            row(l, 1, sl_tr(SL_T_BANDWIDTH), SL_OPEN_BANDWIDTH, 0);
            row(l, 2, m->store.sound ? sl_tr(SL_T_SOUND_ON) : sl_tr(SL_T_SOUND_OFF), SL_SOUND, 0);
            row(l, 3, sl_tr(SL_T_LANGUAGE), SL_OPEN_LANGUAGE, 0);
            if (!m->streaming)
                row(l, 4, sl_tr(SL_T_MANUAL), SL_OPEN_MANUAL, 0);
            break;
        case SL_LANGUAGE:
            strcpy(l->title, sl_tr(SL_T_LANGUAGE));
            row(l, 0, sl_tr(SL_T_SYSTEM_LANGUAGE), SL_SET_LANGUAGE, SL_LANG_SYSTEM);
            row(l, 1, sl_tr(SL_T_CHINESE), SL_SET_LANGUAGE, SL_LANG_ZH_CN);
            row(l, 2, sl_tr(SL_T_ENGLISH), SL_SET_LANGUAGE, SL_LANG_EN);
            break;
        case SL_BANDWIDTH:
            strcpy(l->title, sl_tr(SL_T_BANDWIDTH));
            row(l, 0, "4 Mbps", SL_SET_BANDWIDTH, 4000);
            row(l, 1, "6 Mbps", SL_SET_BANDWIDTH, 6000);
            row(l, 2, "10 Mbps", SL_SET_BANDWIDTH, 10000);
            row(l, 3, "20 Mbps", SL_SET_BANDWIDTH, 20000);
            if (m->streaming)
                text(l, 320, 548, 26, sl_tr(SL_T_NEXT_CONNECTION));
            break;
        case SL_QUALITY:
            strcpy(l->title, sl_tr(SL_T_QUALITY));
            row(l, 0, sl_tr(SL_T_BALANCED), SL_SET_QUALITY, 0);
            row(l, 1, sl_tr(SL_T_FAST), SL_SET_QUALITY, 1);
            row(l, 2, sl_tr(SL_T_SHARP), SL_SET_QUALITY, 2);
            if (m->streaming)
                text(l, 320, 500, 26, sl_tr(SL_T_NEXT_CONNECTION));
            break;
        case SL_PAIRING:
        case SL_SAVING:
            strcpy(l->title, m->page == SL_SAVING ? sl_tr(SL_T_SAVING_PAIR) : sl_tr(SL_T_PAIR_PC));
            text(l, 320, 240, 30, sl_tr(SL_T_ENTER_PAIR_CODE));
            center(l, 330, 72, m->pairing_code[0] ? m->pairing_code : "····");
            break;
        case SL_CONNECTING:
            strcpy(l->title, sl_tr(SL_T_CONNECTING));
            text(l, 320, 282, 36, m->intent.host.name[0] ? m->intent.host.name : m->intent.text);
            text(l, 320, 360, 28, sl_tr(SL_T_WAIT_VIDEO));
            break;
        case SL_STOPPING:
            strcpy(l->title, sl_tr(m->ending_game ? SL_T_ENDING_GAME : SL_T_DISCONNECTING));
            if (m->ending_game) {
                button(l, 9, 320, 596, 640, 64, sl_tr(SL_T_STOP_WAITING_KEY), SL_BACK, 0, false);
            }
            break;
        case SL_CLOSING:
            strcpy(l->title, sl_tr(SL_T_EXITING));
            break;
        case SL_PIN:
        case SL_MANUAL: {
            bool pin = m->page == SL_PIN;
            strcpy(l->title, pin ? sl_tr(SL_T_SECURITY_PIN) : sl_tr(SL_T_PC_IP));
            text(l, 320, 204, 36,
                 m->input[0] ? m->input
                 : pin       ? sl_tr(SL_T_ENTER_PIN)
                             : sl_tr(SL_T_IP_EXAMPLE));
            for (int i = 0; i < 12; ++i) {
                int digit = i < 9 ? '1' + i : i == 9 ? '.' : i == 10 ? '0' : 0;
                if (pin && i == 9)
                    continue;
                char label[32] = {digit ? digit : 0, 0};
                if (!digit)
                    strcpy(label, sl_tr(SL_T_DELETE));
                button(l, 200 + i, 320 + (i % 3) * 136, 274 + (i / 3) * 72, 120, 64, label,
                       digit ? SL_DIGIT : SL_ERASE, digit, false);
            }
            button(l, 220, 756, 274, 204, 136, sl_tr(SL_T_CONFIRM), SL_SUBMIT, 0, true);
            break;
        }
        case SL_END_GAME:
            strcpy(l->title, sl_tr(SL_T_END_GAME_QUESTION));
            text(l, 320, 236, 30, sl_tr(SL_T_END_GAME_EXPLANATION));
            row(l, 2, sl_tr(SL_T_END_GAME), SL_CONFIRM_END_GAME, 0);
            break;
        case SL_DISCONNECT:
            strcpy(l->title, sl_tr(SL_T_DISCONNECT_QUESTION));
            text(l, 320, 236, 30, sl_tr(SL_T_GAME_CONTINUES));
            row(l, 2, sl_tr(SL_T_DISCONNECT), SL_CONFIRM_STOP, 0);
            break;
        case SL_FORGET:
            strcpy(l->title, sl_tr(SL_T_REMOVE_QUESTION));
            text(l, 320, 236, 30, sl_tr(SL_T_REMOVE_EXPLANATION));
            row(l, 2, sl_tr(SL_T_REMOVE), SL_CONFIRM_FORGET, 0);
            break;
        case SL_EXIT:
            strcpy(l->title, sl_tr(SL_T_EXIT_QUESTION));
            row(l, 1, sl_tr(SL_T_EXIT), SL_CONFIRM_EXIT, 0);
            break;
        case SL_ERROR:
            strcpy(l->title,
                   m->ending_game ? sl_tr(SL_T_END_GAME)
                   : m->had_stream ? sl_tr(SL_T_STREAM_INTERRUPTED) : sl_tr(SL_T_CONNECT_FAILED));
            text(l, 320, 232, 30, m->error);
            if (m->intent.host.id && !m->ending_game)
                row(l, 2, sl_tr(SL_T_RETRY), SL_RETRY, 0);
            break;
        default:
            break;
        }
        if (m->page != SL_STOPPING && m->page != SL_INSTALLING && m->page != SL_CLOSING)
            button(l, 9, 320, 596, 640, 64,
                   m->page == SL_CONNECTING || m->page == SL_PAIRING || m->page == SL_SAVING
                       ? sl_tr(SL_T_CANCEL_KEY)
                       : sl_tr(SL_T_BACK_KEY),
                   SL_BACK, 0, false);
    }
    if (l->dialog) {
        l->drawer = m->page == SL_MENU || m->page == SL_OPTIONS || m->page == SL_SETTINGS ||
                    m->page == SL_QUALITY || m->page == SL_BANDWIDTH || m->page == SL_LANGUAGE;
        l->compact = m->page == SL_END_GAME || m->page == SL_DISCONNECT || m->page == SL_FORGET ||
                     m->page == SL_EXIT || m->page == SL_ERROR || m->page == SL_STOPPING ||
                     m->page == SL_INSTALLING;
        l->panel_x = 272;
        l->panel_y = 96;
        l->panel_w = 736;
        l->panel_h = 588;
        if (l->drawer) {
            l->panel_x = 744;
            l->panel_y = 0;
            l->panel_w = 536;
            l->panel_h = 720;
            for (int i = 0; i < l->count; ++i) {
                sl_control *c = &l->controls[i];
                c->x = 776;
                c->w = 472;
                c->y = c->id == 9 ? 624 : 172 + (c->id - 100) * 88;
                c->h = 72;
            }
            for (int i = 0; i < l->label_count; ++i)
                l->labels[i].x = 784;
        } else if (l->compact) {
            l->panel_x = 304;
            l->panel_y = 188;
            l->panel_w = 672;
            l->panel_h = 344;
            for (int i = 0; i < l->label_count; ++i) {
                l->labels[i].x = 344;
                l->labels[i].y = 292;
            }
            for (int i = 0; i < l->count; ++i) {
                sl_control *c = &l->controls[i];
                c->x = c->id == 9 ? 344 : 648;
                c->y = 420;
                c->w = 288;
                c->h = 72;
                if (c->id == 9)
                    strcpy(c->label, sl_tr(SL_T_CANCEL_KEY));
                else {
                    char title[160];
                    snprintf(title, sizeof(title), "A  %.150s", c->label);
                    snprintf(c->label, sizeof(c->label), "%s", title);
                    c->primary = true;
                }
            }
            if (m->page == SL_STOPPING || m->page == SL_INSTALLING) {
                l->panel_x = 360;
                l->panel_y = 256;
                l->panel_w = 560;
                l->panel_h = 208;
                if (m->page == SL_STOPPING && m->ending_game) {
                    l->panel_y = 208;
                    l->panel_h = 304;
                    sl_control *c = &l->controls[0];
                    c->x = l->panel_x + (l->panel_w - c->w) / 2;
                    c->y = l->panel_y + 192;
                    strcpy(c->label, sl_tr(SL_T_STOP_WAITING_KEY));
                }
            }
            if (m->page == SL_EXIT) {
                l->panel_y = 230;
                l->panel_h = 260;
                for (int i = 0; i < l->count; ++i)
                    l->controls[i].y = 378;
            }
        } else if (m->page == SL_SHORTCUT) {
            l->panel_y = 164;
            l->panel_h = 392;
            for (int i = 0; i < l->count; ++i) {
                sl_control *c = &l->controls[i];
                c->x = c->id == 9 ? 320 : 652;
                c->y = 444;
                c->w = 308;
                c->h = 72;
                c->primary = c->id != 9;
                if (c->primary)
                    snprintf(c->label, sizeof(c->label), "A  %s", sl_tr(SL_T_SHORTCUT_INSTALL));
                else
                    snprintf(c->label, sizeof(c->label), "%s", sl_tr(SL_T_CANCEL_KEY));
            }
        } else if (m->page == SL_INSTALL_RESULT) {
            l->panel_y = 164;
            l->panel_h = 420;
            l->labels[0].y = 272;
            l->labels[1].y = 376;
            l->controls[0].y = 472;
        } else if (m->page == SL_PAIRING) {
            l->panel_y = 160;
            l->panel_h = 420;
            l->controls[l->count - 1].y = 484;
            l->labels[0].y = 260;
        }
        if (!l->drawer && !l->compact) {
            for (int i = 0; i < l->label_count; ++i)
                if (!l->labels[i].center)
                    l->labels[i].x = l->panel_x + 40;
            for (int i = 0; i < l->count; ++i)
                if (l->controls[i].id == 9) {
                    l->controls[i].x = l->panel_x + 40;
                    l->controls[i].w = 180;
                }
        }
        l->opacity = sl_ui_overlay_opacity(m);
        l->offset_x = l->drawer ? (int)(536 * (1.f - l->opacity)) : 0;
        l->offset_y = l->drawer ? 0 : (int)(20 * (1.f - l->opacity));
    } else
        l->opacity = 1.f;
    if (m->page == SL_HOME) {
        int count = sl_ui_game_count(m);
        if (m->focus < 40 || m->focus >= 40 + count)
            m->focus = count ? (h->focus >= 40 && h->focus < 40 + count ? h->focus : 40) : 0;
        if (h)
            h->focus = m->focus;
        if (m->games_host != (h ? h->id : 0)) {
            m->games_host = h ? h->id : 0;
            m->games_dragging = false;
            m->games_target = m->focus >= 40 ? (m->focus - 40) * SL_CARD_STEP : 0.f;
            float limit = sl_ui_scroll_limit(m);
            if (m->games_target > limit)
                m->games_target = limit;
            m->games_scroll = m->games_target;
        }
        float limit = sl_ui_scroll_limit(m);
        if (m->games_target > limit)
            m->games_target = limit;
        if (m->games_scroll > limit)
            m->games_scroll = limit;
        if (!count) {
            m->games_scroll = m->games_target = 0.f;
            m->games_dragging = false;
        }
        for (int i = 0; i < l->count; ++i)
            if (l->controls[i].action == SL_RECENT)
                l->controls[i].x =
                    SL_GAMES_LEFT + l->controls[i].arg * SL_CARD_STEP - (int)m->games_scroll;
        return;
    }
    if (m->page == SL_CONNECTING || m->page == SL_SAVING || m->page == SL_PAIRING) {
        m->focus = 0; /* B/touch shortcut, never an A-selectable cancellation. */
        return;
    }
    bool found = false;
    for (int i = 0; i < l->count; ++i)
        if (l->controls[i].id == m->focus)
            found = true;
    if (!found) {
        m->focus = l->count ? l->controls[0].id : 0;
    }
    if (l->compact || m->page == SL_SHORTCUT) {
        m->focus = 0;
        for (int i = 0; i < l->count; ++i)
            if (l->controls[i].primary)
                m->focus = l->controls[i].id;
    }
}
