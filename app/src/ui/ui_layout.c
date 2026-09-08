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
        snprintf(l->title, sizeof(l->title), "NSteamLink  http://github.com/kxn/nsteamlink  v%s",
                 NSL_APP_VERSION);
        if (h) {
            int begin = r->selected / 3 * 3, end = begin + 3;
            if (end > r->count)
                end = r->count;
            if (r->count > 1)
                button(l, 1, 40, 86, 64, 72, "L", SL_PREV_HOST, 0, false);
            int origin = (1280 - (end - begin) * 342 + 16) / 2;
            for (int i = begin; i < end; ++i)
                button(l, 10 + i, origin + (i - begin) * 342, 86, 326, 72,
                       r->hosts[i].name[0] ? r->hosts[i].name : r->hosts[i].address, SL_SELECT_HOST,
                       i, i == r->selected);
            if (r->count > 1)
                button(l, 2, 1176, 86, 64, 72, "R", SL_NEXT_HOST, 0, false);
            bool duplicate = !h->name[0];
            for (int i = 0; i < r->count; ++i)
                if (&r->hosts[i] != h && !strcmp(h->name, r->hosts[i].name))
                    duplicate = true;
            if (!sl_host_online(h, m->now)) {
                center(l, 300, 44, "暂未发现这台电脑");
                center(l, 372, 30, "正在自动查找");
            } else if (h->paired && h->games[0].id) {
                text(l, 52, 236, 36, "最近游玩");
                button(l, 30, 956, 220, 272, 72, "打开 Steam →", SL_START, 0, false);
                for (int i = 0; i < 2 && h->games[i].id; ++i)
                    button(l, 40 + i, 52 + i * 602, 320, 572, 250, h->games[i].name, SL_RECENT, i,
                           false);
            } else {
                center(l, 284, 44, h->paired ? "准备就绪" : "连接这台电脑");
                char meta[128];
                snprintf(meta, sizeof(meta), "%s%s%s", h->system,
                         duplicate && h->system[0] ? " · " : "", duplicate ? h->address : "");
                if (meta[0])
                    center(l, 356, 30, meta);
                if (h->games_running)
                    center(l, 404, 28, "电脑正在运行游戏");
                button(l, 30, 448, 472, 384, 80, h->paired ? "开始游玩" : "配对并连接", SL_START, 0,
                       true);
            }
            button(l, 4, 776, 632, 264, 64, "Y  电脑信息", SL_OPEN_INFO, 0, false);
        } else {
            center(l, 292, 44,
                   !m->network_ok                  ? "网络未连接"
                   : m->now - m->entered_at < 8000 ? "正在查找电脑"
                                                   : "尚未发现电脑");
            center(l, 368, 30, m->network_ok ? "在同一网络中打开 Steam" : "联网后会自动继续查找");
        }
        button(l, 3, 1060, 632, 180, 64, "X  选项", SL_OPEN_OPTIONS, 0, false);
        button(l, 5, 40, 632, 180, 64, "B  退出", SL_BACK, 0, false);
        if (h && sl_host_online(h, m->now))
            text(l, 260, 648, 24, "A  确认");
    } else if (m->page == SL_STREAM) {
        /* Full video, no persistent local touch target. */
    } else if (connecting) {
        snprintf(l->title, sizeof(l->title), "NSteamLink  http://github.com/kxn/nsteamlink  v%s",
                 NSL_APP_VERSION);
        center(l, 276, 44, "正在连接");
        center(l, 354, 30, m->intent.host.name[0] ? m->intent.host.name : m->intent.text);
        button(l, 9, 40, 632, 180, 64, "B  取消", SL_BACK, 0, false);
    } else {
        switch (m->page) {
        case SL_MENU:
            strcpy(l->title, "游玩菜单");
            row(l, 0, "继续游玩", SL_BACK, 0);
            row(l, 1, "设置", SL_OPEN_SETTINGS, 0);
            row(l, 2, "断开连接", SL_OPEN_DISCONNECT, 0);
            break;
        case SL_OPTIONS:
            strcpy(l->title, "选项");
            row(l, 0, "设置", SL_OPEN_SETTINGS, 0);
            if (h)
                row(l, 1, "移除电脑", SL_OPEN_FORGET, 0);
            break;
        case SL_SETTINGS:
            strcpy(l->title, "设置");
            row(l, 0, "画面偏好", SL_OPEN_QUALITY, 0);
            row(l, 1, m->store.sound ? "声音：开" : "声音：关", SL_SOUND, 0);
            if (!m->streaming)
                row(l, 2, "手动添加电脑", SL_OPEN_MANUAL, 0);
            break;
        case SL_QUALITY:
            strcpy(l->title, "画面偏好");
            row(l, 0, "均衡", SL_SET_QUALITY, 0);
            row(l, 1, "流畅", SL_SET_QUALITY, 1);
            row(l, 2, "清晰", SL_SET_QUALITY, 2);
            if (m->streaming)
                text(l, 320, 500, 26, "下次连接时生效");
            break;
        case SL_INFO:
            strcpy(l->title, "电脑信息");
            if (h) {
                text(l, 320, 220, 32, h->name[0] ? h->name : "未提供名称");
                text(l, 320, 324, 28, h->system);
                text(l, 320, 380, 28, sl_host_online(h, m->now) ? "已发现" : "暂未发现 · 上次地址");
                text(l, 320, 436, 28, h->address);
                text(l, 320, 492, 28, h->paired ? "本机有配对记录" : "尚未配对");
            }
            break;
        case SL_PAIRING:
        case SL_SAVING:
            strcpy(l->title, m->page == SL_SAVING ? "正在保存配对" : "配对电脑");
            text(l, 320, 240, 30, "在电脑上的 Steam 输入此代码");
            center(l, 330, 72, m->pairing_code[0] ? m->pairing_code : "····");
            break;
        case SL_CONNECTING:
            strcpy(l->title, "正在连接");
            text(l, 320, 282, 36, m->intent.host.name[0] ? m->intent.host.name : m->intent.text);
            text(l, 320, 360, 28, "等待电脑和画面");
            break;
        case SL_STOPPING:
            strcpy(l->title, "正在断开");
            break;
        case SL_CLOSING:
            strcpy(l->title, "正在退出");
            break;
        case SL_PIN:
        case SL_MANUAL: {
            bool pin = m->page == SL_PIN;
            strcpy(l->title, pin ? "连接安全码" : "电脑 IP 地址");
            text(l, 320, 204, 36,
                 m->input[0] ? m->input
                 : pin       ? "输入电脑的安全码"
                             : "例如 192.168.1.24");
            for (int i = 0; i < 12; ++i) {
                int digit = i < 9 ? '1' + i : i == 9 ? '.' : i == 10 ? '0' : 0;
                if (pin && i == 9)
                    continue;
                char label[8] = {digit ? digit : 0, 0};
                if (!digit)
                    strcpy(label, "删除");
                button(l, 200 + i, 320 + (i % 3) * 136, 274 + (i / 3) * 72, 120, 64, label,
                       digit ? SL_DIGIT : SL_ERASE, digit, false);
            }
            button(l, 220, 756, 274, 204, 136, "确认", SL_SUBMIT, 0, true);
            break;
        }
        case SL_DISCONNECT:
            strcpy(l->title, "断开串流？");
            text(l, 320, 236, 30, "电脑上的游戏会继续运行");
            row(l, 2, "断开连接", SL_CONFIRM_STOP, 0);
            break;
        case SL_FORGET:
            strcpy(l->title, "移除这台电脑？");
            text(l, 320, 236, 30, "移除本机的配对和游玩记录");
            row(l, 2, "移除", SL_CONFIRM_FORGET, 0);
            break;
        case SL_EXIT:
            strcpy(l->title, "退出 NSteamLink？");
            row(l, 1, "退出", SL_CONFIRM_EXIT, 0);
            break;
        case SL_ERROR:
            strcpy(l->title, "连接未完成");
            text(l, 320, 232, 30, m->error);
            if (m->intent.host.id)
                row(l, 2, "重试", SL_RETRY, 0);
            break;
        default:
            break;
        }
        if (m->page != SL_STOPPING && m->page != SL_CLOSING)
            button(l, 9, 320, 596, 640, 64,
                   m->page == SL_CONNECTING || m->page == SL_PAIRING || m->page == SL_SAVING
                       ? "B  取消"
                       : "B  返回",
                   SL_BACK, 0, false);
    }
    if (l->dialog) {
        l->drawer = m->page == SL_MENU || m->page == SL_OPTIONS || m->page == SL_SETTINGS ||
                    m->page == SL_QUALITY;
        l->compact = m->page == SL_DISCONNECT || m->page == SL_FORGET || m->page == SL_EXIT ||
                     m->page == SL_ERROR;
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
                    strcpy(c->label, "B  取消");
                else {
                    char title[160];
                    snprintf(title, sizeof(title), "A  %.150s", c->label);
                    snprintf(c->label, sizeof(c->label), "%s", title);
                    c->primary = true;
                }
            }
            if (m->page == SL_EXIT) {
                l->panel_y = 230;
                l->panel_h = 260;
                for (int i = 0; i < l->count; ++i)
                    l->controls[i].y = 378;
            }
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
    bool found = false;
    for (int i = 0; i < l->count; ++i)
        if (l->controls[i].id == m->focus)
            found = true;
    if (!found) {
        m->focus = l->count ? l->controls[0].id : 0;
        if (m->page == SL_HOME)
            for (int i = 0; i < l->count; ++i)
                if (l->controls[i].action == SL_START || l->controls[i].action == SL_RECENT) {
                    m->focus = l->controls[i].id;
                    break;
                }
    }
    if (l->compact) {
        m->focus = 0;
        for (int i = 0; i < l->count; ++i)
            if (l->controls[i].primary)
                m->focus = l->controls[i].id;
    }
}
