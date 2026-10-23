#include "input/input_router.h"
#include "services/auth_store_legacy.h"
#include "ui/ui_events.h"
#include "ui/ui_model.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static bool no_replace, fail_publish;
int __real_rename(const char *, const char *);
int __wrap_rename(const char *from, const char *to) {
    if (no_replace && access(to, F_OK) == 0) {
        errno = EEXIST;
        return -1;
    }
    if (fail_publish && strstr(from, "profile.tmp") && access(to, F_OK) != 0) {
        errno = EIO;
        return -1;
    }
    return __real_rename(from, to);
}
static sl_input_event sent[64];
static int n, neutral;
static void send_event(const sl_input_event *e, void *ctx) {
    (void)ctx;
    assert(n < 64);
    sent[n++] = *e;
}
static void reset_remote(void *ctx) {
    (void)ctx;
    neutral++;
}
static void key(sl_input_router *r, sl_key k, int v, uint64_t now) {
    sl_input_event e = {.type = SL_BUTTON, .code = k, .value = v};
    sl_input_event_handle(r, &e, now);
}
static void tap(sl_input_router *r, int x, int y) {
    sl_input_event e = {.type = SL_TOUCH_DOWN, .finger = 12, .x = x / 1280.f, .y = y / 720.f};
    sl_input_event_handle(r, &e, 100);
    e.type = SL_TOUCH_UP;
    sl_input_event_handle(r, &e, 101);
}
static sl_ui_model model(void) {
    sl_auth_store s = {.sound = true};
    sl_host_registry_init(&s.registry);
    sl_ui_model m;
    sl_ui_init(&m, &s);
    m.now = 100;
    return m;
}
static bool has_label(const sl_ui_model *m, const char *label) {
    for (int i = 0; i < m->layout.label_count; ++i)
        if (!strcmp(m->layout.labels[i].text, label))
            return true;
    return false;
}
static void discovery_source_evidence(void) {
    sl_ui_model m = model();
    sl_runtime_event e = {.type = SL_EVENT_HOST, .host = {.client_id = 4321}};
    strcpy(e.host.name, "PC");
    strcpy(e.host.address, "10.10.10.166");
    e.discovery_source = SL_DISCOVERY_INTERNET;
    sl_ui_runtime_event(&m, &e);
    sl_host *h = &m.store.registry.hosts[0];
    assert(sl_ui_host_source(&m, h) == SL_DISCOVERY_INTERNET); /* Private IP is not LAN proof. */
    e.discovery_source = SL_DISCOVERY_LAN;
    sl_ui_runtime_event(&m, &e);
    assert(sl_ui_host_source(&m, h) == SL_DISCOVERY_LAN);
    e.discovery_source = SL_DISCOVERY_INTERNET;
    sl_ui_runtime_event(&m, &e);
    assert(sl_ui_host_source(&m, h) ==
           SL_DISCOVERY_INTERNET); /* Fresh complete evidence replaces old. */
    h->paired = true;
    sl_ui_layout(&m);
    assert(has_label(&m, sl_tr(SL_T_OPEN_STEAM_KEY)) && !has_label(&m, sl_tr(SL_T_HOST_OFFLINE)));
    sl_ui_tick(&m, m.now + 15000);
    assert(sl_ui_host_source(&m, h) == SL_DISCOVERY_NONE && h->paired);
    assert(has_label(&m, sl_tr(SL_T_HOST_OFFLINE))); /* Saved pairing is not discovery. */
    e.discovery_source = SL_DISCOVERY_INTERNET;
    sl_ui_runtime_event(&m, &e);
    sl_runtime_event off = {.type = SL_EVENT_HOST_OFFLINE, .host = {.client_id = 4321}};
    sl_ui_runtime_event(&m, &off);
    assert(sl_ui_host_source(&m, h) == SL_DISCOVERY_NONE);
    sl_auth_store saved = m.store;
    sl_ui_model restarted;
    sl_ui_init(&restarted, &saved);
    /* Store loaders clear observed; model never fabricates a source from old metadata. */
    restarted.store.registry.hosts[0].observed = true;
    restarted.store.registry.hosts[0].last_seen = restarted.now;
    assert(sl_ui_host_source(&restarted, &restarted.store.registry.hosts[0]) ==
           SL_DISCOVERY_UNKNOWN);
}
static void add(sl_ui_model *m, int id, const char *name) {
    sl_host h = {.client_id = id, .instance_id = 10};
    snprintf(h.name, 64, "%s", name);
    snprintf(h.address, 64, "192.168.1.%d", id);
    sl_host_observe(&m->store.registry, &h, m->now);
    sl_ui_layout(m);
}
static void layout_check(sl_ui_model *m) {
    sl_ui_layout(m);
    for (int i = 0; i < m->layout.count; ++i) {
        sl_control *c = &m->layout.controls[i];
        assert(c->w >= 64 && c->h >= 64);
        assert(c->action == SL_RECENT ||
               (c->x >= 0 && c->y >= 0 && c->x + c->w <= 1280 && c->y + c->h <= 720));
        for (int j = 0; j < i; ++j) {
            sl_control *d = &m->layout.controls[j];
            assert(c->id != d->id);
            assert(c->x >= d->x + d->w || d->x >= c->x + c->w || c->y >= d->y + d->h ||
                   d->y >= c->y + c->h);
        }
    }
}
static void add_computer_navigation(void) {
    sl_ui_model m = model();
    sl_command command;
    add(&m, 1, "First");
    add(&m, 2, "Second");
    sl_ui_action(&m, SL_NEXT_HOST, 0);
    assert(m.store.registry.selected == 1);
    sl_ui_action(&m, SL_NEXT_HOST, 0);
    assert(sl_ui_adding_host(&m) && m.store.registry.count == 2 && m.store.registry.selected == 1 &&
           !sl_ui_take_command(&m, &command));
    add(&m, 3, "Found while adding");
    assert(sl_ui_adding_host(&m)); /* Discovery must not steal the explicit Add tab. */
    sl_ui_action(&m, SL_PREV_HOST, 0);
    assert(!sl_ui_adding_host(&m) && m.store.registry.selected == 2);
    sl_ui_action(&m, SL_NEXT_HOST, 0);
    sl_ui_action(&m, SL_NEXT_HOST, 0);
    assert(!sl_ui_adding_host(&m) && m.store.registry.selected == 0);

    sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
    sl_ui_action(&m, SL_OPEN_HOST_SETTINGS, 0);
    sl_ui_activate(&m, 100); /* Existing manual entry goes to the final Add tab. */
    assert(m.page == SL_HOME && sl_ui_adding_host(&m) && !m.depth &&
           !sl_ui_take_command(&m, &command));
    layout_check(&m);
    assert(m.focus == 31); /* Manual address is the first row. */
    sl_ui_action(&m, SL_ACCEPT, 0);
    assert(m.page == SL_MANUAL && !sl_ui_take_command(&m, &command));
    strcpy(m.input, "10.10.10.166");
    sl_ui_action(&m, SL_SUBMIT, 0);
    assert(sl_ui_take_command(&m, &command) && command.type == SL_CMD_MANUAL &&
           !strcmp(command.text, "10.10.10.166"));
    sl_runtime_event found = {
        .type = SL_EVENT_HOST, .discovery_source = SL_DISCOVERY_LAN, .host = {.client_id = 903}};
    strcpy(found.host.name, "Manual target");
    strcpy(found.host.address, "10.10.10.166");
    sl_ui_runtime_event(&m, &found);
    assert(!sl_ui_adding_host(&m) && m.page == SL_CONNECTING);
    assert(sl_ui_take_command(&m, &command) && command.type == SL_CMD_STREAM &&
           command.host.client_id == 903 && !command.game_id);

    m = model();
    sl_ui_action(&m, SL_DOWN, 0);
    sl_ui_action(&m, SL_ACCEPT, 0); /* Second Add action: cloud code, no target host. */
    assert(m.page == SL_PAIRING && sl_ui_take_command(&m, &command) &&
           command.type == SL_CMD_REMOTE_PAIR && !command.host.id);
    m = model();
    for (int i = 0; i < SL_HOST_LIMIT; ++i)
        add(&m, 100 + i, "Computer");
    sl_ui_action(&m, SL_SELECT_HOST, SL_HOST_LIMIT);
    assert(sl_ui_adding_host(&m) && m.store.registry.count == SL_HOST_LIMIT &&
           m.store.registry.selected >= 0 && m.store.registry.selected < SL_HOST_LIMIT);
    layout_check(&m); /* The Add tab does not consume registry capacity. */
}
static void cached_history_availability(void) {
    sl_ui_model m = model();
    add(&m, 1, "First");
    add(&m, 2, "Second");
    sl_host *h = &m.store.registry.hosts[0];
    h->paired = true;
    h->games[0].id = 123;
    strcpy(h->games[0].name, "First computer's game");
    m.store.registry.hosts[1].games[0].id = 456;
    sl_ui_tick(&m, 20000);
    assert(sl_ui_game_count(&m) == 1);
    assert(!has_label(&m, sl_tr(SL_T_HOST_OFFLINE)) && !has_label(&m, sl_tr(SL_T_SEARCHING_AUTO)));
    bool unavailable_caption = false;
    for (int i = 0; i < m.layout.label_count; ++i)
        if (strstr(m.layout.labels[i].text, sl_tr(SL_T_HOST_UNAVAILABLE_SEARCHING))) {
            unavailable_caption = true;
            assert(m.layout.labels[i].after_previous && m.layout.labels[i].size == 24);
            assert(i && !strcmp(m.layout.labels[i - 1].text, sl_tr(SL_T_RECENT)) &&
                   m.layout.labels[i - 1].y == 236 && m.layout.labels[i - 1].size == 36);
        }
    assert(unavailable_caption);
    const sl_control *card = NULL;
    for (int i = 0; i < m.layout.count; ++i)
        if (m.layout.controls[i].action == SL_RECENT)
            card = &m.layout.controls[i];
    assert(card && card->disabled && !strcmp(card->label, h->games[0].name));
    sl_control unavailable_card = *card;
    assert(!sl_ui_hit(&m.layout, card->x + 100, card->y + 50));
    sl_ui_activate(&m, card->id);
    sl_ui_action(&m, SL_ACCEPT, 0);
    sl_ui_action(&m, SL_START, 0);
    sl_ui_action(&m, SL_RECENT, 0);
    sl_command command;
    assert(!sl_ui_take_command(&m, &command));
    assert(h->paired && h->games[0].id == 123);
    assert(sl_ui_host_source(&m, h) == SL_DISCOVERY_NONE);

    sl_runtime_event found = {
        .type = SL_EVENT_HOST, .host = *h, .discovery_source = SL_DISCOVERY_LAN};
    sl_ui_runtime_event(&m, &found);
    sl_ui_layout(&m);
    for (int i = 0; i < m.layout.count; ++i)
        if (m.layout.controls[i].action == SL_RECENT)
            assert(!m.layout.controls[i].disabled && m.layout.controls[i].x == unavailable_card.x &&
                   m.layout.controls[i].y == unavailable_card.y &&
                   m.layout.controls[i].w == unavailable_card.w &&
                   m.layout.controls[i].h == unavailable_card.h);
    sl_ui_action(&m, SL_ACCEPT, 0);
    assert(sl_ui_take_command(&m, &command) && command.type == SL_CMD_STREAM &&
           command.host.client_id == 1 && command.game_id == 123);

    m.page = SL_HOME;
    h->paired = false;
    sl_ui_layout(&m);
    assert(!sl_ui_game_count(&m) && !has_label(&m, sl_tr(SL_T_RECENT)));
    for (int i = 0; i < m.layout.count; ++i)
        assert(m.layout.controls[i].action != SL_RECENT);
    sl_ui_action(&m, SL_RECENT, 0); /* A cached card cannot bypass authorization. */
    assert(!sl_ui_take_command(&m, &command));
    sl_ui_action(&m, SL_ACCEPT, 0); /* The current page's A shortcut pairs directly. */
    assert(sl_ui_take_command(&m, &command) && command.type == SL_CMD_STREAM &&
           command.host.client_id == 1 && !command.game_id);
}
static void selected_host_status(void) {
    sl_ui_model m = model();
    add(&m, 1, "LAN PC");
    add(&m, 2, "Offline PC");
    add(&m, 3, "Internet PC");
    for (int i = 0; i < 3; ++i) {
        sl_host *h = &m.store.registry.hosts[i];
        h->paired = true;
        h->games[0].id = 100 + i;
        snprintf(h->games[0].name, sizeof(h->games[0].name), "Game %d", i);
        sl_runtime_event found = {.type = SL_EVENT_HOST,
                                  .host = *h,
                                  .discovery_source =
                                      i == 2 ? SL_DISCOVERY_INTERNET : SL_DISCOVERY_LAN};
        sl_ui_runtime_event(&m, &found);
    }
    m.store.registry.hosts[1].observed = false;
    sl_label recent = {0};
    for (int selected = 0; selected < 3; ++selected) {
        sl_ui_action(&m, SL_SELECT_HOST, selected);
        int statuses = 0;
        for (int i = 0; i < m.layout.label_count; ++i) {
            const sl_label *label = &m.layout.labels[i];
            if (label->center_x) {
                ++statuses;
                const sl_control *tab = NULL;
                for (int j = 0; j < m.layout.count; ++j)
                    if (m.layout.controls[j].action == SL_SELECT_HOST &&
                        m.layout.controls[j].arg == selected)
                        tab = &m.layout.controls[j];
                assert(tab && label->center_x == tab->x + tab->w / 2);
                assert(label->muted == (selected == 1));
                assert(!!strstr(label->text, sl_tr(SL_T_INTERNET_CONNECTION)) == (selected == 2));
                if (selected != 2)
                    assert(strstr(label->text, m.store.registry.hosts[selected].address));
            }
            if (!strcmp(label->text, sl_tr(SL_T_RECENT))) {
                if (!selected)
                    recent = *label;
                else
                    assert(label->x == recent.x && label->y == recent.y &&
                           label->size == recent.size);
            }
        }
        assert(statuses == 1);
        assert(sl_ui_host_source(&m, &m.store.registry.hosts[0]) == SL_DISCOVERY_LAN);
        assert(sl_ui_host_source(&m, &m.store.registry.hosts[2]) == SL_DISCOVERY_INTERNET);
        sl_host *h = &m.store.registry.hosts[selected];
        assert(h->games[0].id == (uint64_t)(100 + selected));
    }
    sl_ui_action(&m, SL_SELECT_HOST, 3);
    for (int i = 0; i < m.layout.label_count; ++i)
        assert(!m.layout.labels[i].center_x);
    sl_ui_action(&m, SL_BACK, 0);
    assert(m.page == SL_HOME && !sl_ui_adding_host(&m) && m.store.registry.selected == 2);
}
static void session_end_events(void) {
    sl_ui_model m = model();
    add(&m, 1, "HOST");
    m.store.registry.hosts[0].paired = true;
    sl_ui_action(&m, SL_START, 0);
    sl_ui_connected(&m);
    sl_runtime_event e = {.type = SL_EVENT_STOPPED, .generation = m.generation};
    sl_ui_runtime_event(&m, &e);
    assert(m.page == SL_HOME && !m.streaming);
    sl_ui_connected(&m);
    e.account = 1;
    sl_ui_runtime_event(&m, &e);
    assert(m.page == SL_ERROR && !m.streaming);
    sl_ui_connected(&m);
    e.type = SL_EVENT_FAILURE;
    e.account = 0;
    strcpy(e.text, "等待电脑画面超时");
    sl_ui_runtime_event(&m, &e);
    assert(m.page == SL_ERROR && !strcmp(m.error, e.text));
    assert(!strcmp(m.layout.title, "串流已中断"));
    m.page = SL_HOME;
    sl_ui_action(&m, SL_START, 0);
    e.generation = m.generation;
    sl_ui_runtime_event(&m, &e);
    assert(!strcmp(m.layout.title, "连接未完成"));
    e.type = SL_EVENT_STOPPED; /* lifecycle_facts stops the failed owner */
    sl_ui_runtime_event(&m, &e);
    sl_ui_runtime_event(&m, &e); /* repeated cleanup ACK remains harmless */
    assert(m.page == SL_ERROR && !strcmp(m.error, "等待电脑画面超时"));
    assert(!strcmp(m.layout.title, "连接未完成"));
    sl_ui_action(&m, SL_BACK, 0);
    sl_command cancel;
    assert(sl_ui_take_command(&m, &cancel) && cancel.type == SL_CMD_CANCEL);
    sl_ui_runtime_event(&m, &e); /* old ACK cannot dismiss explicit cancellation */
    assert(m.page == SL_STOPPING);
    e.generation = m.generation;
    sl_ui_runtime_event(&m, &e);
    assert(m.page == SL_HOME);
}
static void carousel(void) {
    sl_ui_model m = model();
    add(&m, 1, "HOST");
    m.store.registry.hosts[0].paired = true;
    for (int i = 0; i < 4; ++i) {
        m.store.registry.hosts[0].games[i].id = 100 + i;
        snprintf(m.store.registry.hosts[0].games[i].name, 128, "Game %d", i);
    }
    sl_ui_layout(&m);
    assert(m.focus == 40 && sl_ui_game_count(&m) == 4);
    assert(sl_ui_hit(&m.layout, 1100, 400) == 42);
    assert(!sl_ui_hit(&m.layout, 1250, 400));
    sl_ui_action(&m, SL_DOWN, 0);
    sl_ui_action(&m, SL_UP, 0);
    assert(m.focus == 40);
    sl_ui_action(&m, SL_RIGHT, 0);
    assert(m.focus == 41 && m.games_target == 0);
    sl_ui_action(&m, SL_RIGHT, 0);
    assert(m.focus == 42 && m.games_target > 0 && m.games_scroll == 0);
    sl_ui_tick(&m, 116);
    assert(m.games_scroll > 0 && m.games_scroll < m.games_target);
    sl_ui_action(&m, SL_RIGHT, 0);
    assert(m.focus == 43 && m.games_target == sl_ui_scroll_limit(&m));
    for (int i = 0; i < 50; ++i)
        sl_ui_tick(&m, m.now + 16);
    assert(m.games_scroll == m.games_target);
    add(&m, 2, "OTHER");
    sl_ui_action(&m, SL_NEXT_HOST, 0);
    assert(m.focus == 0 && m.games_scroll == 0);
    sl_ui_action(&m, SL_PREV_HOST, 0);
    assert(m.focus == 43 && m.games_scroll == sl_ui_scroll_limit(&m));
    sl_ui_action(&m, SL_LEFT, 0);
    assert(m.focus == 42);
    sl_ui_model copy = m;
    sl_input_router r;
    sl_input_init(&r, &copy, NULL, NULL, NULL);
    key(&r, SL_KEY_Y, 1, 2000);
    assert(copy.command.type == SL_CMD_STREAM && copy.command.game_id == 0);
    copy = m;
    sl_ui_action(&copy, SL_ACCEPT, 0);
    assert(copy.command.type == SL_CMD_STREAM && copy.command.game_id == 102);

    m.games_scroll = m.games_target = 0;
    m.focus = 40;
    sl_ui_layout(&m);
    sl_input_init(&r, &m, NULL, NULL, NULL);
    sl_input_event e = {.type = SL_TOUCH_DOWN, .finger = 7, .x = .6f, .y = .55f};
    sl_input_event_handle(&r, &e, 2000);
    e.type = SL_TOUCH_MOVE;
    e.x = .25f;
    sl_input_event_handle(&r, &e, 2100);
    assert(m.games_dragging && m.games_scroll > 400);
    sl_ui_action(&m, SL_LEFT, 0);
    assert(m.games_dragging && m.focus == 40);
    e.type = SL_TOUCH_UP;
    sl_input_event_handle(&r, &e, 2110);
    assert(!m.games_dragging && m.page == SL_HOME && m.command.type == SL_CMD_NONE);
    for (int i = 0; i < 50; ++i)
        sl_ui_tick(&m, m.now + 16);
    assert(m.games_scroll == sl_ui_scroll_limit(&m));
    assert(m.focus == 42);
    tap(&r, 1000, 400);
    assert(m.command.type == SL_CMD_STREAM && m.command.game_id == 103);

    m = copy;
    m.page = SL_HOME;
    m.command.type = SL_CMD_NONE;
    m.games_scroll = m.games_target = 0;
    sl_ui_layout(&m);
    sl_input_init(&r, &m, NULL, NULL, NULL);
    e = (sl_input_event){.type = SL_TOUCH_DOWN, .finger = 7, .x = .3f, .y = .55f};
    sl_input_event_handle(&r, &e, 3000);
    sl_ui_action(&m, SL_NEXT_HOST, 0);
    e.type = SL_TOUCH_UP;
    sl_input_event_handle(&r, &e, 3100);
    assert(m.page == SL_HOME && m.command.type == SL_CMD_NONE);

    sl_ui_action(&m, SL_PREV_HOST, 0);
    m.store.registry.hosts[0].games[3].id = 0;
    sl_ui_layout(&m);
    sl_ui_drag_games(&m, 10000);
    sl_ui_release_games(&m, 0);
    assert(m.games_target == sl_ui_scroll_limit(&m) && m.games_target > 0);
    /* Finger-down during motion brakes without launching on release. */
    m.games_scroll = 0;
    sl_ui_layout(&m);
    sl_input_init(&r, &m, NULL, NULL, NULL);
    tap(&r, 300, 400);
    assert(m.games_target == 0 && m.page == SL_HOME && m.command.type == SL_CMD_NONE);
    e = (sl_input_event){.type = SL_TOUCH_DOWN, .finger = 7, .x = 503.f / 1280, .y = .55f};
    sl_input_event_handle(&r, &e, 4000); /* Gap between cards. */
    e.type = SL_TOUCH_MOVE;
    e.x -= .1f;
    sl_input_event_handle(&r, &e, 4050);
    assert(m.games_dragging);
    sl_input_event second = {.type = SL_TOUCH_DOWN, .finger = 8, .x = .2f, .y = .55f};
    sl_input_event_handle(&r, &second, 4051);
    second.type = SL_TOUCH_UP;
    sl_input_event_handle(&r, &second, 4052);
    assert(m.command.type == SL_CMD_NONE);
    e.type = SL_FOCUS_LOST;
    sl_input_event_handle(&r, &e, 4060);
    assert(!m.games_dragging && m.page == SL_HOME && m.command.type == SL_CMD_NONE);
}

static void overlay_interaction(void) {
    sl_ui_model m = model();
    add(&m, 7, "HOST");
    sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
    sl_ui_tick(&m, 160);
    const sl_control *c = &m.layout.controls[0];
    assert(m.layout.drawer && m.layout.offset_x > 0);
    assert(sl_ui_hit(&m.layout, c->x + m.layout.offset_x + 8, c->y + 8) == c->id);
    assert(sl_ui_hit(&m.layout, c->x + 1, c->y + 8) == 0);
    sl_ui_tick(&m, 320);
    sl_ui_action(&m, SL_OPEN_HOST_SETTINGS, 0);
    sl_ui_action(&m, SL_OPEN_FORGET, 0);
    assert(m.focus == 102); /* A executes the named action; B cancels. */
    sl_ui_tick(&m, 540);
    sl_ui_action(&m, SL_BACK, 0);
    assert(m.leaving && m.page == SL_FORGET);
    sl_ui_activate(&m, 102);
    assert(m.focus == 102);
    assert(m.store.registry.count == 1 && m.command.type == SL_CMD_NONE);
    sl_ui_tick(&m, 699);
    assert(m.page == SL_FORGET);
    sl_ui_tick(&m, 700);
    assert(m.page == SL_HOST_SETTINGS && !m.leaving && m.focus == 100);

    sl_ui_connected(&m);
    sl_ui_action(&m, SL_OPEN_MENU, 0);
    sl_ui_tick(&m, 920);
    sl_input_router input;
    sl_input_init(&input, &m, send_event, reset_remote, NULL);
    sl_input_sync(&input);
    n = 0;
    key(&input, SL_KEY_B, 1, 920);
    assert(m.leaving && !sl_ui_remote(&m));
    key(&input, SL_KEY_A, 1, 950);
    sl_ui_tick(&m, 1079);
    assert(!sl_ui_remote(&m) && n == 0);
    sl_ui_tick(&m, 1080);
    sl_input_sync(&input);
    assert(sl_ui_remote(&m));
    key(&input, SL_KEY_A, 0, 1090);
    key(&input, SL_KEY_B, 0, 1090);
    assert(n == 0); /* Neither closing key leaks into the game. */
    key(&input, SL_KEY_A, 1, 1100);
    key(&input, SL_KEY_A, 0, 1110);
    assert(n == 2);
}
static void wait_screen_cancel_shortcut(void) {
    const sl_page pages[] = {SL_CONNECTING, SL_SAVING, SL_PAIRING};
    for (unsigned i = 0; i < sizeof(pages) / sizeof(pages[0]); ++i) {
        for (int touch = 0; touch < 2; ++touch) {
            sl_ui_model m = model();
            m.page = pages[i];
            sl_ui_tick(&m, 4000);
            m.command.type = SL_CMD_NONE;
            uint64_t generation = m.generation;
            sl_ui_action(&m, SL_DOWN, 0);
            sl_ui_action(&m, SL_ACCEPT, 0);
            assert(m.page == pages[i] && m.generation == generation && !m.command.type);
            if (touch)
                sl_ui_activate(&m, 9);
            else
                sl_ui_action(&m, SL_BACK, 0);
            assert(m.page == SL_STOPPING && m.command.type == SL_CMD_CANCEL);
        }
    }
}
static void confirmation_shortcuts(void) {
    const sl_page pages[] = {SL_FORGET, SL_DISCONNECT, SL_EXIT, SL_ERROR, SL_END_GAME};
    const sl_command_type expected[] = {SL_CMD_SAVE, SL_CMD_STOP, SL_CMD_EXIT, SL_CMD_STREAM,
                                        SL_CMD_END_GAME};
    for (int p = 0; p < 5; ++p) {
        for (int path = 0; path < 4; ++path) {
            sl_ui_model m = model();
            add(&m, 7, "HOST");
            m.intent.host = m.store.registry.hosts[0];
            m.page = pages[p];
            m.streaming = m.page == SL_DISCONNECT || m.page == SL_END_GAME;
            sl_ui_tick(&m, 1000);
            sl_control positive = {0}, cancel = {0};
            for (int i = 0; i < m.layout.count; ++i) {
                if (m.layout.controls[i].primary)
                    positive = m.layout.controls[i];
                else
                    cancel = m.layout.controls[i];
            }
            assert(positive.id && positive.label[0] == 'A' && cancel.label[0] == 'B');
            sl_input_router r;
            sl_input_init(&r, &m, NULL, NULL, NULL);
            /* Directional input cannot turn the advertised A action into cancel. */
            key(&r, SL_KEY_LEFT, 1, 1000);
            key(&r, SL_KEY_LEFT, 0, 1001);
            assert(m.focus == positive.id);
            if (path < 2) {
                key(&r, path == 0 ? SL_KEY_A : SL_KEY_B, 1, 1010);
                key(&r, path == 0 ? SL_KEY_A : SL_KEY_B, 0, 1011);
            } else {
                sl_control c = path == 2 ? positive : cancel;
                tap(&r, c.x + c.w / 2, c.y + c.h / 2);
            }
            sl_command command;
            if (path == 0 || path == 2) {
                assert(sl_ui_take_command(&m, &command) && command.type == expected[p]);
                assert(!sl_ui_take_command(&m, &command));
                if (p == 0)
                    assert(m.store.registry.count == 0);
            } else {
                assert(m.store.registry.count == 1 && !m.closing);
                if (p == 3) {
                    assert(sl_ui_take_command(&m, &command) && command.type == SL_CMD_CANCEL);
                } else {
                    assert(m.leaving && !sl_ui_take_command(&m, &command));
                }
            }
        }
    }
    sl_ui_model m = model();
    sl_ui_error(&m, "网络不可用");
    sl_ui_action(&m, SL_ACCEPT, 0);
    assert(m.page == SL_ERROR && !m.command.type); /* No retry target: B only. */
}
static sl_runtime_event update_event(const sl_ui_model *m, sl_event_type type, bool flag,
                                     const char *text) {
    sl_runtime_event e = {.type = type, .generation = m->generation, .account = flag};
    snprintf(e.text, sizeof(e.text), "%s", text);
    return e;
}
static void update_flow(void) {
    sl_command cmd;
    sl_ui_model m = model();
    assert(m.update_check);

    /* Found while another page is open: offered once back on HOME. */
    sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
    sl_runtime_event found = update_event(&m, SL_EVENT_UPDATE, true, "0.2.2");
    sl_ui_runtime_event(&m, &found);
    sl_ui_tick(&m, m.now + 16);
    assert(m.page == SL_SETTINGS);
    sl_ui_action(&m, SL_BACK, 0);
    sl_ui_tick(&m, m.now + 160);
    sl_ui_tick(&m, m.now + 16);
    assert(m.page == SL_UPDATE && m.layout.count == 2);

    /* A installs; B can't abandon a running install. */
    sl_ui_action(&m, SL_ACCEPT, 0);
    assert(m.page == SL_UPDATING && sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_UPDATE);
    sl_ui_action(&m, SL_BACK, 0);
    sl_ui_tick(&m, m.now + 160);
    assert(m.page == SL_UPDATING);

    /* A failure can be retried. */
    sl_runtime_event failed = update_event(&m, SL_EVENT_UPDATE_RESULT, false, "download failed");
    sl_ui_runtime_event(&m, &failed);
    assert(m.page == SL_UPDATE_RESULT && !strcmp(m.error, "download failed"));
    sl_ui_action(&m, SL_ACCEPT, 0);
    assert(m.page == SL_UPDATING && sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_UPDATE);

    /* After a success, A exits the app. */
    sl_runtime_event done = update_event(&m, SL_EVENT_UPDATE_RESULT, true, "updated");
    sl_ui_runtime_event(&m, &done);
    assert(m.page == SL_UPDATE_RESULT && m.update_succeeded);
    sl_ui_action(&m, SL_ACCEPT, 0);
    assert(m.closing && sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_EXIT);

    /* Cancelled: back on HOME and not offered again. */
    m = model();
    found = update_event(&m, SL_EVENT_UPDATE, false, "0.2.2");
    sl_ui_runtime_event(&m, &found);
    sl_ui_tick(&m, m.now + 16);
    assert(m.page == SL_UPDATE);
    sl_ui_action(&m, SL_BACK, 0);
    sl_ui_tick(&m, m.now + 160);
    sl_ui_tick(&m, m.now + 16);
    sl_ui_tick(&m, m.now + 16);
    assert(m.page == SL_HOME && !sl_ui_take_command(&m, &cmd));

    /* The toggle is saved with every save command, activity ones too. */
    sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
    sl_ui_action(&m, SL_OPEN_APP_SETTINGS, 0);
    sl_ui_action(&m, SL_UPDATE_CHECK, 0);
    assert(!m.update_check && sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_SAVE &&
           !cmd.update_check);
    add(&m, 3, "HOST");
    m.store.registry.hosts[0].paired = true;
    sl_runtime_event activity = {
        .type = SL_EVENT_ACTIVITY, .generation = m.generation, .host = m.store.registry.hosts[0]};
    sl_ui_runtime_event(&m, &activity);
    assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_SAVE && !cmd.update_check);
}
static void settings_category(sl_ui_model *m, sl_action category) {
    while (m->page != SL_SETTINGS) {
        assert(m->depth > 0);
        sl_ui_action(m, SL_BACK, 0);
        sl_ui_tick(m, m->now + 220);
    }
    sl_ui_action(m, category, 0);
}
static void actionable_settings(void) {
    sl_ui_model m = model();
    sl_command command;
    sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
    assert(m.page == SL_SETTINGS && m.depth == 1 && m.layout.count == 5);
    const sl_action categories[] = {SL_OPEN_AV_SETTINGS, SL_OPEN_NETWORK_SETTINGS,
                                    SL_OPEN_HOST_SETTINGS, SL_OPEN_APP_SETTINGS};
    for (int i = 0; i < 4; ++i) {
        assert(m.layout.controls[i].action == categories[i]);
        assert(m.layout.controls[i].kind == SL_CONTROL_SUBMENU);
    }
    settings_category(&m, SL_OPEN_HOST_SETTINGS);
    assert(m.layout.controls[0].kind == SL_CONTROL_SUBMENU);
    assert(m.layout.controls[1].disabled && m.layout.controls[1].kind == SL_CONTROL_ACTION);
    sl_ui_activate(&m, m.layout.controls[1].id);
    assert(m.page == SL_HOST_SETTINGS && !m.command.type);
    sl_ui_action(&m, SL_DOWN, 0);
    assert(m.focus == 9); /* Disabled removal is skipped by the controller. */
    sl_ui_action(&m, SL_UP, 0);
    assert(m.focus == 100);
    sl_ui_action(&m, SL_OPEN_ADD, 0);
    sl_ui_action(&m, SL_OPEN_MANUAL, 0);
    assert(m.page == SL_MANUAL);
    sl_ui_action(&m, SL_BACK, 0);
    sl_ui_tick(&m, m.now + 220);
    assert(m.page == SL_HOME && sl_ui_adding_host(&m));
    sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
    settings_category(&m, SL_OPEN_AV_SETTINGS);
    assert(m.layout.count == 4 && !strcmp(m.layout.controls[0].value, "均衡"));
    assert(m.layout.controls[2].kind == SL_CONTROL_TOGGLE);
    sl_ui_action(&m, SL_SOUND, 0);
    assert(!m.store.sound && sl_ui_take_command(&m, &command) && command.type == SL_CMD_SAVE);
    sl_ui_action(&m, SL_OPEN_QUALITY, 0);
    assert(m.layout.count == 4);
    assert(!strcmp(m.layout.controls[0].label, "均衡"));
    assert(!strcmp(m.layout.controls[1].label, "流畅"));
    assert(!strcmp(m.layout.controls[2].label, "清晰"));
    sl_ui_action(&m, SL_DOWN, 0);
    assert(m.store.quality == 0);
    sl_ui_action(&m, SL_SET_QUALITY, 2);
    assert(m.store.quality == 2 && sl_ui_take_command(&m, &command));
    sl_ui_tick(&m, m.now + 220);
    assert(!strcmp(m.layout.controls[0].value, "清晰"));
    settings_category(&m, SL_OPEN_NETWORK_SETTINGS);
    assert(m.layout.controls[1].kind == SL_CONTROL_TOGGLE);
    assert(m.layout.controls[2].kind == SL_CONTROL_ACTION && m.layout.controls[2].disabled);
    sl_ui_activate(&m, m.layout.controls[2].id);
    assert(m.page == SL_NETWORK_SETTINGS && !m.command.type);
    sl_ui_action(&m, SL_FEC, 0);
    assert(m.store.unreliable_fec && sl_ui_take_command(&m, &command));
    assert(command.type == SL_CMD_SAVE && command.unreliable_fec && m.cue == SL_CUE_TOGGLE);
    sl_ui_action(&m, SL_OPEN_BANDWIDTH, 0);
    sl_ui_action(&m, SL_SET_BANDWIDTH, 20000);
    assert(sl_ui_take_command(&m, &command) && command.type == SL_CMD_SAVE);
    assert(command.bitrate_kbps == 20000 && command.quality == 2);
    sl_ui_tick(&m, m.now + 220);
    assert(!strcmp(m.layout.controls[0].value, "20 Mbps"));
    settings_category(&m, SL_OPEN_APP_SETTINGS);
    assert(m.layout.controls[1].kind == SL_CONTROL_TOGGLE);
    assert(m.layout.controls[2].kind == SL_CONTROL_ACTION);
    sl_ui_action(&m, SL_UPDATE_CHECK, 0);
    assert(!m.update_check && sl_ui_take_command(&m, &command) && m.cue == SL_CUE_TOGGLE);
    sl_ui_connected(&m);
    sl_ui_action(&m, SL_OPEN_MENU, 0);
    assert(m.layout.count == 4 && !strcmp(m.layout.title, "串流"));
    const sl_action session_actions[] = {SL_BACK, SL_OPEN_END_GAME, SL_OPEN_DISCONNECT};
    for (int i = 0; i < 3; ++i) {
        assert(m.layout.controls[i].action == session_actions[i]);
        assert(m.layout.controls[i].kind == SL_CONTROL_ACTION);
    }
    const sl_action blocked[] = {SL_OPEN_SETTINGS,
                                 SL_OPEN_AV_SETTINGS,
                                 SL_OPEN_NETWORK_SETTINGS,
                                 SL_OPEN_HOST_SETTINGS,
                                 SL_OPEN_APP_SETTINGS,
                                 SL_OPEN_GUIDE_KEY,
                                 SL_SET_GUIDE_KEY,
                                 SL_OPEN_QUALITY,
                                 SL_OPEN_RESOLUTION,
                                 SL_OPEN_BANDWIDTH,
                                 SL_OPEN_LANGUAGE,
                                 SL_OPEN_MANUAL,
                                 SL_OPEN_FORGET,
                                 SL_OPEN_SHORTCUT,
                                 SL_SOUND,
                                 SL_FEC,
                                 SL_UPDATE_CHECK,
                                 SL_RUN_NETWORK_TEST};
    for (unsigned i = 0; i < sizeof(blocked) / sizeof(blocked[0]); ++i) {
        sl_ui_action(&m, blocked[i], 0);
        assert(m.page == SL_MENU && m.streaming && !m.command.type);
    }
}

static void explicit_cloud_pairing(void) {
    sl_ui_model m = model();
    sl_command cmd;
    sl_ui_action(&m, SL_START, 0);
    assert(m.page == SL_HOME && !sl_ui_take_command(&m, &cmd));
    sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
    sl_ui_action(&m, SL_OPEN_REMOTE_PAIR, 0);
    assert(m.page == SL_SETTINGS && !sl_ui_take_command(&m, &cmd));
    sl_ui_action(&m, SL_OPEN_ADD, 0);
    sl_ui_action(&m, SL_OPEN_REMOTE_PAIR, 0);
    assert(m.page == SL_PAIRING && sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_REMOTE_PAIR &&
           !cmd.host.id);
    sl_runtime_event code = {.type = SL_EVENT_CODE, .generation = m.generation};
    strcpy(code.text, "1234");
    sl_ui_runtime_event(&m, &code);
    assert(!strcmp(m.pairing_code, "1234"));
    sl_runtime_event authorized = {.type = SL_EVENT_AUTHORIZED,
                                   .generation = m.generation,
                                   .account = 88,
                                   .host = {.client_id = 77, .has_secret = true}};
    strcpy(authorized.host.name, "Steam");
    authorized.host.secret[0] = 7;
    sl_ui_runtime_event(&m, &authorized);
    assert(m.page == SL_HOME && m.store.registry.count == 1 && m.store.registry.hosts[0].paired &&
           !m.store.registry.hosts[0].observed &&
           !sl_ui_take_command(&m, &cmd)); /* Pairing does not auto-start streaming. */
    sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
    sl_ui_action(&m, SL_OPEN_ADD, 0);
    sl_ui_action(&m, SL_OPEN_REMOTE_PAIR, 0);
    assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_REMOTE_PAIR);
    uint64_t generation = m.generation;
    sl_ui_action(&m, SL_BACK, 0);
    sl_ui_tick(&m, m.now + 200);
    assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_CANCEL);
    code.generation = generation;
    sl_ui_runtime_event(&m, &code);
    assert(m.page == SL_STOPPING);
    sl_host_registry older = m.store.registry;
    m.store.registry.hosts[0].secret[0] = 9;
    sl_host_registry_keep_secrets(&older, &m.store.registry);
    assert(older.hosts[0].secret[0] == 9); /* An existing stale key also gets replaced. */
    sl_host cloud = {.client_id = 77};
    sl_host *known = sl_host_observe(&m.store.registry, &cloud, m.now);
    assert(known && m.store.registry.count == 1);
    sl_host direct = {.client_id = 77, .instance_id = 10};
    known = sl_host_observe(&m.store.registry, &direct, m.now);
    assert(known && m.store.registry.count == 1 && known->paired);
    known = sl_host_observe(&m.store.registry, &cloud, m.now);
    assert(known && known->instance_id == 10 && m.store.registry.count == 1);
    direct.instance_id = 11;
    known = sl_host_observe(&m.store.registry, &direct, m.now);
    assert(known && m.store.registry.count == 2 && !known->paired);
}
static void end_game_failure(void) {
    sl_ui_model m = model();
    add(&m, 3, "HOST");
    m.store.registry.hosts[0].paired = true;
    sl_ui_action(&m, SL_START, 0);
    sl_command cmd;
    assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_STREAM);
    sl_ui_connected(&m);
    sl_ui_action(&m, SL_OPEN_END_GAME, 0);
    sl_ui_action(&m, SL_CONFIRM_END_GAME, 0);
    assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_END_GAME);
    sl_ui_action(&m, SL_CONFIRM_END_GAME, 0);
    assert(!sl_ui_take_command(&m, &cmd)); /* repeated confirm is inert */
    assert(m.layout.label_count == 0 && m.layout.count == 1);
    const sl_control *disconnect = &m.layout.controls[0];
    assert(disconnect->x >= m.layout.panel_x && disconnect->y >= m.layout.panel_y);
    assert(disconnect->x + disconnect->w <= m.layout.panel_x + m.layout.panel_w);
    assert(disconnect->y + disconnect->h <= m.layout.panel_y + m.layout.panel_h);
    sl_ui_model waiting = m;
    sl_runtime_event error = {.type = SL_EVENT_FAILURE, .generation = m.generation};
    strcpy(error.text, "End confirmation timed out");
    sl_ui_runtime_event(&m, &error);
    assert(m.page == SL_ERROR && m.ending_game && !m.streaming);
    for (int i = 0; i < m.layout.count; ++i)
        assert(m.layout.controls[i].action != SL_RETRY);
    for (int i = 0; i < 3; ++i) {
        sl_ui_action(&m, SL_ACCEPT, 0);
        sl_ui_action(&m, SL_RETRY, 0); /* direct/stale action is guarded too */
        assert(!sl_ui_take_command(&m, &cmd));
    }
    sl_ui_action(&m, SL_BACK, 0);
    assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_CANCEL);
    sl_ui_runtime_event(&m, &error); /* late failure after cancel */
    assert(m.page == SL_STOPPING && !m.ending_game);
    sl_ui_stopped(&m, false);
    assert(m.page == SL_HOME);
    sl_ui_action(&m, SL_START, 0); /* an explicit new launch remains possible */
    assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_STREAM);

    m = waiting;
    sl_runtime_event stopped = {.type = SL_EVENT_STOPPED, .generation = m.generation};
    sl_ui_runtime_event(&m, &stopped);
    sl_ui_runtime_event(&m, &error); /* completion wins over a queued old error */
    assert(m.page == SL_HOME && !m.ending_game);

    m = waiting;
    sl_ui_action(&m, SL_ACCEPT, 0); /* don't activate B while waiting */
    assert(!sl_ui_take_command(&m, &cmd));
    sl_ui_action(&m, SL_BACK, 0); /* bounded user escape from the longer wait */
    assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_CANCEL);
    sl_ui_runtime_event(&m, &stopped); /* old completion must not end a new operation */
    assert(m.page == SL_STOPPING && !m.ending_game);
}

static void profile_v2_migration(void) {
    disk_store_v2 old = {0};
    char dir[] = "/tmp/nsl-profile-v2-XXXXXX", path[512];
    assert(mkdtemp(dir));
    snprintf(path, sizeof(path), "%s/profile.bin", dir);
    memcpy(old.magic, "NSLUI02", 8);
    old.version = 2;
    old.size = sizeof(old);
    old.data.device_id = 12345;
    memset(old.data.secret, 0x5a, sizeof(old.data.secret));
    strcpy(old.data.device_name, "paired device");
    old.data.registry.count = 1;
    old.data.registry.hosts[0].client_id = 98765;
    old.data.registry.hosts[0].paired = true;
    const uint32_t rates[] = {6000, 4000, 10000};
    for (unsigned q = 0; q < 3; ++q) {
        old.data.quality = q;
        old.checksum = 2166136261u;
        const uint8_t *p = (const void *)&old.data;
        for (size_t i = 0; i < sizeof(old.data); ++i)
            old.checksum = (old.checksum ^ p[i]) * 16777619u;
        FILE *f = fopen(path, "wb");
        assert(f && fwrite(&old, 1, sizeof(old), f) == sizeof(old));
        assert(fclose(f) == 0);
        sl_auth_store s, reload;
        assert(sl_auth_load(&s, dir) == 0);
        assert(s.device_id == 12345 && !memcmp(s.secret, old.data.secret, 32));
        assert(!strcmp(s.device_name, "paired device") && !s.sound);
        assert(s.registry.hosts[0].paired && s.registry.hosts[0].client_id == 98765);
        assert(s.quality == q && s.bitrate_kbps == rates[q]);
        assert(sl_auth_save(&s, dir) && sl_auth_load(&reload, dir) == 0);
        assert(reload.quality == q && reload.bitrate_kbps == rates[q]);
        assert(reload.device_id == s.device_id && reload.registry.hosts[0].paired);
        assert(!reload.registry.hosts[0].has_secret);
    }
    unlink(path);
    rmdir(dir);
}

/* v3 hosts were paired before the key exchange: they keep the installation key. */
static void profile_v3_migration(void) {
    disk_store_v3 old = {0};
    char dir[] = "/tmp/nsl-profile-v3-XXXXXX", path[512];
    assert(mkdtemp(dir));
    snprintf(path, sizeof(path), "%s/profile.bin", dir);
    memcpy(old.magic, "NSLUI03", 8);
    old.version = 3;
    old.size = sizeof(old);
    old.data.device_id = 4242;
    memset(old.data.secret, 0x3c, sizeof(old.data.secret));
    strcpy(old.data.device_name, "v3 device");
    old.data.quality = 1;
    old.data.sound = true;
    old.data.bitrate_kbps = 10000;
    old.data.registry.count = 2;
    old.data.registry.selected = 1;
    old.data.registry.next_id = 3;
    old.data.registry.hosts[0].id = 1;
    old.data.registry.hosts[0].client_id = 111;
    old.data.registry.hosts[0].paired = true;
    old.data.registry.hosts[0].account = 76561198000000001ull;
    strcpy(old.data.registry.hosts[0].name, "first");
    old.data.registry.hosts[0].games[0].id = 570;
    strcpy(old.data.registry.hosts[0].games[0].name, "Dota 2");
    old.data.registry.hosts[1].id = 2;
    old.data.registry.hosts[1].client_id = 222;
    strcpy(old.data.registry.hosts[1].address, "192.168.1.14");
    old.checksum = 2166136261u;
    const uint8_t *p = (const void *)&old.data;
    for (size_t i = 0; i < sizeof(old.data); ++i)
        old.checksum = (old.checksum ^ p[i]) * 16777619u;
    FILE *f = fopen(path, "wb");
    assert(f && fwrite(&old, 1, sizeof(old), f) == sizeof(old));
    assert(fclose(f) == 0);

    sl_auth_store s, reload;
    assert(sl_auth_load(&s, dir) == 0);
    assert(s.device_id == 4242 && !memcmp(s.secret, old.data.secret, 32));
    assert(!strcmp(s.device_name, "v3 device") && s.quality == 1 && s.sound);
    assert(s.bitrate_kbps == 10000 && s.registry.count == 2 && s.registry.next_id == 3);
    const sl_host *first = &s.registry.hosts[0];
    assert(first->id == 1 && first->client_id == 111 && first->paired && !first->has_secret);
    assert(first->account == 76561198000000001ull && !strcmp(first->name, "first"));
    assert(first->games[0].id == 570 && !strcmp(first->games[0].name, "Dota 2"));
    assert(s.registry.hosts[1].client_id == 222 && !s.registry.hosts[1].paired);
    assert(!strcmp(s.registry.hosts[1].address, "192.168.1.14"));

    /* Saved again as v5, a negotiated key survives the round trip. */
    s.registry.hosts[1].paired = true;
    s.registry.hosts[1].has_secret = true;
    memset(s.registry.hosts[1].secret, 0xa5, sizeof(s.registry.hosts[1].secret));
    assert(sl_auth_save(&s, dir) && sl_auth_load(&reload, dir) == 0);
    assert(reload.registry.hosts[1].has_secret && reload.registry.hosts[1].secret[31] == 0xa5);
    assert(!reload.registry.hosts[0].has_secret);
    f = fopen(path, "rb");
    char magic[8];
    assert(f && fread(magic, 1, sizeof(magic), f) == sizeof(magic) && fclose(f) == 0);
    assert(!memcmp(magic, "NSLUI05", 8));
    unlink(path);
    rmdir(dir);
}

static void profile_v4_migration(void) {
    disk_store_v4 old = {0};
    char dir[] = "/tmp/nsl-profile-v4-XXXXXX", path[512];
    assert(mkdtemp(dir));
    snprintf(path, sizeof(path), "%s/profile.bin", dir);
    memcpy(old.magic, "NSLUI04", 8);
    old.version = 4;
    old.size = sizeof(old);
    old.data.device_id = 12345;
    memset(old.data.secret, 0x5a, sizeof(old.data.secret));
    strcpy(old.data.device_name, "v4 paired device");
    old.data.registry.count = 1;
    old.data.registry.hosts[0].id = 1;
    old.data.registry.hosts[0].client_id = 98765;
    old.data.registry.hosts[0].paired = true;
    old.data.registry.hosts[0].has_secret = true;
    memset(old.data.registry.hosts[0].secret, 0xa5, 32);
    old.data.bitrate_kbps = 20000;
    old.data.quality = 2;
    old.data.sound = true;
    old.checksum = 2166136261u;
    const uint8_t *bytes = (const void *)&old.data;
    for (size_t i = 0; i < sizeof(old.data); ++i)
        old.checksum = (old.checksum ^ bytes[i]) * 16777619u;
    FILE *f = fopen(path, "wb");
    assert(f && fwrite(&old, 1, sizeof(old), f) == sizeof(old) && fclose(f) == 0);
    sl_auth_store store, loaded;
    assert(sl_auth_load(&store, dir) == 0 && !store.unreliable_fec);
    for (int enabled = 1; enabled >= 0; --enabled) {
        store.unreliable_fec = enabled;
        assert(sl_auth_save(&store, dir) && sl_auth_load(&loaded, dir) == 0);
        assert(loaded.unreliable_fec == (bool)enabled);
        assert(loaded.device_id == old.data.device_id && loaded.quality == 2 &&
               loaded.bitrate_kbps == 20000 && loaded.sound);
        assert(!memcmp(loaded.secret, old.data.secret, 32));
        assert(loaded.registry.hosts[0].paired && loaded.registry.hosts[0].has_secret &&
               loaded.registry.hosts[0].client_id == 98765);
        assert(!memcmp(loaded.registry.hosts[0].secret, old.data.registry.hosts[0].secret, 32));
    }
    unlink(path);
    rmdir(dir);
}

static void host_secrets(void) {
    sl_host_registry known, snapshot;
    sl_host_registry_init(&known);
    sl_host o = {.client_id = 77, .instance_id = 1};
    strcpy(o.name, "pc");
    sl_host *h = sl_host_observe(&known, &o, 1000);
    assert(h && !h->has_secret);
    h->paired = true;
    h->has_secret = true;
    memset(h->secret, 0x42, sizeof(h->secret));

    /* Rediscovery updates the record without touching the key. */
    o.instance_id = 2;
    assert(sl_host_observe(&known, &o, 60000) == h && h->has_secret && h->secret[0] == 0x42);

    /* A snapshot taken before the pairing finished keeps the negotiated key... */
    snapshot = known;
    snapshot.hosts[0].has_secret = false;
    memset(snapshot.hosts[0].secret, 0, sizeof(snapshot.hosts[0].secret));
    sl_host_registry_keep_secrets(&snapshot, &known);
    assert(snapshot.hosts[0].has_secret && snapshot.hosts[0].secret[0] == 0x42);

    /* ...but not for an unpaired record or another installation behind the same id. */
    snapshot.hosts[0].has_secret = false;
    snapshot.hosts[0].paired = false;
    sl_host_registry_keep_secrets(&snapshot, &known);
    assert(!snapshot.hosts[0].has_secret);
    snapshot.hosts[0].paired = true;
    snapshot.hosts[0].client_id = 78;
    sl_host_registry_keep_secrets(&snapshot, &known);
    assert(!snapshot.hosts[0].has_secret);
}
static void network_test_flow(void) {
    for (unsigned accept = 0; accept < 2; ++accept) {
        sl_ui_model m = model();
        add(&m, 1, "HOST");
        m.store.registry.hosts[0].paired = true;
        sl_ui_action(&m, SL_START, 0);
        sl_command cmd;
        assert(sl_ui_take_command(&m, &cmd));
        uint64_t generation = cmd.generation;
        sl_network_test_view failed = {
            .generation = generation, .revision = 1, .phase = SL_TEST_FAILED};
        strcpy(failed.error, "Couldn't connect to HOST on port 61024.");
        sl_ui_network_test(&m, &failed);
        assert(m.page == SL_ERROR && m.cancel_only_error && !strcmp(m.error, failed.error));
        assert(!strcmp(m.layout.title, sl_tr(SL_T_TEST_FAILED)));
        sl_ui_error(&m, "unrelated queued error");
        assert(m.cancel_only_error && !strcmp(m.error, failed.error));
        layout_check(&m);
        for (int i = 0; i < m.layout.count; ++i)
            assert(m.layout.controls[i].action != SL_RETRY);
        sl_ui_action(&m, SL_RETRY, 0);
        assert(!sl_ui_take_command(&m, &cmd));
        failed.revision++;
        failed.phase = SL_TEST_RUNNING;
        sl_ui_network_test(&m, &failed);
        assert(m.page == SL_ERROR && m.cancel_only_error);
        /* A newer failure from this owner replaces the pending dialog; stale
         * snapshots and unrelated queued errors still cannot dismiss it. */
        failed.revision++;
        failed.phase = SL_TEST_FAILED;
        failed.control_error = true;
        strcpy(failed.error, "New valid control error");
        sl_ui_network_test(&m, &failed);
        assert(m.page == SL_ERROR && m.cancel_only_error && !strcmp(m.error, failed.error));
        assert(!strcmp(m.layout.title, sl_tr(SL_T_CONNECT_FAILED)));
        sl_ui_error(&m, "unrelated queued error");
        assert(!strcmp(m.error, failed.error));
        sl_network_test_view stale = failed;
        strcpy(stale.error, "stale error");
        sl_ui_network_test(&m, &stale);
        assert(!strcmp(m.error, failed.error));
        stale.generation++;
        stale.revision++;
        sl_ui_network_test(&m, &stale);
        assert(!strcmp(m.error, failed.error));
        sl_ui_action(&m, accept ? SL_ACCEPT : SL_BACK, 0);
        assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_CANCEL &&
               cmd.generation > generation && m.page == SL_STOPPING);
        sl_ui_stopped(&m, false);
        assert(m.page == SL_HOME && !m.cancel_only_error);
    }
    for (unsigned manual = 0; manual < 2; ++manual) {
        for (unsigned accept = 0; accept < 2; ++accept) {
            sl_ui_model m = model();
            add(&m, 1, "HOST");
            m.store.registry.hosts[0].paired = true;
            if (manual) {
                sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
                sl_ui_action(&m, SL_OPEN_NETWORK_SETTINGS, 0);
            }
            sl_ui_action(&m, manual ? SL_RUN_NETWORK_TEST : SL_START, 0);
            sl_command cmd;
            assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_STREAM &&
                   cmd.test_only == (bool)manual);
            uint64_t generation = cmd.generation;
            sl_network_test_view view = {.generation = generation,
                                         .revision = 1,
                                         .phase = SL_TEST_REQUESTING,
                                         .test_only = manual};
            sl_ui_network_test(&m, &view);
            assert(m.page == SL_NETWORK_TEST && !m.streaming);
            layout_check(&m);
            sl_ui_action(&m, SL_ACCEPT, 0);
            sl_ui_action(&m, SL_DOWN, 0);
            assert(!sl_ui_take_command(&m, &cmd));
            view.revision++;
            view.phase = SL_TEST_RUNNING;
            view.progress = 50;
            sl_ui_network_test(&m, &view);
            view.revision++;
            view.phase = SL_TEST_RESULT;
            view.recommendation = 1;
            view.mean_ms = 2.5f;
            sl_ui_network_test(&m, &view);
            assert(m.page == SL_NETWORK_RESULT && m.focus == 103);
            layout_check(&m);
            sl_ui_action(&m, accept ? SL_ACCEPT : SL_BACK, 0);
            assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_TEST_CONFIRM &&
                   cmd.generation == generation && cmd.accept_recommendation == (bool)accept);
            assert(m.page == (manual ? SL_STOPPING : SL_CONNECTING));
            /* An unchanged persistent result cannot reopen the acknowledged dialog. */
            sl_ui_network_test(&m, &view);
            assert(m.page == (manual ? SL_STOPPING : SL_CONNECTING));
            if (manual) {
                sl_runtime_event done = {.type = SL_EVENT_STOPPED, .generation = generation};
                sl_ui_runtime_event(&m, &done);
                assert(m.page == SL_NETWORK_SETTINGS && m.depth == 2 && m.stack[0] == SL_HOME &&
                       m.stack[1] == SL_SETTINGS);
            } else {
                view.revision++;
                view.phase = SL_TEST_CONTINUING;
                sl_ui_network_test(&m, &view);
                assert(m.page == SL_CONNECTING);
                sl_runtime_event video = {.type = SL_EVENT_FIRST_FRAME, .generation = generation};
                sl_ui_runtime_event(&m, &video);
                assert(m.page == SL_STREAM);
            }
        }
    }
    sl_ui_model m = model();
    add(&m, 1, "HOST");
    m.store.registry.hosts[0].paired = true;
    sl_ui_action(&m, SL_START, 0);
    sl_command cmd;
    assert(sl_ui_take_command(&m, &cmd));
    sl_network_test_view view = {
        .generation = cmd.generation, .revision = 1, .phase = SL_TEST_RUNNING};
    sl_ui_network_test(&m, &view);
    sl_runtime_event pin = {.type = SL_EVENT_PIN, .generation = cmd.generation};
    sl_ui_runtime_event(&m, &pin);
    assert(m.page == SL_PIN);
    view.revision++;
    sl_ui_network_test(&m, &view);
    assert(m.page == SL_PIN); /* Progress cannot obscure a security PIN or failure. */
    sl_ui_action(&m, SL_DIGIT, '7');
    sl_ui_action(&m, SL_SUBMIT, 0);
    assert(sl_ui_take_command(&m, &cmd) && cmd.security_pin_retry &&
           cmd.generation == view.generation && !strcmp(cmd.text, "7"));
    view.revision++;
    sl_ui_network_test(&m, &view);
    sl_ui_action(&m, SL_BACK, 0);
    assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_CANCEL &&
           cmd.generation > view.generation);
    view.revision++;
    view.phase = SL_TEST_RESULT;
    sl_ui_network_test(&m, &view);
    assert(m.page == SL_STOPPING);

    for (unsigned accept = 0; accept < 2; ++accept) {
        m = model();
        add(&m, 1, "HOST");
        sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
        sl_ui_action(&m, SL_OPEN_NETWORK_SETTINGS, 0);
        sl_ui_action(&m, SL_RUN_NETWORK_TEST, 0);
        assert(sl_ui_take_command(&m, &cmd) && cmd.test_only);
        view = (sl_network_test_view){.generation = cmd.generation, .revision = 1,
                                      .phase = SL_TEST_RESULT, .test_only = true};
        sl_ui_network_test(&m, &view);
        sl_ui_action(&m, accept ? SL_ACCEPT : SL_BACK, 0);
        assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_TEST_CONFIRM);
        assert(m.page == SL_STOPPING);
        view.phase = SL_TEST_FAILED;
        strcpy(view.error, "Later control failure");
        sl_ui_network_test(&m, &view);
        assert(m.page == SL_STOPPING); /* An old revision cannot restore a dialog. */
        ++view.revision;
        sl_ui_network_test(&m, &view);
        assert(m.page == SL_ERROR && m.cancel_only_error);
        sl_ui_action(&m, SL_ACCEPT, 0);
        assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_CANCEL &&
               cmd.generation > view.generation);
        ++view.revision;
        sl_ui_network_test(&m, &view);
        assert(m.page == SL_STOPPING); /* Genuine cancel keeps its generation fence. */
    }

    m = model();
    add(&m, 1, "HOST");
    sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
    sl_ui_action(&m, SL_OPEN_NETWORK_SETTINGS, 0);
    sl_ui_action(&m, SL_RUN_NETWORK_TEST, 0);
    assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_STREAM && cmd.test_only);
    sl_runtime_event prompt = {.type = SL_EVENT_STREAM_AUTHORIZATION, .generation = cmd.generation};
    strcpy(prompt.text, "0042");
    sl_ui_runtime_event(&m, &prompt);
    sl_runtime_event paired = {.type = SL_EVENT_STREAM_RESUMED,
                               .generation = cmd.generation,
                               .account = 1,
                               .host = cmd.host};
    paired.host.paired = true;
    paired.host.account = 12;
    sl_ui_runtime_event(&m, &paired);
    assert(!sl_ui_take_command(&m, &cmd) && m.page == SL_NETWORK_TEST && m.intent.test_only);

    for (unsigned automatic = 0; automatic < 2; ++automatic) {
        m = model();
        sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
        sl_ui_action(&m, SL_OPEN_NETWORK_SETTINGS, 0);
        sl_ui_action(&m, SL_OPEN_BANDWIDTH, 0);
        layout_check(&m);
        sl_ui_action(&m, SL_SET_BANDWIDTH, automatic ? -1 : 0);
        assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_SAVE &&
               m.store.bitrate_kbps == (automatic ? UINT32_MAX : 0));
    }
}
int main(void) {
    discovery_source_evidence();
    add_computer_navigation();
    cached_history_availability();
    selected_host_status();
    network_test_flow();
    update_flow();
    profile_v2_migration();
    profile_v3_migration();
    profile_v4_migration();
    host_secrets();
    end_game_failure();
    carousel();
    session_end_events();
    wait_screen_cancel_shortcut();
    confirmation_shortcuts();
    actionable_settings();
    explicit_cloud_pairing();
    overlay_interaction();
    sl_ui_model m = model();
    sl_input_router r;
    sl_input_init(&r, &m, send_event, reset_remote, NULL);
    sl_command cmd;
    assert(m.store.registry.count == 0);
    assert(!sl_ui_take_command(&m, &cmd));
    tap(&r, 600, 300);
    assert(m.page == SL_HOME);
    assert(!sl_ui_take_command(&m, &cmd));
    add(&m, 1, "DESKTOP-A");
    add(&m, 2, "DESKTOP-A");
    assert(m.store.registry.selected == 0);
    tap(&r, 900, 660);
    assert(m.page == SL_HOME);
    assert(!sl_ui_take_command(&m, &cmd));
    sl_ui_tick(&m, m.now + 160);
    tap(&r, 1140, 660);
    assert(m.page == SL_SETTINGS);
    assert(!sl_ui_take_command(&m, &cmd));
    sl_ui_action(&m, SL_BACK, 0);
    sl_ui_tick(&m, m.now + 160);
    sl_ui_action(&m, SL_NEXT_HOST, 0);
    assert(m.store.registry.selected == 1);
    assert(!sl_ui_take_command(&m, &cmd));
    sl_ui_action(&m, SL_START, 0);
    assert(m.page == SL_CONNECTING);
    assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_STREAM && cmd.host.client_id == 2);
    uint64_t generation = m.generation;
    sl_ui_action(&m, SL_BACK, 0);
    sl_ui_tick(&m, m.now + 160);
    assert(m.generation > generation && m.page == SL_STOPPING);
    assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_CANCEL);
    sl_ui_stopped(&m, false);
    sl_host *h = &m.store.registry.hosts[1];
    h->paired = true;
    h->account = 55;
    sl_game g = {.id = 123};
    strcpy(g.name, "游戏");
    sl_host_activity(h, 54, &g);
    assert(!h->games[0].id);
    sl_host_activity(h, 55, &g);
    assert(h->games[0].id == 123);
    assert(!m.store.registry.hosts[0].games[0].id);
    sl_ui_action(&m, SL_RECENT, 0);
    assert(sl_ui_take_command(&m, &cmd) && cmd.game_id == 123);
    sl_ui_action(&m, SL_BACK, 0);
    sl_ui_tick(&m, m.now + 160);
    sl_ui_take_command(&m, &cmd);
    sl_ui_stopped(&m, false);
    sl_ui_tick(&m, 20000);
    sl_ui_action(&m, SL_START, 0);
    assert(!sl_ui_take_command(&m, &cmd));
    for (int p = SL_HOME; p <= SL_CLOSING; ++p) {
        m.page = (sl_page)p;
        layout_check(&m);
    }
    m = model();
    sl_ui_connected(&m);
    sl_input_init(&r, &m, send_event, reset_remote, NULL);
    n = neutral = 0;
    key(&r, SL_KEY_X, 1, 100);
    assert(n == 1);
    sl_input_tick(&r, 1300);
    assert(m.page == SL_STREAM && !m.debug);
    key(&r, SL_KEY_X, 0, 1301);
    assert(n == 2);
    n = 0;
    key(&r, SL_KEY_MINUS, 1, 1400);
    assert(n == 0);
    sl_input_tick(&r, 1499);
    assert(n == 0);
    sl_input_tick(&r, 1500);
    assert(n == 1 && sent[0].value == 1);
    key(&r, SL_KEY_MINUS, 0, 1520);
    assert(n == 2 && !sent[1].value);
    n = 0;
    key(&r, SL_KEY_MINUS, 1, 2000);
    key(&r, SL_KEY_PLUS, 1, 2050);
    sl_input_tick(&r, 2849);
    assert(m.page == SL_STREAM);
    sl_input_tick(&r, 2850);
    assert(m.page == SL_MENU && n == 0 && neutral == 1);
    key(&r, SL_KEY_MINUS, 0, 2860);
    key(&r, SL_KEY_PLUS, 0, 2860);
    assert(n == 0);
    key(&r, SL_KEY_X, 1, 3000);
    sl_input_tick(&r, 3700);
    key(&r, SL_KEY_X, 0, 3701);
    sl_input_tick(&r, 4100);
    assert(!m.debug && m.page == SL_MENU);
    key(&r, SL_KEY_X, 1, 4200);
    sl_input_tick(&r, 5200);
    sl_ui_tick(&m, m.now + 160);
#if NSL_DIAGNOSTICS
    assert(m.debug && m.page == SL_STREAM);
    sl_input_tick(&r, 7000);
    assert(m.debug);
#else
    assert(!m.debug && m.page == SL_MENU);
    sl_ui_action(&m, SL_BACK, 0);
    sl_ui_tick(&m, m.now + 160);
#endif
    key(&r, SL_KEY_X, 0, 7100);
    assert(n == 0);
    tap(&r, 1180, 50);
    assert(m.page == SL_STREAM && n == 2);
    assert(m.layout.count == 0);
    sl_ui_action(&m, SL_OPEN_MENU, 0);
    sl_input_sync(&r);
    n = 0;
    key(&r, SL_KEY_X, 1, 7200);
    sl_input_tick(&r, 8200);
#if !NSL_DIAGNOSTICS
    assert(!m.debug && m.page == SL_MENU);
    sl_ui_action(&m, SL_DEBUG, 0);
    assert(!m.debug && m.page == SL_MENU);
    sl_ui_action(&m, SL_BACK, 0);
#endif
    sl_ui_tick(&m, m.now + 160);
    assert(!m.debug && m.page == SL_STREAM);
    key(&r, SL_KEY_X, 0, 8210);
    n = 0;
    sl_input_event touch = {.type = SL_TOUCH_DOWN, .finger = 9, .x = .4f, .y = .4f};
    sl_input_event_handle(&r, &touch, 8300);
    assert(n == 1);
    sl_ui_action(&m, SL_OPEN_MENU, 0);
    sl_input_sync(&r);
    assert(n == 2 && sent[1].type == SL_TOUCH_UP);
    touch.type = SL_TOUCH_UP;
    sl_input_event_handle(&r, &touch, 8400);
    assert(n == 2);
    sl_ui_action(&m, SL_BACK, 0);
    sl_ui_tick(&m, m.now + 160);
    sl_input_sync(&r);
    n = 0;
    key(&r, SL_KEY_MINUS, 1, 9000);
    key(&r, SL_KEY_PLUS, 1, 9050);
    key(&r, SL_KEY_PLUS, 0, 9100);
    key(&r, SL_KEY_MINUS, 0, 9200);
    assert(n == 4 && sent[0].code == SL_KEY_MINUS && sent[1].code == SL_KEY_PLUS &&
           sent[2].value == 0 && sent[3].value == 0);
    sl_ui_action(&m, SL_OPEN_MENU, 0);
    sl_input_sync(&r);
    key(&r, SL_KEY_X, 1, 10000);
    sl_input_event lost = {.type = SL_FOCUS_LOST};
    sl_input_event_handle(&r, &lost, 10300);
    sl_input_tick(&r, 12000);
    assert(!m.debug && m.page == SL_MENU);
    /* Late events cannot reconnect a canceled generation. Pair-save retry must
     * retain the new generation when authorization continues into streaming. */
    m = model();
    add(&m, 3, "HOST");
    sl_ui_action(&m, SL_START, 0);
    sl_ui_take_command(&m, &cmd);
    sl_runtime_event late = {
        .type = SL_EVENT_STREAM_RESUMED, .generation = m.generation, .host = m.intent.host};
    late.host.account = 88;
    late.host.paired = true;
    sl_ui_action(&m, SL_BACK, 0);
    sl_ui_tick(&m, m.now + 160);
    sl_ui_take_command(&m, &cmd);
    sl_ui_runtime_event(&m, &late);
    assert(m.page == SL_STOPPING && !m.command.type);
    sl_ui_stopped(&m, false);
    sl_ui_action(&m, SL_START, 0);
    sl_ui_take_command(&m, &cmd);
    sl_ui_error(&m, "无法保存配对");
    sl_ui_action(&m, SL_RETRY, 0);
    assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_STREAM);
    late.generation = m.generation;
    late.host = m.intent.host;
    late.host.account = 88;
    late.host.paired = true;
    sl_ui_runtime_event(&m, &late);
    assert(!sl_ui_take_command(&m, &cmd) && m.intent.host.account == 88);
    sl_runtime_event pin = {.type = SL_EVENT_PIN, .generation = m.generation};
    sl_ui_runtime_event(&m, &pin);
    assert(m.page == SL_PIN);
    sl_ui_action(&m, SL_DIGIT, '2');
    sl_ui_action(&m, SL_SUBMIT, 0);
    assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_STREAM && !strcmp(cmd.text, "2"));
    sl_runtime_event first = {.type = SL_EVENT_FIRST_FRAME, .generation = m.generation - 1};
    sl_ui_runtime_event(&m, &first);
    assert(!m.streaming);
    first.generation = m.generation;
    sl_ui_runtime_event(&m, &first);
    assert(m.streaming);
    /* Authorization is consumed once; neither duplicates nor a refusal after
     * pairing may silently generate another code. */
    sl_ui_model flow = model();
    add(&flow, 4, "PAIR-HOST");
    sl_ui_action(&flow, SL_START, 0);
    assert(sl_ui_take_command(&flow, &cmd) && cmd.type == SL_CMD_STREAM);
    sl_runtime_event code = {.type = SL_EVENT_STREAM_AUTHORIZATION, .generation = flow.generation};
    strcpy(code.text, "1234");
    sl_ui_runtime_event(&flow, &code);
    strcpy(code.text, "5678");
    sl_ui_runtime_event(&flow, &code);
    assert(!strcmp(flow.pairing_code, "1234"));
    assert(!sl_ui_pair_prompt_visible(&flow) && !flow.layout.dialog);
    sl_ui_tick(&flow, flow.pair_code_at + 1799);
    assert(!sl_ui_pair_prompt_visible(&flow));
    sl_ui_tick(&flow, flow.pair_code_at + 1800);
    assert(sl_ui_pair_prompt_visible(&flow) && flow.layout.dialog);
    sl_runtime_event success = {
        .type = SL_EVENT_STREAM_RESUMED, .generation = flow.generation, .host = flow.intent.host};
    success.host.paired = true;
    success.host.account = 88;
    success.host.has_secret = true;
    memset(success.host.secret, 0x17, sizeof(success.host.secret));
    sl_ui_runtime_event(&flow, &success);
    assert(!sl_ui_take_command(&flow, &cmd));
    /* The UI's copy keeps the negotiated key, so its later saves carry it. */
    const sl_host *stored = sl_host_find(&flow.store.registry, flow.intent.host.id);
    assert(stored && stored->has_secret && stored->secret[0] == 0x17);
    assert(flow.intent.host.has_secret && flow.intent.host.secret[31] == 0x17);
    sl_ui_runtime_event(&flow, &success);
    assert(!sl_ui_take_command(&flow, &cmd));
    sl_runtime_event refusal = {
        .type = SL_EVENT_FAILURE, .generation = flow.generation, .account = 1};
    strcpy(refusal.text, "需要重新配对");
    sl_ui_runtime_event(&flow, &refusal);
    assert(flow.page == SL_ERROR && !sl_ui_take_command(&flow, &cmd));
    sl_ui_runtime_event(&flow, &success);
    assert(flow.page == SL_ERROR && !sl_ui_take_command(&flow, &cmd));
    sl_ui_action(&flow, SL_RETRY, 0);
    assert(flow.page == SL_CONNECTING && !flow.pairing_code[0]);
    assert(sl_ui_take_command(&flow, &cmd) && cmd.type == SL_CMD_STREAM);
    /* A centered axis works immediately after opening a stream. Held axes
     * remain neutral across the menu until returning through the deadzone. */
    sl_input_init(&r, &m, send_event, reset_remote, NULL);
    n = 0;
    sl_input_event axis = {.type = SL_AXIS, .code = 0, .value = 24000};
    sl_input_event_handle(&r, &axis, 13000);
    assert(n == 1);
    sl_ui_action(&m, SL_OPEN_MENU, 0);
    sl_input_sync(&r);
    sl_ui_action(&m, SL_BACK, 0);
    sl_ui_tick(&m, m.now + 160);
    sl_input_sync(&r);
    sl_input_event_handle(&r, &axis, 13010);
    assert(n == 1);
    axis.value = 0;
    sl_input_event_handle(&r, &axis, 13020);
    axis.value = 24000;
    sl_input_event_handle(&r, &axis, 13030);
    assert(n == 3);
    /* Alternating X/Y events must not turn one held direction into a burst. */
    m = model();
    sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
    sl_input_init(&r, &m, send_event, reset_remote, NULL);
    axis = (sl_input_event){.type = SL_AXIS, .code = 1, .value = 25000};
    sl_input_event_handle(&r, &axis, 14000);
    int stick_focus = m.focus;
    for (int i = 1; i < 100; ++i) {
        axis.code = 0;
        axis.value = i % 500;
        sl_input_event_handle(&r, &axis, 14000 + i);
        axis.code = 1;
        axis.value = 25000 + i;
        sl_input_event_handle(&r, &axis, 14000 + i);
        assert(m.focus == stick_focus && r.repeat == SL_DOWN && r.repeat_at == 14300);
    }
    sl_input_tick(&r, 14299);
    assert(m.focus == stick_focus);
    sl_input_tick(&r, 14300);
    assert(r.repeat_at == 14460);
    axis.code = 1;
    axis.value = 0;
    sl_input_event_handle(&r, &axis, 14301);
    assert(r.repeat == SL_NONE);
    char dir[] = "/tmp/nsl-auth-test-XXXXXX";
    assert(mkdtemp(dir));
    sl_auth_store s, t;
    assert(sl_auth_load(&s, dir) == 1);
    assert(s.device_id && s.bitrate_kbps == 6000 && !s.unreliable_fec);
    assert(sl_auth_load(&t, dir) == 0);
    assert(s.device_id == t.device_id && !memcmp(s.secret, t.secret, 32));
    s.quality = 2;
    s.bitrate_kbps = 20000;
    s.unreliable_fec = true;
    assert(sl_auth_save(&s, dir));
    assert(sl_auth_load(&t, dir) == 0 && t.quality == 2 && t.bitrate_kbps == 20000 &&
           t.unreliable_fec);
    no_replace = true;
    s.quality = 1;
    assert(sl_auth_save(&s, dir));
    assert(sl_auth_load(&t, dir) == 0 && t.quality == 1);
    fail_publish = true;
    s.quality = 2;
    assert(!sl_auth_save(&s, dir));
    assert(sl_auth_load(&t, dir) == 0 && t.quality == 1);
    fail_publish = false;
    assert(sl_auth_save(&s, dir));
    no_replace = false;
    char primary[512], backup[512];
    snprintf(primary, sizeof(primary), "%s/profile.bin", dir);
    snprintf(backup, sizeof(backup), "%s/profile.bak", dir);
    assert(rename(primary, backup) == 0); /* interrupted before publication */
    assert(sl_auth_load(&t, dir) == 0 && t.quality == 2 && t.bitrate_kbps == 20000 &&
           t.unreliable_fec);
    assert(access(primary, F_OK) == 0);
    /* A failed temporary write must preserve the previous valid profile. */
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s/profile.tmp", dir);
    assert(mkdir(tmp, 0700) == 0);
    s.quality = 1;
    assert(!sl_auth_save(&s, dir));
    assert(sl_auth_load(&t, dir) == 0 && t.quality == 2 && t.bitrate_kbps == 20000 &&
           t.unreliable_fec);
    assert(rmdir(tmp) == 0);
    char path[512];
    snprintf(path, sizeof(path), "%s/profile.bin", dir);
    FILE *f = fopen(path, "r+b");
    assert(f);
    fputc('X', f);
    fclose(f);
    assert(sl_auth_load(&t, dir) == -2);
    unlink(path);
    /* The exact packed v1 format preserves device identity, never grants
     * its account to an unrelated discovered computer. */
    struct __attribute__((packed)) {
        char magic[8];
        uint32_t version, size;
        uint64_t device_id;
        uint8_t secret[32];
        char name[64];
        uint64_t steam_id;
        char hostname[64];
        uint8_t ip[4];
        uint16_t port;
        uint8_t reserved[30];
    } old = {0};
    memcpy(old.magic, "NSLAUTH", 8);
    old.version = 1;
    old.size = sizeof(old);
    old.device_id = 12345;
    memset(old.secret, 42, 32);
    strcpy(old.name, "Existing Switch");
    old.steam_id = 999;
    strcpy(old.hostname, "OLD-PC");
    old.ip[0] = 192;
    old.ip[1] = 168;
    old.ip[2] = 1;
    old.ip[3] = 24;
    snprintf(path, sizeof(path), "%s/auth.bin", dir);
    f = fopen(path, "wb");
    assert(f);
    assert(fwrite(&old, 1, sizeof(old), f) == sizeof(old));
    fclose(f);
    assert(sl_auth_load(&t, dir) == 1);
    assert(t.device_id == old.device_id && !memcmp(t.secret, old.secret, 32));
    assert(!strcmp(t.device_name, old.name) && t.registry.count == 0);
    assert(sl_auth_load(&s, dir) == 0 && s.device_id == old.device_id);
    char hint[64];
    assert(sl_auth_discovery_hint(&s, dir, hint, sizeof(hint)) && !strcmp(hint, "192.168.1.24"));
    s.device_id++;
    assert(!sl_auth_discovery_hint(&s, dir, hint, sizeof(hint)));
    unlink(path);
    snprintf(path, sizeof(path), "%s/profile.bin", dir);
    unlink(path);
    rmdir(dir);
    sl_command shortcut_cmd;
    /* HOME install has fixed A/B actions and cannot be cancelled halfway through. */
    sl_ui_init(&m, &s);
    m.now = 5000;
    sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
    sl_ui_action(&m, SL_OPEN_APP_SETTINGS, 0);
    sl_ui_action(&m, SL_OPEN_SHORTCUT, 0);
    assert(m.page == SL_SHORTCUT);
    m.focus = 9;
    sl_ui_action(&m, SL_LEFT, 0);
    sl_ui_action(&m, SL_ACCEPT, 0);
    assert(m.page == SL_INSTALLING);
    assert(sl_ui_take_command(&m, &shortcut_cmd) && shortcut_cmd.type == SL_CMD_SHORTCUT);
    sl_ui_action(&m, SL_ACCEPT, 0);
    sl_ui_action(&m, SL_BACK, 0);
    assert(m.page == SL_INSTALLING && !m.leaving && m.layout.count == 0);
    sl_runtime_event installed = {.type = SL_EVENT_SHORTCUT, .generation = m.generation - 1};
    sl_ui_runtime_event(&m, &installed);
    assert(m.page == SL_INSTALLING);
    installed.generation = m.generation;
    strcpy(installed.text, "Added");
    sl_ui_runtime_event(&m, &installed);
    assert(m.page == SL_INSTALL_RESULT);
    sl_ui_action(&m, SL_BACK, 0);
    sl_ui_tick(&m, m.now + 200);
    assert(m.page == SL_APP_SETTINGS);
    puts("PASS model, touch ownership, controller commands, hotkey timing, debug, host/account "
         "isolation, expiry, layouts and atomic storage");
    return 0;
}
