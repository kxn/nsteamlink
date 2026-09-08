#include "input/input_router.h"
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
        assert(c->x >= 0 && c->y >= 0 && c->x + c->w <= 1280 && c->y + c->h <= 720);
        for (int j = 0; j < i; ++j) {
            sl_control *d = &m->layout.controls[j];
            assert(c->id != d->id);
            assert(c->x >= d->x + d->w || d->x >= c->x + c->w || c->y >= d->y + d->h ||
                   d->y >= c->y + c->h);
        }
    }
}
int main(void) {
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
    assert(m.page == SL_INFO);
    assert(!sl_ui_take_command(&m, &cmd));
    sl_ui_action(&m, SL_BACK, 0);
    tap(&r, 1140, 660);
    assert(m.page == SL_OPTIONS);
    assert(!sl_ui_take_command(&m, &cmd));
    sl_ui_action(&m, SL_BACK, 0);
    sl_ui_action(&m, SL_NEXT_HOST, 0);
    assert(m.store.registry.selected == 1);
    assert(!sl_ui_take_command(&m, &cmd));
    sl_ui_action(&m, SL_START, 0);
    assert(m.page == SL_PAIRING);
    assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_PAIR && cmd.host.client_id == 2);
    uint64_t generation = m.generation;
    sl_ui_action(&m, SL_BACK, 0);
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
    assert(m.debug && m.page == SL_STREAM);
    sl_input_tick(&r, 7000);
    assert(m.debug);
    key(&r, SL_KEY_X, 0, 7100);
    assert(n == 0);
    tap(&r, 1180, 50);
    assert(m.page == SL_MENU);
    assert(n == 0);
    key(&r, SL_KEY_X, 1, 7200);
    sl_input_tick(&r, 8200);
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
    sl_runtime_event late = {.type = SL_EVENT_AUTHORIZED,
                             .generation = m.generation,
                             .account = 88,
                             .host = m.intent.host};
    sl_ui_action(&m, SL_BACK, 0);
    sl_ui_take_command(&m, &cmd);
    sl_ui_runtime_event(&m, &late);
    assert(m.page == SL_STOPPING && !m.command.type);
    sl_ui_stopped(&m, false);
    sl_ui_action(&m, SL_START, 0);
    sl_ui_take_command(&m, &cmd);
    sl_ui_error(&m, "无法保存配对");
    sl_ui_action(&m, SL_RETRY, 0);
    assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_PAIR);
    late.generation = m.generation;
    late.host = m.intent.host;
    sl_ui_runtime_event(&m, &late);
    assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_STREAM &&
           cmd.generation == m.generation && cmd.host.account == 88);
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
    assert(flow.repair_attempted);
    assert(sl_ui_take_command(&flow, &cmd) && cmd.type == SL_CMD_PAIR);
    sl_runtime_event code = {.type = SL_EVENT_CODE, .generation = flow.generation};
    strcpy(code.text, "1234");
    sl_ui_runtime_event(&flow, &code);
    strcpy(code.text, "5678");
    sl_ui_runtime_event(&flow, &code);
    assert(!strcmp(flow.pairing_code, "1234"));
    sl_runtime_event success = {.type = SL_EVENT_AUTHORIZED,
                                .generation = flow.generation,
                                .host = flow.intent.host,
                                .account = 88};
    sl_ui_runtime_event(&flow, &success);
    assert(sl_ui_take_command(&flow, &cmd) && cmd.type == SL_CMD_STREAM);
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
    assert(flow.page == SL_PAIRING && !flow.pairing_code[0]);
    assert(sl_ui_take_command(&flow, &cmd) && cmd.type == SL_CMD_PAIR);
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
    sl_ui_action(&m, SL_OPEN_OPTIONS, 0);
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
    assert(s.device_id);
    assert(sl_auth_load(&t, dir) == 0);
    assert(s.device_id == t.device_id && !memcmp(s.secret, t.secret, 32));
    s.quality = 2;
    assert(sl_auth_save(&s, dir));
    assert(sl_auth_load(&t, dir) == 0 && t.quality == 2);
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
    assert(sl_auth_load(&t, dir) == 0 && t.quality == 2);
    assert(access(primary, F_OK) == 0);
    /* A failed temporary write must preserve the previous valid profile. */
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s/profile.tmp", dir);
    assert(mkdir(tmp, 0700) == 0);
    s.quality = 1;
    assert(!sl_auth_save(&s, dir));
    assert(sl_auth_load(&t, dir) == 0 && t.quality == 2);
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
    puts("PASS model, touch ownership, controller commands, hotkey timing, debug, host/account "
         "isolation, expiry, layouts and atomic storage");
    return 0;
}
