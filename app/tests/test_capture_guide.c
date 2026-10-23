#include "input/guide_pulse.h"
#include "services/special_settings.h"
#include "ui/ui_events.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool no_replace, fail_publish;
int __real_rename(const char *, const char *);
int __wrap_rename(const char *from, const char *to) {
    if (no_replace && !access(to, F_OK)) {
        errno = EEXIST;
        return -1;
    }
    if (fail_publish && strstr(from, "special.tmp")) {
        errno = EIO;
        return -1;
    }
    return __real_rename(from, to);
}
static void write_setting(const char *path, const char *text) {
    FILE *f = fopen(path, "wb");
    assert(f && fputs(text, f) >= 0 && !fclose(f));
}
static void check_v2(const char *path, sl_guide_key key) {
    char text[64] = {0};
    FILE *f = fopen(path, "rb");
    assert(f && fread(text, 1, sizeof(text) - 1, f) > 0 && !ferror(f) && !fclose(f));
    assert(!strcmp(text, key == SL_GUIDE_KEY_CAPTURE ? "version=2\nguide_key=capture\n"
                                                    : "version=2\nguide_key=off\n"));
}
static void storage(void) {
    char dir[] = "/tmp/nsl-capture-XXXXXX", path[512], backup[512];
    assert(mkdtemp(dir));
    snprintf(path, sizeof(path), "%s/special.conf", dir);
    snprintf(backup, sizeof(backup), "%s/special.bak", dir);
    assert(sl_special_settings_load(dir) == SL_GUIDE_KEY_CAPTURE); /* Pre-feature install. */
    const sl_guide_key choices[] = {SL_GUIDE_KEY_OFF, SL_GUIDE_KEY_CAPTURE};
    for (unsigned i = 0; i < 2; ++i) {
        write_setting(path, i ? "version=1\ncapture_guide=1\n" : "version=1\ncapture_guide=0\n");
        assert(sl_special_settings_load(dir) == choices[i]);
        assert(sl_special_settings_save(dir, sl_special_settings_load(dir)));
        check_v2(path, choices[i]); /* Migration preserves either preference and writes v2. */
    }
    for (unsigned pass = 0; pass < 2; ++pass) {
        no_replace = pass != 0;
        for (unsigned i = 0; i < 2; ++i) {
            assert(sl_special_settings_save(dir, choices[i]));
            assert(sl_special_settings_load(dir) == choices[i]);
            check_v2(path, choices[i]);
        }
        assert(sl_special_settings_save(dir, SL_GUIDE_KEY_OFF));
    }
    assert(!sl_special_settings_save(dir, (sl_guide_key)2));
    assert(!sl_special_settings_save(dir, (sl_guide_key)-1));
    assert(sl_special_settings_load(dir) == SL_GUIDE_KEY_OFF);
    fail_publish = true;
    assert(!sl_special_settings_save(dir, SL_GUIDE_KEY_CAPTURE));
    assert(sl_special_settings_load(dir) == SL_GUIDE_KEY_OFF);
    fail_publish = no_replace = false;
    assert(!rename(path, backup) && sl_special_settings_load(dir) == SL_GUIDE_KEY_OFF);
    assert(sl_special_settings_save(dir, SL_GUIDE_KEY_CAPTURE));
    assert(sl_special_settings_load(dir) == SL_GUIDE_KEY_CAPTURE);
    const char *invalid[] = {"", "version=3\nguide_key=capture\n", "version=2\ncapture_guide=1\n",
                             "capture_guide=1\n", "version=1\ncapture_guide=1\ntrailing",
                             "version=1\ncapture_guide=2\n", "version=2\nguide_key=home\n",
                             "version=2\nguide_key=capture\ntrailing"};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(*invalid); ++i) {
        write_setting(path, invalid[i]);
        assert(sl_special_settings_load(dir) == SL_GUIDE_KEY_OFF);
    }
    assert(!unlink(path) && !rmdir(dir));
}
static void settings(void) {
    for (unsigned language = SL_LANG_ZH_CN; language <= SL_LANG_EN; ++language) {
        sl_i18n_set(language);
        sl_ui_model m;
        sl_ui_init(&m, &(sl_auth_store){0});
        sl_ui_action(&m, SL_SET_GUIDE_KEY, SL_GUIDE_KEY_OFF);
        assert(m.guide_key == SL_GUIDE_KEY_CAPTURE && !m.command.type);
        sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
        assert(m.layout.count == 5); /* Only the original four categories plus Back. */
        sl_ui_action(&m, SL_OPEN_GUIDE_KEY, 0);
        assert(m.page == SL_SETTINGS); /* Guide source is under Application, not a category. */
        sl_ui_action(&m, SL_OPEN_APP_SETTINGS, 0);
        assert(m.layout.count == 5 && m.layout.controls[3].action == SL_OPEN_GUIDE_KEY);
        assert(m.layout.controls[3].kind == SL_CONTROL_SUBMENU);
        assert(!strcmp(m.layout.controls[3].label, sl_tr(SL_T_GUIDE_KEY)));
        assert(!strcmp(m.layout.controls[3].value, sl_tr(SL_T_GUIDE_KEY_CAPTURE)));
        assert(m.layout.controls[3].y + m.layout.controls[3].h <= m.layout.controls[4].y);
        sl_ui_activate(&m, m.layout.controls[3].id);
        assert(m.page == SL_GUIDE_KEY && m.layout.drawer && m.layout.count == 3 && m.focus == 101);
        assert(!strcmp(m.layout.title, sl_tr(SL_T_GUIDE_KEY)));
        for (unsigned i = 0; i < 2; ++i) {
            assert(m.layout.controls[i].action == SL_SET_GUIDE_KEY &&
                   m.layout.controls[i].kind == SL_CONTROL_RADIO &&
                   m.layout.controls[i].arg == (int)i);
        }
        assert(!strcmp(m.layout.controls[0].label, sl_tr(SL_T_GUIDE_KEY_OFF)));
        assert(!strcmp(m.layout.controls[1].label, sl_tr(SL_T_GUIDE_KEY_CAPTURE)));
        sl_ui_action(&m, SL_SET_GUIDE_KEY, 2); /* HOME is neither valid nor displayed. */
        assert(m.guide_key == SL_GUIDE_KEY_CAPTURE && !m.command.type);
        sl_ui_activate(&m, m.layout.controls[0].id);
        sl_command c;
        assert(m.guide_key == SL_GUIDE_KEY_OFF && sl_ui_take_command(&m, &c) &&
               c.type == SL_CMD_SAVE && c.guide_key == SL_GUIDE_KEY_OFF);
        sl_ui_tick(&m, m.now + 300);
        assert(m.page == SL_APP_SETTINGS && m.focus == 103);
        assert(!strcmp(m.layout.controls[3].value, sl_tr(SL_T_GUIDE_KEY_OFF)));
        sl_runtime_event activity = {.type = SL_EVENT_ACTIVITY, .generation = m.generation};
        sl_ui_runtime_event(&m, &activity);
        assert(sl_ui_take_command(&m, &c) && c.guide_key == SL_GUIDE_KEY_OFF);
        sl_ui_action(&m, SL_OPEN_GUIDE_KEY, 0);
        assert(m.focus == 100);
        sl_ui_action(&m, SL_SET_GUIDE_KEY, SL_GUIDE_KEY_CAPTURE);
        assert(m.guide_key == SL_GUIDE_KEY_CAPTURE && sl_ui_take_command(&m, &c) &&
               c.guide_key == SL_GUIDE_KEY_CAPTURE);
        sl_ui_tick(&m, m.now + 300);
        sl_ui_connected(&m);
        sl_ui_action(&m, SL_SET_GUIDE_KEY, SL_GUIDE_KEY_OFF);
        assert(m.guide_key == SL_GUIDE_KEY_CAPTURE && !m.command.type);
    }
}
typedef struct { unsigned calls, downs, ups; bool accept; } sink;
static bool submit(void *context, bool down) {
    sink *s = context;
    ++s->calls;
    if (down) ++s->downs; else ++s->ups;
    return s->accept;
}
static void pulses(void) {
    sl_guide_pulse p = {0};
    sink s = {.accept = true};
    sl_guide_pulse_tick(&p, false, true, 0, submit, &s);
    assert(!s.calls);
    sl_guide_pulse_tick(&p, true, true, 10, submit, &s);
    assert(s.downs == 1 && !s.ups && p.admitted);
    sl_guide_pulse_tick(&p, true, true, 11, submit, &s);
    assert(s.calls == 1); /* Burst notifications coalesce instead of holding/restarting. */
    sl_guide_pulse_tick(&p, true, false, 60, submit, &s);
    assert(s.ups == 1 && !p.held && !p.releasing);
    s = (sink){0};
    sl_guide_pulse_tick(&p, true, true, 100, submit, &s);
    assert(p.held && !p.admitted && s.downs == 1);
    sl_guide_pulse_tick(&p, true, false, 151, submit, &s);
    assert(!p.admitted && !s.ups); /* Time alone never certifies a failed press. */
    sl_guide_pulse_tick(&p, true, false, 350, submit, &s);
    assert(!p.held && p.releasing && s.ups == 1); /* Bounded cancellation. */
    s.accept = true;
    sl_guide_pulse_tick(&p, true, true, 370, submit, &s);
    assert(!p.releasing && s.downs == 2 && s.ups == 2); /* Release retries before any new pulse. */
    sl_guide_pulse_tick(&p, true, true, 400, submit, &s);
    sl_guide_pulse_tick(&p, false, true, 401, submit, &s);
    assert(s.ups == 3 && !p.held); /* Menu/focus/gate cancellation is immediate. */
}
int main(void) {
    storage();
    settings();
    pulses();
    puts("PASS Guide source v1/v2 migration, OFF persistence, Application radio selection, and admitted pulses");
}
