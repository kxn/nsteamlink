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
static void storage(void) {
    char dir[] = "/tmp/nsl-capture-XXXXXX", path[512], backup[512];
    assert(mkdtemp(dir));
    snprintf(path, sizeof(path), "%s/special.conf", dir);
    snprintf(backup, sizeof(backup), "%s/special.bak", dir);
    assert(sl_special_settings_load(dir)); /* Migration from profiles before this feature. */
    for (unsigned pass = 0; pass < 2; ++pass) {
        no_replace = pass != 0;
        assert(sl_special_settings_save(dir, false) && !sl_special_settings_load(dir));
        assert(sl_special_settings_save(dir, true) && sl_special_settings_load(dir));
        assert(sl_special_settings_save(dir, false) && !sl_special_settings_load(dir));
    }
    fail_publish = true;
    assert(!sl_special_settings_save(dir, true) && !sl_special_settings_load(dir));
    fail_publish = no_replace = false;
    assert(!rename(path, backup) && !sl_special_settings_load(dir));
    assert(sl_special_settings_save(dir, true) && sl_special_settings_load(dir));
    const char *invalid[] = {"", "version=2\ncapture_guide=1\n", "capture_guide=1\n",
                             "version=1\ncapture_guide=1\ntrailing"};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(*invalid); ++i) {
        FILE *f = fopen(path, "wb");
        assert(f && fputs(invalid[i], f) >= 0 && !fclose(f));
        assert(!sl_special_settings_load(dir)); /* Unknown/corrupt config preserves screenshots. */
    }
    assert(!unlink(path) && !rmdir(dir));
}
static void settings(void) {
    for (unsigned language = SL_LANG_ZH_CN; language <= SL_LANG_EN; ++language) {
        sl_i18n_set(language);
        sl_ui_model m;
        sl_ui_init(&m, &(sl_auth_store){0});
        sl_ui_action(&m, SL_CAPTURE_GUIDE, 0);
        assert(m.capture_guide && !m.command.type);
        sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
        assert(m.layout.count == 6 && m.layout.controls[4].action == SL_OPEN_SPECIAL_SETTINGS);
        assert(m.layout.controls[4].kind == SL_CONTROL_SUBMENU);
        assert(m.layout.controls[4].y + m.layout.controls[4].h <= m.layout.controls[5].y);
        sl_ui_activate(&m, m.layout.controls[4].id);
        assert(m.page == SL_SPECIAL_SETTINGS && m.layout.drawer && m.layout.count == 2);
        assert(m.layout.controls[0].action == SL_CAPTURE_GUIDE &&
               m.layout.controls[0].kind == SL_CONTROL_TOGGLE);
        assert(!strcmp(m.layout.title, sl_tr(SL_T_SPECIAL_SETTINGS)));
        sl_ui_activate(&m, m.layout.controls[0].id);
        sl_command c;
        assert(!m.capture_guide && sl_ui_take_command(&m, &c) && c.type == SL_CMD_SAVE &&
               !c.capture_guide && m.cue == SL_CUE_TOGGLE);
        sl_runtime_event activity = {.type = SL_EVENT_ACTIVITY, .generation = m.generation};
        sl_ui_runtime_event(&m, &activity);
        assert(sl_ui_take_command(&m, &c) && !c.capture_guide); /* Unrelated saves retain OFF. */
        sl_ui_action(&m, SL_CAPTURE_GUIDE, 0);
        assert(m.capture_guide && sl_ui_take_command(&m, &c) && c.capture_guide);
        sl_ui_connected(&m);
        sl_ui_action(&m, SL_CAPTURE_GUIDE, 0);
        assert(m.capture_guide && !m.command.type); /* Settings never mutate mid-stream. */
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
    puts("PASS Capture settings migration, OFF persistence, separate drawer, and admitted pulses");
}
