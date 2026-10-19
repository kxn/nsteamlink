#include "services/video_settings.h"
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
    if (fail_publish && strstr(from, "video.tmp") && access(to, F_OK)) {
        errno = EIO;
        return -1;
    }
    return __real_rename(from, to);
}
static void storage(void) {
    char dir[] = "/tmp/nsl-resolution-XXXXXX";
    assert(mkdtemp(dir));
    assert(sl_video_settings_load(dir) == SL_RESOLUTION_AUTO);
    const sl_resolution modes[] = {SL_RESOLUTION_1080, SL_RESOLUTION_720, SL_RESOLUTION_AUTO};
    for (unsigned pass = 0; pass < 2; ++pass) {
        no_replace = pass != 0;
        for (unsigned i = 0; i < 3; ++i) {
            assert(sl_video_settings_save(dir, modes[i]));
            assert(sl_video_settings_load(dir) == modes[i]);
        }
    }
    assert(sl_video_settings_save(dir, SL_RESOLUTION_1080));
    assert(!sl_video_settings_save(dir, (sl_resolution)1440));
    fail_publish = true;
    assert(!sl_video_settings_save(dir, SL_RESOLUTION_720));
    assert(sl_video_settings_load(dir) == SL_RESOLUTION_1080);
    fail_publish = no_replace = false;
    char path[512], backup[512];
    snprintf(path, sizeof(path), "%s/video.conf", dir);
    snprintf(backup, sizeof(backup), "%s/video.bak", dir);
    assert(!rename(path, backup));
    assert(sl_video_settings_load(dir) == SL_RESOLUTION_1080);
    assert(sl_video_settings_save(dir, SL_RESOLUTION_720));
    assert(sl_video_settings_load(dir) == SL_RESOLUTION_720);
    FILE *f = fopen(path, "wb");
    assert(f && fputs("resolution=1080\ntrailing", f) >= 0 && !fclose(f));
    assert(sl_video_settings_load(dir) == SL_RESOLUTION_AUTO);
    assert(!unlink(path) && !rmdir(dir));
}
/* All settings drawers keep options separate from the fixed Back row. */
static void drawer(const sl_ui_model *m) {
    const sl_layout *l = &m->layout;
    assert(l->drawer && l->label_count == 0);
    for (int i = 0; i < l->count; ++i) {
        const sl_control *c = &l->controls[i];
        assert(c->x >= l->panel_x && c->y >= 136 && c->h >= 64);
        assert(c->x + c->w <= l->panel_x + l->panel_w);
        assert(c->y + c->h <= 720);
        for (int j = i + 1; j < l->count; ++j) {
            const sl_control *other = &l->controls[j];
            assert(c->y + c->h <= other->y || other->y + other->h <= c->y);
        }
    }
}
static void ui(void) {
    for (unsigned language = SL_LANG_ZH_CN; language <= SL_LANG_EN; ++language) {
        sl_i18n_set(language);
        sl_ui_model m;
        sl_ui_init(&m, &(sl_auth_store){.sound = true});
        sl_ui_action(&m, SL_SET_RESOLUTION, 1080);
        assert(m.resolution == SL_RESOLUTION_AUTO && !m.command.type);
        sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
        drawer(&m);
        sl_ui_action(&m, SL_OPEN_AV_SETTINGS, 0);
        drawer(&m);
        assert(m.layout.controls[0].action == SL_OPEN_QUALITY);
        assert(m.layout.controls[1].action == SL_OPEN_RESOLUTION);
        sl_ui_action(&m, SL_OPEN_QUALITY, 0);
        drawer(&m);
        assert(m.layout.count == 4);
        sl_ui_action(&m, SL_OPEN_RESOLUTION, 0);
        assert(m.page == SL_QUALITY);
        sl_ui_action(&m, SL_BACK, 0);
        sl_ui_tick(&m, m.now + 300);
        m.focus = 101;
        sl_ui_action(&m, SL_ACCEPT, 0);
        drawer(&m);
        assert(m.page == SL_RESOLUTION && m.focus == 100);
        sl_ui_action(&m, SL_SET_RESOLUTION, 1440);
        assert(!m.command.type && m.resolution == SL_RESOLUTION_AUTO);
        sl_ui_action(&m, SL_DOWN, 0);
        sl_ui_action(&m, SL_DOWN, 0);
        sl_ui_action(&m, SL_ACCEPT, 0);
        sl_command command;
        assert(sl_ui_take_command(&m, &command) && command.type == SL_CMD_SAVE &&
               command.resolution == SL_RESOLUTION_1080);
        sl_ui_tick(&m, m.now + 300);
        assert(m.page == SL_AV_SETTINGS && m.focus == 101);
        assert(!strcmp(m.layout.controls[1].value, "1080p"));
        sl_ui_action(&m, SL_OPEN_RESOLUTION, 0);
        assert(m.focus == 102);
        sl_ui_connected(&m);
        sl_ui_action(&m, SL_OPEN_MENU, 0);
        sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
        sl_ui_action(&m, SL_OPEN_RESOLUTION, 0);
        sl_ui_action(&m, SL_SET_RESOLUTION, 720);
        assert(m.page == SL_MENU && m.resolution == SL_RESOLUTION_1080 && !m.command.type);
        sl_runtime_event activity = {.type = SL_EVENT_ACTIVITY, .generation = m.generation};
        sl_ui_runtime_event(&m, &activity);
        assert(sl_ui_take_command(&m, &command) && command.resolution == SL_RESOLUTION_1080);
    }
}
int main(void) {
    storage();
    ui();
    puts("PASS resolution persistence/recovery, bilingual controls, stream-time settings blocked "
         "and activity saves");
    return 0;
}
