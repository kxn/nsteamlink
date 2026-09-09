#include "services/i18n.h"
#include "ui/ui_events.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static bool horizon, fail_publish;
int __real_rename(const char *, const char *);
int __wrap_rename(const char *from, const char *to) {
    if (fail_publish && strstr(from, "language.tmp")) {
        errno = EIO;
        return -1;
    }
    if (horizon && access(to, F_OK) == 0) {
        errno = EEXIST;
        return -1;
    }
    return __real_rename(from, to);
}
int main(void) {
    char dir[] = "/tmp/nsl-i18n-XXXXXX";
    assert(mkdtemp(dir));
    sl_i18n_load(dir, "en_US.UTF-8");
    assert(sl_i18n_language() == SL_LANG_SYSTEM);
    assert(!strcmp(sl_tr(SL_T_SETTINGS), "Settings"));
    sl_auth_store store;
    assert(sl_auth_load(&store, dir) == 1);
    sl_ui_model m;
    sl_ui_init(&m, &store);
    sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
    sl_ui_action(&m, SL_OPEN_LANGUAGE, 0);
    assert(m.page == SL_LANGUAGE && m.focus == 100);
    sl_ui_action(&m, SL_DOWN, 0);
    assert(sl_i18n_language() == SL_LANG_SYSTEM);
    sl_ui_action(&m, SL_ACCEPT, 0);
    assert(sl_i18n_language() == SL_LANG_ZH_CN);
    sl_command cmd;
    assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_SAVE &&
           cmd.language == SL_LANG_ZH_CN);
    assert(sl_i18n_save(dir, cmd.language));
    sl_i18n_load(dir, "en_GB");
    assert(!strcmp(sl_tr(SL_T_SETTINGS), "设置"));
    /* Touch path selects English immediately without leaving the language menu. */
    sl_ui_activate(&m, 102);
    assert(!strcmp(m.layout.title, "Language"));
    assert(sl_ui_take_command(&m, &cmd) && cmd.language == SL_LANG_EN);
    horizon = true;
    assert(sl_i18n_save(dir, cmd.language));
    sl_i18n_load(dir, "zh-CN");
    assert(!strcmp(sl_tr(SL_T_SETTINGS), "Settings"));
    fail_publish = true;
    assert(!sl_i18n_save(dir, SL_LANG_ZH_CN));
    fail_publish = false;
    sl_i18n_load(dir, "zh-CN");
    assert(sl_i18n_language() == SL_LANG_EN);
    /* Changing language must not migrate or damage pairing identity. */
    sl_auth_store restored;
    assert(sl_auth_load(&restored, dir) == 0);
    assert(restored.device_id == store.device_id && !memcmp(restored.secret, store.secret, 32));
    assert(sl_i18n_save(dir, SL_LANG_SYSTEM));
    sl_i18n_load(dir, "zh_TW");
    assert(!strcmp(sl_tr(SL_T_SETTINGS), "设置"));
    sl_i18n_load(dir, "de_DE");
    assert(!strcmp(sl_tr(SL_T_SETTINGS), "Settings"));
    sl_ui_connected(&m);
    sl_ui_action(&m, SL_OPEN_MENU, 0);
    sl_ui_action(&m, SL_OPEN_SETTINGS, 0);
    sl_ui_action(&m, SL_OPEN_LANGUAGE, 0);
    sl_ui_activate(&m, 102);
    assert(m.streaming && m.page == SL_LANGUAGE);
    assert(sl_ui_take_command(&m, &cmd) && cmd.type == SL_CMD_SAVE);
    sl_ui_stopped(&m, true);
    assert(!strcmp(m.layout.title, "Stream interrupted"));
    assert(!strcmp(m.error, "Connection lost"));
    for (int lang = SL_LANG_ZH_CN; lang <= SL_LANG_EN; ++lang) {
        sl_i18n_set(lang);
        for (int id = 0; id < SL_T_COUNT; ++id)
            assert(sl_tr(id)[0]);
    }
    char path[512], backup[512];
    snprintf(path, sizeof(path), "%s/language.conf", dir);
    snprintf(backup, sizeof(backup), "%s/language.bak", dir);
    assert(!rename(path, backup));
    sl_i18n_load(dir, "en");
    assert(sl_i18n_language() == SL_LANG_SYSTEM);
    assert(!unlink(backup));
    FILE *f = fopen(path, "w");
    assert(f);
    fputs("unsupported\n", f);
    fclose(f);
    sl_i18n_load(dir, "en");
    assert(sl_i18n_language() == SL_LANG_SYSTEM);
    assert(!unlink(path));
    snprintf(path, sizeof(path), "%s/profile.bin", dir);
    assert(!unlink(path));
    assert(!rmdir(dir));
    puts("PASS i18n: selection, persistence, fallback, pairing preservation and streaming");
}
