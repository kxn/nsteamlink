#include "i18n.h"
#include "i18n_data.h"
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static atomic_int preferred = SL_LANG_SYSTEM;
static atomic_int system_language = SL_LANG_ZH_CN;
const char *sl_tr(sl_text_id id) {
    int language = atomic_load(&preferred);
    if (language == SL_LANG_SYSTEM)
        language = atomic_load(&system_language);
    return id >= 0 && id < SL_T_COUNT ? translations[language == SL_LANG_EN][id] : "";
}
sl_language sl_i18n_language(void) {
    return atomic_load(&preferred);
}
void sl_i18n_set(sl_language language) {
    if (language >= 0 && language < SL_LANG_COUNT)
        atomic_store(&preferred, language);
}
static const char *codes[] = {"system", "zh-CN", "en"};
void sl_i18n_load(const char *dir, const char *locale) {
    atomic_store(&system_language,
                 locale && !strncmp(locale, "zh", 2) ? SL_LANG_ZH_CN : SL_LANG_EN);
    sl_i18n_set(SL_LANG_SYSTEM);
    char path[512], value[32];
    snprintf(path, sizeof(path), "%s/language.conf", dir);
    FILE *f = fopen(path, "r");
    if (!f && errno == ENOENT) {
        snprintf(path, sizeof(path), "%s/language.bak", dir);
        f = fopen(path, "r");
    }
    if (!f)
        return;
    if (fgets(value, sizeof(value), f)) {
        value[strcspn(value, "\r\n")] = 0;
        for (int i = 0; i < SL_LANG_COUNT; ++i)
            if (!strcmp(value, codes[i]))
                sl_i18n_set(i);
    }
    fclose(f);
}
bool sl_i18n_save(const char *dir, sl_language language) {
    if (language < 0 || language >= SL_LANG_COUNT)
        return false;
    if (mkdir(dir, 0700) && errno != EEXIST)
        return false;
    char path[512], tmp[512], backup[512];
    snprintf(path, sizeof(path), "%s/language.conf", dir);
    snprintf(tmp, sizeof(tmp), "%s/language.tmp", dir);
    snprintf(backup, sizeof(backup), "%s/language.bak", dir);
    FILE *f = fopen(tmp, "w");
    if (!f)
        return false;
    bool ok = fprintf(f, "%s\n", codes[language]) > 0;
    if (fflush(f))
        ok = false;
    if (ok && fsync(fileno(f)) && errno != ENOSYS && errno != EINVAL)
        ok = false;
    if (fclose(f))
        ok = false;
    if (ok && rename(tmp, path)) {
        /* Horizon does not replace existing files. Keep a recoverable backup. */
        ok = false;
        if (errno == EEXIST || errno == ENOTEMPTY) {
            if ((remove(backup) == 0 || errno == ENOENT) && rename(path, backup) == 0) {
                ok = rename(tmp, path) == 0;
                if (!ok)
                    rename(backup, path);
            }
        }
    }
    if (ok)
        remove(backup);
    else
        remove(tmp);
    return ok;
}
