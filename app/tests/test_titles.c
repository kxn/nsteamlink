#include "artwork.h"
#include "services/i18n.h"
#include "ui/ui_events.h"
#include <assert.h>
#include <dirent.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef struct fixture {
    atomic_int calls;
    atomic_bool hold, entered, fail;
} fixture;
static bool fetch(const char *url, size_t limit, unsigned char **out, size_t *size, void *ctx) {
    fixture *f = ctx;
    atomic_fetch_add(&f->calls, 1);
    atomic_store(&f->entered, true);
    while (atomic_load(&f->hold))
        usleep(1000);
    if (atomic_load(&f->fail))
        return false;
    assert(strstr(url, "IStoreBrowseService/GetItems/v1/"));
    const char *name = strstr(url, "schinese") ? "\\u9ed1\\u795e\\u8bdd\\uff1a\\u609f\\u7a7a"
                                               : "Black Myth: Wukong";
    char json[512];
    snprintf(json, sizeof(json),
             "{\"response\":{\"store_items\":[{\"success\":1,\"appid\":2358720,\"name\":\"%s\"}]}}",
             name);
    *size = strlen(json);
    assert(*size <= limit);
    *out = (unsigned char *)strdup(json);
    return true;
}
static void wait_name(sl_artwork *a, int lang, const char *expected) {
    char name[512];
    for (int n = 0; n < 4000; ++n) {
        if (sl_artwork_title(a, 2358720, lang, name, sizeof(name))) {
            assert(!strcmp(name, expected));
            return;
        }
        usleep(1000);
    }
    assert(!"title timed out");
}
static bool parse(const char *title, char *out, size_t cap) {
    char json[2048];
    snprintf(json, sizeof(json),
             "{\"response\":{\"store_items\":[{\"success\":1,\"appid\":2358720,\"name\":\"%s\"}]}}",
             title);
    return sl_artwork_name((unsigned char *)json, strlen(json), 2358720, out, cap);
}
int main(void) {
    char name[512];
    assert(parse("黑神话：悟空", name, sizeof(name)) && !strcmp(name, "黑神话：悟空"));
    assert(parse("A \\ud83c\\udfae", name, sizeof(name)) && !strcmp(name, "A 🎮"));
    assert(parse("A\\nB\\/C", name, sizeof(name)) && !strcmp(name, "A B/C"));
    assert(!parse("\\ud800", name, sizeof(name)));
    assert(!parse("\\udc00", name, sizeof(name)));
    assert(!parse("\\u0000", name, sizeof(name)));
    assert(!parse("\xc0\xaf", name, sizeof(name)));
    assert(!parse("   ", name, sizeof(name)));
    assert(!parse("中文", name, 5) && !name[0]);
    const char *wrong =
        "{\"response\":{\"store_items\":[{\"success\":1,\"appid\":10,\"name\":\"Wrong\"}]}}";
    assert(!sl_artwork_name((unsigned char *)wrong, strlen(wrong), 2358720, name, sizeof(name)));
    char dir[] = "/tmp/nsl-titles-XXXXXX";
    assert(mkdtemp(dir));
    fixture f = {0};
    sl_artwork *a = sl_artwork_create(dir, fetch, &f);
    assert(a);
    atomic_store(&f.hold, true);
    assert(!sl_artwork_title(a, 2358720, SL_LANG_EN, name, sizeof(name)));
    for (int n = 0; n < 4000 && !atomic_load(&f.entered); ++n)
        usleep(1000);
    assert(atomic_load(&f.entered));
    /* Old English query completes after switching to Chinese; keys never mix. */
    assert(!sl_artwork_title(a, 2358720, SL_LANG_ZH_CN, name, sizeof(name)));
    atomic_store(&f.hold, false);
    wait_name(a, SL_LANG_ZH_CN, "黑神话：悟空");
    wait_name(a, SL_LANG_EN, "Black Myth: Wukong");
    assert(atomic_load(&f.calls) == 2);
    assert(!sl_artwork_title(a, UINT64_C(0x8000000001000000), SL_LANG_EN, name, sizeof(name)));
    sl_artwork_destroy(a);
    atomic_store(&f.fail, true);
    a = sl_artwork_create(dir, fetch, &f);
    assert(a);
    wait_name(a, SL_LANG_EN, "Black Myth: Wukong");
    wait_name(a, SL_LANG_ZH_CN, "黑神话：悟空");
    assert(atomic_load(&f.calls) == 2); /* disk cache works without network or JPEGs */
    for (int i = 0; i < 50; ++i) {
        assert(!sl_artwork_title(a, 10, SL_LANG_EN, name, sizeof(name)));
        usleep(1000);
    }
    assert(atomic_load(&f.calls) == 3); /* retry backoff, fallback remains available */
    sl_artwork_destroy(a);
    /* Recording a newly played game must preserve the chosen language on save. */
    sl_i18n_set(SL_LANG_EN);
    sl_auth_store store = {0};
    sl_ui_model model;
    sl_ui_init(&model, &store);
    sl_runtime_event e = {.type = SL_EVENT_ACTIVITY};
    sl_ui_runtime_event(&model, &e);
    sl_command cmd;
    assert(sl_ui_take_command(&model, &cmd));
    assert(cmd.type == SL_CMD_SAVE && cmd.language == SL_LANG_EN);
    char path[512];
    snprintf(path, sizeof(path), "%s/artwork", dir);
    DIR *d = opendir(path);
    assert(d);
    struct dirent *ent;
    while ((ent = readdir(d)))
        if (ent->d_name[0] != '.') {
            char file[800];
            snprintf(file, sizeof(file), "%s/%s", path, ent->d_name);
            assert(!unlink(file));
        }
    closedir(d);
    assert(!rmdir(path));
    assert(!rmdir(dir));
    puts("PASS localized titles, UTF-8, language isolation, offline cache and fallback");
}
