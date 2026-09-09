#pragma once
#include "i18n_keys.h"
#include <stdbool.h>
typedef enum sl_language { SL_LANG_SYSTEM, SL_LANG_ZH_CN, SL_LANG_EN, SL_LANG_COUNT } sl_language;
/* Immutable resources; lookup and language changes are safe across workers. */
const char *sl_tr(sl_text_id id);
sl_language sl_i18n_language(void);
void sl_i18n_set(sl_language language);
void sl_i18n_load(const char *directory, const char *system_locale);
bool sl_i18n_save(const char *directory, sl_language language);

sl_language sl_i18n_resolved(void);
