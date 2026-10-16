#pragma once
#include "services/i18n.h"
#include <stddef.h>
#define SL_SHORTCUT_PATH "sdmc:/switch/nsteamlink/nsteamlink.nro"
/* Set before creating workers. Installation runs on a joined worker, including preflight. */
void sl_shortcut_source(int argc, char **argv);
sl_text_id sl_shortcut_install(char *detail, size_t capacity);
