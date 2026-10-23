#pragma once
#include <stdbool.h>
/* Independent application policy; old profiles without this file default on. */
bool sl_special_settings_load(const char *directory);
bool sl_special_settings_save(const char *directory, bool capture_guide);
