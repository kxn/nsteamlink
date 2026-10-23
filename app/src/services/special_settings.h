#pragma once
#include <stdbool.h>
/* Only sources with a working input path belong in the current schema/UI. */
typedef enum sl_guide_key {
    SL_GUIDE_KEY_OFF = 0,
    SL_GUIDE_KEY_CAPTURE = 1,
} sl_guide_key;
static inline bool sl_guide_key_valid(sl_guide_key key) {
    return key == SL_GUIDE_KEY_OFF || key == SL_GUIDE_KEY_CAPTURE;
}
/* Independent application policy. Missing files default to Capture; v1 bool
 * preferences migrate without changing an explicit Off selection. */
sl_guide_key sl_special_settings_load(const char *directory);
bool sl_special_settings_save(const char *directory, sl_guide_key key);
