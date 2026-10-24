#pragma once
#include <stdbool.h>
/* Startup update check preference, kept beside language.conf and independent
 * of profile.bin. A missing or unreadable file means enabled. */
bool sl_update_config_load(const char *directory);
bool sl_update_config_save(const char *directory, bool enabled);
/* Exact release opted out of, independent of the global update-check toggle. */
void sl_update_ignored_load(const char *directory, char version[16]);
bool sl_update_ignored_save(const char *directory, const char *version);
