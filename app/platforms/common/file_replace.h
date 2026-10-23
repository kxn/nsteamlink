#pragma once
#include <stdbool.h>
/* Horizon rename does not replace an existing destination. Publish a complete
 * temporary file with recoverable .old backup; never delete the valid target
 * before preserving it. The two renames are recoverable, not jointly atomic. */
bool sl_file_replace(const char *temporary, const char *path);
/* Restore the previous complete file if interrupted between the two renames.
 * No target and no backup is also a normal first-run state. */
bool sl_file_replace_recover(const char *path);
