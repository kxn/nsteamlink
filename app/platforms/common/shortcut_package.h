#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define SL_SHORTCUT_ID UINT64_C(0x01004e534c4b1000)
typedef void (*sl_shortcut_hash)(void *out, const void *data, size_t size);
typedef bool (*sl_shortcut_seal)(void *context, unsigned char *header);
typedef struct sl_shortcut_package {
    unsigned char *allocation, *data[3]; /* program, control, meta */
    size_t size[3];
    unsigned char hashes[3][32];
    unsigned char database[96]; /* NcmContentMetaHeader + extended header + 3 content infos */
} sl_shortcut_package;
bool sl_shortcut_materialize(sl_shortcut_package *out, const unsigned char *blob, size_t size,
                             sl_shortcut_hash hash, sl_shortcut_seal seal, void *context);
void sl_shortcut_package_free(sl_shortcut_package *package);
