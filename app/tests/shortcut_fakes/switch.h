#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint64_t u64;
typedef int Result;
#define R_FAILED(r)    ((r) != 0)
#define R_SUCCEEDED(r) ((r) == 0)
typedef struct {
    int active;
} Service;
typedef Service NcmContentStorage;
typedef Service NcmContentMetaDatabase;
typedef struct {
    unsigned char c[16];
} NcmContentId;
typedef struct {
    unsigned char c[16];
} NcmPlaceHolderId;
typedef struct {
    u64 id;
    u32 version;
    u8 type, install_type, padding[2];
} NcmContentMetaKey;
enum {
    NcmStorageId_SdCard = 5,
    NcmStorageId_BuiltInUser = 4,
    NcmContentMetaType_Unknown = 0,
    NcmContentMetaType_Application = 0x80,
    NcmContentInstallType_Full = 0
};
typedef struct {
    unsigned sector;
} Aes128XtsContext;
void aes128XtsContextCreate(Aes128XtsContext *, const void *, const void *, bool);
void aes128XtsContextResetSector(Aes128XtsContext *, u64, bool);
void aes128XtsEncrypt(Aes128XtsContext *, void *, const void *, size_t);
void sha256CalculateHash(void *, const void *, size_t);
Result splCryptoInitialize(void);
Result splCryptoGenerateAesKek(const void *, u32, u32, void *);
Result splCryptoGenerateAesKey(const void *, const void *, void *);
void splCryptoExit(void);
Result ncmInitialize(void);
void ncmExit(void);
Result nsInitialize(void);
void nsExit(void);
Result nsGetApplicationManagerInterface(Service *);
typedef struct {
    u64 application_id;
} NsApplicationRecord;
Result nsListApplicationRecord(NsApplicationRecord *, s32, s32, s32 *);
Result nsIsAnyApplicationEntityInstalled(u64, bool *);
Result ncmOpenContentMetaDatabase(NcmContentMetaDatabase *, int);
Result ncmOpenContentStorage(NcmContentStorage *, int);
Result ncmContentMetaDatabaseList(NcmContentMetaDatabase *, s32 *, s32 *, NcmContentMetaKey *, s32,
                                  int, u64, u64, u64, int);
Result ncmContentStorageHas(NcmContentStorage *, bool *, const NcmContentId *);
Result ncmContentStorageGeneratePlaceHolderId(NcmContentStorage *, NcmPlaceHolderId *);
Result ncmContentStorageCreatePlaceHolder(NcmContentStorage *, const NcmContentId *,
                                          const NcmPlaceHolderId *, int64_t);
Result ncmContentStorageWritePlaceHolder(NcmContentStorage *, const NcmPlaceHolderId *, u64,
                                         const void *, size_t);
Result ncmContentStorageRegister(NcmContentStorage *, const NcmContentId *,
                                 const NcmPlaceHolderId *);
Result ncmContentStorageDeletePlaceHolder(NcmContentStorage *, const NcmPlaceHolderId *);
Result ncmContentStorageDelete(NcmContentStorage *, const NcmContentId *);
Result ncmContentMetaDatabaseSet(NcmContentMetaDatabase *, const NcmContentMetaKey *, const void *,
                                 u64);
Result ncmContentMetaDatabaseRemove(NcmContentMetaDatabase *, const NcmContentMetaKey *);
Result ncmContentMetaDatabaseCommit(NcmContentMetaDatabase *);
void serviceClose(Service *);
#define ncmContentMetaDatabaseClose serviceClose
#define ncmContentStorageClose      serviceClose
Result fake_push(u64 id);
#define serviceDispatchIn(service, command, input, ...) ((void)record, fake_push((input).id))
/* Preflight surface: any attempt to use SDL would fail to link this test. */
typedef enum {
    AppletType_None,
    AppletType_Default,
    AppletType_Application,
    AppletType_SystemApplication,
    AppletType_LibraryApplet,
    AppletType_SystemApplet
} AppletType;
typedef struct {
    int unused;
} PadState;
enum { HidNpadStyleSet_NpadStandard = 1, HidNpadButton_B = 2 };
AppletType appletGetAppletType(void);
void *consoleInit(void *);
void consoleExit(void *);
void consoleUpdate(void *);
void padConfigureInput(int, int);
void padInitializeDefault(PadState *);
void padUpdate(PadState *);
u64 padGetButtonsDown(PadState *);
bool appletMainLoop(void);
