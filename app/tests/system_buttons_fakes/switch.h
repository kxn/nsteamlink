#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef uint64_t u64;
typedef int64_t s64;
typedef uint32_t Result;
#define R_SUCCEEDED(x) ((x) == 0)
#define R_FAILED(x) ((x) != 0)
#define MAKERESULT(module, description) ((Result)((module) | ((description) << 9)))
enum { Module_Libnx = 345, LibnxError_BadInput = 11 };
typedef enum { AppletFocusState_InFocus, AppletFocusState_OutOfFocus } AppletFocusState;
unsigned appletGetAppletType(void);
unsigned hosversionGet(void);
enum { HiddbgNpadButton_Home = 1 << 18, HiddbgNpadButton_Capture = 1 << 19,
       HidDeviceType_FullKey3 = 3, HidNpadInterfaceType_Bluetooth = 1 };
typedef struct { unsigned handle; } Event;
typedef struct { u64 id; } HiddbgHdlsSessionId;
typedef struct { u64 handle; } HiddbgHdlsHandle;
typedef struct { unsigned deviceType, npadInterfaceType; } HiddbgHdlsDeviceInfo;
typedef struct { unsigned battery_level, flags; u64 buttons; } HiddbgHdlsState;
typedef struct { u64 sampling_number, buttons; } HidHomeButtonState;
Result hidsysInitialize(void);
void hidsysExit(void);
Result hidsysActivateHomeButton(void);
Result hidsysAcquireHomeButtonEventHandle(Event *, bool);
Result eventWait(Event *, u64);
void eventClose(Event *);
void *hidGetSharedmemAddr(void);
size_t hidGetHomeButtonStates(HidHomeButtonState *, size_t);
AppletFocusState appletGetFocusState(void);
Result appletIsHomeButtonShortPressedBlocked(bool *);
Result appletBeginBlockingHomeButton(s64);
Result appletEndBlockingHomeButton(void);
Result hiddbgInitialize(void);
void hiddbgExit(void);
Result hiddbgAttachHdlsWorkBuffer(HiddbgHdlsSessionId *, void *, size_t);
Result hiddbgReleaseHdlsWorkBuffer(HiddbgHdlsSessionId);
Result hiddbgAttachHdlsVirtualDevice(HiddbgHdlsHandle *, const HiddbgHdlsDeviceInfo *);
Result hiddbgDetachHdlsVirtualDevice(HiddbgHdlsHandle);
Result hiddbgSetHdlsState(HiddbgHdlsHandle, const HiddbgHdlsState *);
_Noreturn void diagAbortWithResult(Result);
