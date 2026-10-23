#pragma once
#include <stdbool.h>
#include <stdint.h>
typedef uint32_t Result;
#define R_SUCCEEDED(value) ((value) == 0)
#define R_FAILED(value) ((value) != 0)
typedef enum { AppletFocusState_InFocus, AppletFocusState_OutOfFocus } AppletFocusState;
typedef enum { AppletHookType_OnFocusState, AppletHookType_OnExitRequest,
               AppletHookType_OnCaptureButtonShortPressed } AppletHookType;
typedef struct { unsigned value; } AppletHookCookie;
typedef void (*AppletHookFn)(AppletHookType, void *);
typedef enum { AppletSystemButtonType_CaptureButtonShortPressing = 6 } AppletSystemButtonType;
void appletHook(AppletHookCookie *, AppletHookFn, void *);
void appletUnhook(AppletHookCookie *);
Result appletSetRequiresCaptureButtonShortPressedMessage(bool);
Result appletPerformSystemButtonPressingIfInFocus(AppletSystemButtonType);
AppletFocusState appletGetFocusState(void);
bool hosversionAtLeast(unsigned, unsigned, unsigned);
void hidInitializeTouchScreen(void);
_Noreturn void diagAbortWithResult(Result);
