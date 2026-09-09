#include "platform/system.h"
#include <assert.h>
#include <stdio.h>
#include <switch.h>
static AppletType type;
static int consoles, frames, application_runs;
extern int sl_test_entry(int argc, char **argv);
AppletType appletGetAppletType(void) {
    return type;
}
void *consoleInit(void *p) {
    (void)p;
    ++consoles;
    return &type;
}
void consoleExit(void *p) {
    (void)p;
    --consoles;
}
void consoleUpdate(void *p) {
    (void)p;
    ++frames;
}
void padConfigureInput(int a, int b) {
    (void)a;
    (void)b;
}
void padInitializeDefault(PadState *p) {
    (void)p;
}
void padUpdate(PadState *p) {
    (void)p;
}
u64 padGetButtonsDown(PadState *p) {
    (void)p;
    return frames ? HidNpadButton_B : 0;
}
bool appletMainLoop(void) {
    return true;
}
int sl_application_run(int argc, char **argv) {
    (void)argc;
    (void)argv;
    ++application_runs;
    return 17;
}
int main(void) {
    for (type = AppletType_None; type <= AppletType_SystemApplet; ++type) {
        frames = application_runs = 0;
        int rc = sl_test_entry(0, NULL);
        bool full = type == AppletType_Application || type == AppletType_SystemApplication;
        assert(rc == (full ? 17 : 0) && application_runs == (full ? 1 : 0) && !consoles);
        assert(frames == (full ? 0 : 1));
    }
    puts("PASS preflight returns to loader before application/SDL initialization in every applet "
         "type");
}
