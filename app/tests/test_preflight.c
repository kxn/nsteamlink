#include "platform/system.h"
#include <assert.h>
#include <stdio.h>
#include <switch.h>
static AppletType type;
u32 __nx_applet_exit_mode;
static bool nso;
static u64 program_id;
static Result query_result;
static unsigned query_count;
bool envIsNso(void) {
    return nso;
}
Result svcGetInfo(u64 *out, u32 info, u32 handle, u64 sub_id) {
    assert(info == InfoType_ProgramId && handle == CUR_PROCESS_HANDLE && sub_id == 0);
    ++query_count;
    *out = program_id;
    return query_result;
}
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
    /* Same NRO, different hosts: only our HOME application may terminate its host.
     * In particular, a game used for title takeover is also a full application. */
    const u64 ids[] = {UINT64_C(0x01004e534c4b1000), UINT64_C(0x01004e534c4b0000),
                       UINT64_C(0x010000000000100d), UINT64_C(0x0100123456780000), 0};
    for (int app = AppletType_Application; app <= AppletType_SystemApplication; ++app)
        for (int binary = 0; binary < 2; ++binary)
            for (unsigned id = 0; id < sizeof(ids) / sizeof(ids[0]); ++id)
                for (int fail = 0; fail < 2; ++fail) {
                    type = app;
                    nso = binary;
                    program_id = ids[id];
                    query_result = fail ? 0x1234 : 0;
                    __nx_applet_exit_mode = 0;
                    query_count = 0;
                    assert(sl_test_entry(0, NULL) == 17);
                    assert(__nx_applet_exit_mode == (!binary && !fail && id == 0 ? 1u : 0u));
                    assert(query_count == (binary ? 0u : 1u));
                }
    type = AppletType_LibraryApplet;
    program_id = ids[0];
    nso = false;
    query_result = 0;
    frames = 0;
    query_count = 0;
    __nx_applet_exit_mode = 0;
    assert(sl_test_entry(0, NULL) == 0 && !query_count && !__nx_applet_exit_mode && !consoles);
    puts("PASS preflight returns to loader before application/SDL initialization in every applet "
         "type; HOME exit handshake isolated from hbmenu, takeover, NSO and failed identity "
         "queries");
}
