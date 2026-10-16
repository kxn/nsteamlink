#include "platform/shortcut.h"
#include "platform/system.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <switch.h>
#include <time.h>
#include <unistd.h>
static AppletType type;
u32 __nx_applet_exit_mode;
static u64 program_id;
static Result query_result;
static unsigned query_count;
Result svcGetInfo(u64 *out, u32 info, u32 handle, u64 sub_id) {
    assert(info == InfoType_ProgramId && handle == CUR_PROCESS_HANDLE && sub_id == 0);
    ++query_count;
    *out = program_id;
    return query_result;
}
static int consoles, frames, application_runs;
static int creates, joins, locks, unlocks, source_calls, loops, exit_loop;
static bool console_fails, create_fails, lock_fails, check_activity;
static atomic_bool allow_finish, installer_finished;
static sl_text_id install_result;
enum { WAIT = 16, BUSY, EXIT_REQUEST };
static const int *steps;
static unsigned step_count, step_index;
static pthread_t main_thread;
uint64_t __wrap_sl_system_now(void) {
    return (uint64_t)loops * 100;
}

void sl_shortcut_source(int argc, char **argv) {
    assert(argc == 1 && argv && !strcmp(argv[0], "sdmc:/running.nro"));
    ++source_calls;
}
sl_text_id sl_shortcut_install(char *detail, size_t capacity) {
    assert(!pthread_equal(pthread_self(), main_thread) && source_calls == 1);
    while (!atomic_load(&allow_finish)) {
        struct timespec delay = {.tv_nsec = 100000};
        nanosleep(&delay, NULL);
    }
    snprintf(detail, capacity, "test-stage: 00001234");
    atomic_store(&installer_finished, true);
    return install_result;
}
int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*entry)(void *),
                          void *context) {
    assert(consoles == 1 && locks == 1 && !unlocks && !creates);
    ++creates;
    return create_fails ? EAGAIN : __real_pthread_create(thread, attr, entry, context);
}
int __real_pthread_join(pthread_t, void **);
int __wrap_pthread_join(pthread_t thread, void **value) {
    assert(consoles == 1 && !unlocks && atomic_load(&installer_finished) && !joins);
    int rc = __real_pthread_join(thread, value);
    assert(!rc);
    ++joins;
    return rc;
}
Result appletLockExit(void) {
    assert(consoles == 1 && !locks++);
    return lock_fails ? 0x1234 : 0;
}
Result appletUnlockExit(void) {
    assert(!consoles && locks == 1 && !unlocks++);
    assert(!creates || create_fails || joins == 1);
    return 0;
}
extern int sl_test_entry(int argc, char **argv);
AppletType appletGetAppletType(void) {
    return type;
}
void *consoleInit(void *p) {
    (void)p;
    if (console_fails)
        return NULL;
    ++consoles;
    return &type;
}
void consoleExit(void *p) {
    (void)p;
    assert(!creates || create_fails || joins == 1);
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
    if (!steps)
        return frames ? HidNpadButton_B : 0;
    assert(step_index < step_count);
    int step = steps[step_index];
    if (step == WAIT) {
        atomic_store(&allow_finish, true);
        if (joins)
            ++step_index;
        return 0;
    }
    ++step_index;
    if (step == BUSY) {
        assert(creates == 1 && !joins);
        return HidNpadButton_A | HidNpadButton_B;
    }
    assert(step != EXIT_REQUEST);
    return step;
}
bool appletMainLoop(void) {
    assert(++loops < 100000);
    if (steps && step_index < step_count && steps[step_index] == EXIT_REQUEST) {
        ++step_index;
        exit_loop = loops;
    }
    if (exit_loop && loops - exit_loop >= 3)
        atomic_store(&allow_finish, true);
    if (creates && !joins) {
        struct timespec delay = {.tv_nsec = 100000};
        nanosleep(&delay, NULL);
    }
    return !exit_loop;
}
int sl_application_run(int argc, char **argv) {
    (void)argc;
    (void)argv;
    ++application_runs;
    return 17;
}
static void reset(void) {
    frames = application_runs = creates = joins = locks = unlocks = source_calls = loops =
        exit_loop = 0;
    create_fails = lock_fails = console_fails = check_activity = false;
    atomic_store(&allow_finish, false);
    atomic_store(&installer_finished, false);
    steps = NULL;
    step_count = step_index = 0;
}
static void run_steps(const int *script, unsigned count, int expected_jobs,
                      sl_text_id expected_text) {
    steps = script;
    step_count = count;
    FILE *capture = tmpfile();
    assert(capture);
    fflush(stdout);
    int original = dup(STDOUT_FILENO);
    assert(original >= 0 && dup2(fileno(capture), STDOUT_FILENO) >= 0);
    char *argv[] = {"sdmc:/running.nro"};
    assert(sl_test_entry(1, argv) == 0);
    fflush(stdout);
    assert(dup2(original, STDOUT_FILENO) >= 0);
    close(original);
    rewind(capture);
    char output[8192];
    size_t size = fread(output, 1, sizeof(output) - 1, capture);
    output[size] = 0;
    fclose(capture);
    assert(!consoles && !application_runs && source_calls == 1);
    assert(step_index == step_count && creates == expected_jobs);
    assert(joins == (expected_jobs && !create_fails ? 1 : 0));
    assert(unlocks == (locks && !lock_fails ? 1 : 0));
    assert(strstr(output, sl_tr(expected_text)));
    if (check_activity) {
        assert(strstr(output, "[|]  0s") && strstr(output, "[/]  0s"));
        assert(strstr(output, "[\\]  1s"));
    }
    if (expected_jobs && !create_fails)
        assert(strstr(output, "test-stage: 00001234") && strstr(output, SL_SHORTCUT_PATH));
}
int main(void) {
    main_thread = pthread_self();
    for (type = AppletType_None; type <= AppletType_SystemApplet; ++type) {
        reset();
        char *argv[] = {"sdmc:/running.nro"};
        int rc = sl_test_entry(1, argv);
        bool full = type == AppletType_Application || type == AppletType_SystemApplication;
        assert(rc == (full ? 17 : 0) && application_runs == (full ? 1 : 0) && !consoles);
        assert(frames == (full ? 0 : 1));
    }
    /* Same NRO, different hosts: only our HOME application may terminate its host.
     * In particular, a game used for title takeover is also a full application. */
    const u64 ids[] = {UINT64_C(0x01004e534c4b1000), UINT64_C(0x01004e534c4b0000),
                       UINT64_C(0x010000000000100d), UINT64_C(0x0100123456780000), 0};
    for (int app = AppletType_Application; app <= AppletType_SystemApplication; ++app)
        for (unsigned id = 0; id < sizeof(ids) / sizeof(ids[0]); ++id)
            for (int fail = 0; fail < 2; ++fail) {
                type = app;
                program_id = ids[id];
                query_result = fail ? 0x1234 : 0;
                __nx_applet_exit_mode = 0;
                query_count = 0;
                assert(sl_test_entry(0, NULL) == 17);
                assert(__nx_applet_exit_mode == (!fail && id == 0 ? 1u : 0u));
                assert(query_count == 1);
            }
    type = AppletType_LibraryApplet;
    program_id = ids[0];
    query_result = 0;
    reset();
    query_count = 0;
    __nx_applet_exit_mode = 0;
    char *argv[] = {"sdmc:/running.nro"};
    assert(sl_test_entry(1, argv) == 0 && !query_count && !__nx_applet_exit_mode && !consoles);
    const int cancel[] = {HidNpadButton_A, HidNpadButton_B, HidNpadButton_B};
    reset();
    run_steps(cancel, 3, 0, SL_T_APPLET_INSTALL);
    const int install[] = {HidNpadButton_A, HidNpadButton_A, BUSY, WAIT, HidNpadButton_B};
    const sl_text_id results[] = {SL_T_SHORTCUT_ADDED, SL_T_SHORTCUT_EXISTS, SL_T_SHORTCUT_FAILED,
                                  SL_T_SHORTCUT_CLEANUP_FAILED, SL_T_SHORTCUT_NRO_REQUIRED};
    for (unsigned i = 0; i < sizeof(results) / sizeof(results[0]); ++i) {
        reset();
        install_result = results[i];
        run_steps(install, 5, 1, results[i]);
    }
    const int activity[] = {HidNpadButton_A,
                            HidNpadButton_A,
                            BUSY,
                            BUSY,
                            BUSY,
                            BUSY,
                            BUSY,
                            BUSY,
                            BUSY,
                            BUSY,
                            BUSY,
                            BUSY,
                            BUSY,
                            BUSY,
                            BUSY,
                            BUSY,
                            WAIT,
                            HidNpadButton_B};
    reset();
    check_activity = true;
    install_result = SL_T_SHORTCUT_ADDED;
    run_steps(activity, sizeof(activity) / sizeof(activity[0]), 1, SL_T_SHORTCUT_ADDED);
    const int exit_install[] = {HidNpadButton_A, HidNpadButton_A, BUSY, EXIT_REQUEST};
    reset();
    install_result = SL_T_SHORTCUT_ADDED;
    run_steps(exit_install, 4, 1, SL_T_SHORTCUT_ADDED);
    assert(loops - exit_loop >= 3);
    const int failure[] = {HidNpadButton_A, HidNpadButton_A, HidNpadButton_B};
    reset();
    create_fails = true;
    run_steps(failure, 3, 1, SL_T_SHORTCUT_FAILED);
    reset();
    lock_fails = true;
    run_steps(failure, 3, 0, SL_T_SHORTCUT_FAILED);
    const int prompt_exit[] = {EXIT_REQUEST};
    reset();
    run_steps(prompt_exit, 1, 0, SL_T_APPLET_INSTALL);
    reset();
    console_fails = true;
    assert(sl_test_entry(0, NULL) == 0 && !consoles && !application_runs && !creates);
    puts("PASS console install confirmation/cancel, results, busy input, exit drain/join, "
         "worker/lock/console failures; preflight returns to loader before application/SDL "
         "initialization in every applet "
         "type; HOME exit handshake isolated from hbmenu, takeover and failed identity "
         "queries");
}
