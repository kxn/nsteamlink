#include "../common/shortcut_package.h"
#include "platform/shortcut.h"
#include "platform/system.h"
#include "services/i18n.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <switch.h>
/* libnx defaults to returning NROs to their loader, without SelfController::Exit.
 * Our HOME forwarder owns an application process and must use the normal applet
 * exit handshake instead. Never apply this to ordinary hbmenu/title takeover. */
extern u32 __nx_applet_exit_mode;
static void configure_home_exit(void) {
    u64 program_id = 0;
    if (R_SUCCEEDED(svcGetInfo(&program_id, InfoType_ProgramId, CUR_PROCESS_HANDLE, 0)) &&
        program_id == SL_SHORTCUT_ID)
        __nx_applet_exit_mode = 1;
}
typedef struct {
    atomic_bool done;
    sl_text_id result;
    char detail[160];
} install_job;
static void *install_main(void *context) {
    install_job *job = context;
    job->result = sl_shortcut_install(job->detail, sizeof(job->detail));
    /* Publish only after the installer has released services and package memory. */
    atomic_store_explicit(&job->done, true, memory_order_release);
    return NULL;
}
typedef enum { PROMPT, CONFIRM, INSTALLING, RESULT } preflight_page;
static void draw(preflight_page page, const install_job *job) {
    printf("\x1b[2J\x1b[3;3H%s\n\n", sl_tr(SL_T_BRAND));
    switch (page) {
    case PROMPT:
        printf("%s\n\n%s\n\n%s\n\n%s", sl_tr(SL_T_APPLET_UNSUPPORTED),
               sl_tr(SL_T_APPLET_INSTRUCTION), sl_tr(SL_T_APPLET_INSTALL),
               sl_tr(SL_T_APPLET_RETURN));
        break;
    case CONFIRM:
        printf("%s\n\n%s\n\n%s\n\n%s    %s", sl_tr(SL_T_SHORTCUT_QUESTION),
               sl_tr(SL_T_SHORTCUT_DESCRIPTION), SL_SHORTCUT_PATH, sl_tr(SL_T_CONFIRM_KEY),
               sl_tr(SL_T_BACK_KEY));
        break;
    case INSTALLING:
        printf("%s\n\n%s", sl_tr(SL_T_SHORTCUT_INSTALLING), sl_tr(SL_T_APPLET_INSTALL_WAIT));
        break;
    case RESULT:
        printf("%s\n\n%s\n\n%s\n\n", sl_tr(job->result), job->detail, SL_SHORTCUT_PATH);
        if (job->result == SL_T_SHORTCUT_ADDED || job->result == SL_T_SHORTCUT_EXISTS)
            printf("%s\n\n", sl_tr(SL_T_APPLET_HOME_INSTRUCTION));
        printf("%s", sl_tr(SL_T_APPLET_RETURN));
        break;
    }
}
bool sl_system_preflight(int argc, char **argv) {
    AppletType type = appletGetAppletType();
    if (type == AppletType_Application || type == AppletType_SystemApplication) {
        configure_home_exit();
        return true;
    }
    /* libnx console uses its framebuffer, not SDL/Mesa. The built-in font is
     * ASCII: deliberately use the English resource before loading preferences. */
    sl_i18n_set(SL_LANG_EN);
    if (!consoleInit(NULL))
        return false;
    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    PadState pad;
    padInitializeDefault(&pad);
    sl_shortcut_source(argc, argv);
    install_job job = {.done = ATOMIC_VAR_INIT(false)};
    pthread_t worker;
    bool started = false, exit_locked = false, exiting = false;
    uint64_t install_started = 0, activity_tick = UINT64_MAX;
    preflight_page page = PROMPT;
    draw(page, &job);
    for (;;) {
        if (!appletMainLoop())
            exiting = true;
        if (started && atomic_load_explicit(&job.done, memory_order_acquire)) {
            pthread_join(worker, NULL);
            started = false;
            page = RESULT;
            draw(page, &job);
        }
        /* No cancellation in the middle of a content/database transaction. Keep
         * pumping lifecycle while it finishes, then join before console/unlock. */
        if (exiting && !started)
            break;
        u64 buttons = 0;
        if (!exiting) {
            padUpdate(&pad);
            buttons = padGetButtonsDown(&pad);
        }
        preflight_page previous = page;
        if (!exiting && page != INSTALLING) {
            if (buttons & HidNpadButton_B) {
                if (page == CONFIRM)
                    page = PROMPT;
                else
                    break;
            } else if (buttons & HidNpadButton_A) {
                if (page == PROMPT)
                    page = CONFIRM;
                else if (page == CONFIRM) {
                    /* libnx allows a bounded cleanup window after an exit
                     * request. If locking fails, never begin installation. */
                    Result rc = appletLockExit();
                    exit_locked = R_SUCCEEDED(rc);
                    int error = exit_locked ? pthread_create(&worker, NULL, install_main, &job) : 0;
                    started = exit_locked && error == 0;
                    page = started ? INSTALLING : RESULT;
                    install_started = sl_system_now();
                    if (!started) {
                        job.result = SL_T_SHORTCUT_FAILED;
                        if (exit_locked)
                            snprintf(job.detail, sizeof(job.detail), "worker: %d", error);
                        else
                            snprintf(job.detail, sizeof(job.detail), "exit lock: %08X", rc);
                    }
                }
            }
        }
        if (page != previous)
            draw(page, &job);
        if (page == INSTALLING) {
            uint64_t elapsed = sl_system_now() - install_started;
            uint64_t tick = elapsed / 200;
            if (tick != activity_tick) {
                /* Update one console row at 5 Hz; this is activity, not an
                 * estimated completion percentage. No worker-side output. */
                printf("\x1b[10;1H\x1b[2K[%c]  %llus", "|/-\\"[tick % 4],
                       (unsigned long long)(elapsed / 1000));
                activity_tick = tick;
            }
        }
        consoleUpdate(NULL);
    }
    consoleExit(NULL);
    if (exit_locked)
        appletUnlockExit();
    return false;
}
