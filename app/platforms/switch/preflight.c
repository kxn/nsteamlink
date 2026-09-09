#include "../common/shortcut_package.h"
#include "platform/system.h"
#include "services/i18n.h"
#include <stdio.h>
#include <switch.h>
/* libnx defaults to returning NROs to their loader, without SelfController::Exit.
 * Our HOME forwarder owns an application process and must use the normal applet
 * exit handshake instead. Never apply this to ordinary hbmenu/title takeover. */
extern u32 __nx_applet_exit_mode;
static void configure_home_exit(void) {
    u64 program_id = 0;
    if (!envIsNso() &&
        R_SUCCEEDED(svcGetInfo(&program_id, InfoType_ProgramId, CUR_PROCESS_HANDLE, 0)) &&
        program_id == SL_SHORTCUT_ID)
        __nx_applet_exit_mode = 1;
}
bool sl_system_preflight(void) {
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
    printf("\x1b[3;3H%s\n\n%s\n\n%s\n\n%s", sl_tr(SL_T_BRAND), sl_tr(SL_T_APPLET_UNSUPPORTED),
           sl_tr(SL_T_APPLET_INSTRUCTION), sl_tr(SL_T_APPLET_RETURN));
    while (appletMainLoop()) {
        padUpdate(&pad);
        if (padGetButtonsDown(&pad) & HidNpadButton_B)
            break;
        consoleUpdate(NULL);
    }
    consoleExit(NULL);
    return false;
}
