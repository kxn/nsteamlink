/* App's real wait predicate and public transport-stage getter. */
#include "connection_wait.h"
#include "test_session.h"
#include "session/session_pri.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

int main(void) {
    IHS_Init();
    IHS_Session *session = IHS_TestSessionCreate();
    assert(session && !IHS_SessionIsConnectionPending(NULL));
    for (int phase = IHS_SessionConnectionStateUnconnected;
         phase <= IHS_SessionConnectionStateStopping; ++phase) {
        atomic_store(&session->state.connectionState, phase);
        assert(IHS_SessionIsConnectionPending(session) ==
               (phase <= IHS_SessionConnectionStateConnecting));
    }
    atomic_store(&session->state.connectionState, IHS_SessionConnectionStateConnecting);
    atomic_store(&session->transport.closeRequested, true);
    assert(!IHS_SessionIsConnectionPending(session));
    atomic_store(&session->transport.closeRequested, false);
    atomic_store(&session->transport.shutdown, 1);
    assert(!IHS_SessionIsConnectionPending(session));
    atomic_store(&session->transport.shutdown, 0);
    unsigned pending;
    uint32_t begin, now;
    while (scanf("%u %" SCNu32 " %" SCNu32, &pending, &begin, &now) == 3)
        printf("%d\n", sl_connection_wait_expired(pending != 0, begin, now));
    assert(sl_connection_wait_tick(0) == 0);
    assert(sl_connection_wait_tick(10000) == 655360);
    assert(sl_connection_wait_tick(65536000) == 0);
    atomic_store(&session->state.connectionState, IHS_SessionConnectionStateUnconnected);
    IHS_SessionDestroy(session);
    IHS_Quit();
    return 0;
}
