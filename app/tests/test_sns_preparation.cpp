/* Execute the production prepare/admit/start lifecycle. Real SDK manual
 * polling and teardown; successful BInit and signaling readiness are explicit
 * providers. This does not claim a real certificate or WAN media test. */
#include "../platforms/common/sns_backend.cpp"
#include <cassert>
static bool cloud_ready;
static unsigned bridge_updates;
extern "C" bool __wrap_sl_stream_bridge_ready(const sl_stream_bridge *) {
    return cloud_ready;
}
extern "C" void __wrap_sl_stream_bridge_update(sl_stream_bridge *, uint64_t, bool wants) {
    if (wants)
        ++bridge_updates;
}
static sl_sns *start() {
    SteamNetworkingSockets_SetManualPollMode(true);
    SteamNetworkingErrMsg err{};
    assert(GameNetworkingSockets_Init(nullptr, err));
    auto b = new sl_sns;
    b->initialized = true;
    b->sockets = SteamNetworkingSockets();
    b->config_ready = true; // Explicit successful BInit provider.
    return b;
}
int main() {
    for (unsigned round = 0; round < 2; ++round) {
        cloud_ready = false;
        bridge_updates = 0;
        auto b = start();
        assert(sl_sns_initialized(b) && !sl_sns_session_ready(b));
        assert(!sl_sns_start_session(b));
        sl_sns_update(b, 1000);
        sl_sns_update(b, 11500); // Slow bootstrap crosses the player's 10s window.
        assert(bridge_updates == 2 && !b->session_started && !b->connection_attempted);
        assert(sl_sns_get_state(b) == SL_SNS_CONNECTING && !sl_sns_session_ready(b));
        cloud_ready = true;
        sl_sns_update(b, 12000);
        assert(sl_sns_session_ready(b) && !b->connection_attempted);
        assert(sl_sns_start_session(b) && b->session_started);
        // A later CM loss cannot revoke admission or create a second IHS owner.
        cloud_ready = false;
        assert(sl_sns_session_ready(b) && sl_sns_start_session(b));
        b->connection_attempted = true; // SDK start outcome is not under test.
        b->connection = 1;              // Real invalid-handle query must retire it normally.
        sl_sns_update(b, 12001);
        assert(sl_sns_get_state(b) == SL_SNS_FAILED && !sl_sns_session_ready(b));
        sl_sns_destroy(b);
        b = start();
        cloud_ready = false;
        sl_sns_update(b, 1000);
        sl_sns_update(b, 90999);
        assert(sl_sns_get_state(b) == SL_SNS_CONNECTING && !b->connection_attempted);
        sl_sns_update(b, 91000);
        assert(sl_sns_get_state(b) == SL_SNS_FAILED && !b->connection_attempted);
        assert(b->stats.terminal_source == SL_SNS_TERMINAL_PREPARATION);
        sl_sns_destroy(b);
        b = start();
        sl_sns_update(b, 0);
        sl_sns_destroy(b); // Cancellation during preparation creates no SDK handle.
    }
    puts("PASS explicit preparation/admission, 10s-independent bootstrap, 90s cap, stable "
         "admission, two-owner cancellation/cleanup");
}
