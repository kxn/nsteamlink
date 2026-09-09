/* Include the production mixer to drive its callback deterministically while
 * SDL's device is paused. No alternate mixer implementation in the test. */
#include "../platforms/common/ui_audio.c"
#include <assert.h>
#include <stdlib.h>
static void feedback_model(void) {
    sl_auth_store store = {.sound = true};
    sl_ui_model m;
    sl_ui_init(&m, &store);
    m.now = 100;
    sl_ui_action(&m, SL_OPEN_OPTIONS, 0);
    assert(m.cue_serial == 1 && m.cue == SL_CUE_CONFIRM);
    sl_ui_action(&m, SL_ACCEPT, 0);
    assert(m.page == SL_SETTINGS && m.cue_serial == 2); /* nested accept emits only once */
    sl_ui_action(&m, SL_DOWN, 0);
    assert(m.cue == SL_CUE_MOVE && m.cue_serial == 3);
    sl_ui_action(&m, SL_DOWN, 0);
    assert(m.cue_serial == 3); /* repeat is rate limited */
    m.now += 100;
    sl_ui_activate(&m, 101); /* touch uses the same action as the controller */
    assert(!m.store.sound && m.cue == SL_CUE_TOGGLE);
    sl_ui_action(&m, SL_BACK, 0);
    assert(m.cue == SL_CUE_BACK);
    uint64_t n = m.cue_serial;
    sl_ui_action(&m, SL_ACCEPT, 0);
    assert(m.cue_serial == n); /* exiting overlay ignores presses */
    sl_ui_tick(&m, m.now + 200);
    sl_ui_connected(&m);
    n = m.cue_serial;
    sl_ui_action(&m, SL_START, 0);
    assert(m.cue_serial == n); /* game input is not a UI action */
}
int main(void) {
    feedback_model();
    assert(!SDL_Init(SDL_INIT_AUDIO));
    for (int launch = 0; launch < 2; ++launch) {
        assert(sl_audio_init());
        SDL_PauseAudioDevice(device, 1);
        assert(sl_audio_configure(48000, 2));
        int16_t pcm[2048], out[2048];
        for (int i = 0; i < 2048; ++i)
            pcm[i] = (i % 2 ? -1234 : 1234);
        assert(!sl_audio_queue(pcm, sizeof(pcm)));
        assert(sl_audio_queued() == sizeof(pcm));
        sl_audio_feedback(SL_CUE_NONE, false);
        callback(NULL, (Uint8 *)out, sizeof(out));
        assert(!memcmp(pcm, out, sizeof(out)) && !sl_audio_queued());
        callback(NULL, (Uint8 *)out, sizeof(out));
        for (int i = 0; i < 2048; ++i)
            assert(!out[i]);
        for (int kind = 1; kind < SL_CUE_COUNT; ++kind) {
            sl_audio_feedback(kind, true);
            long energy = 0;
            for (int block = 0; block < 8; ++block) {
                callback(NULL, (Uint8 *)out, sizeof(out));
                for (int i = 0; i < 2048; ++i) {
                    energy += abs(out[i]);
                    assert(abs(out[i]) < 6000);
                }
            }
            assert(energy > 10000);
            for (int i = 0; i < 2048; ++i)
                assert(!out[i]); /* finite cue, no looping or tail DC */
        }
        for (int i = 0; i < 2048; ++i)
            pcm[i] = 32000;
        assert(!sl_audio_queue(pcm, sizeof(pcm)));
        sl_audio_feedback(SL_CUE_CONFIRM, true);
        callback(NULL, (Uint8 *)out, sizeof(out));
        for (int i = 0; i < 2048; ++i)
            assert(out[i] > 25000); /* saturates, never wraps sign */
        sl_audio_feedback(SL_CUE_NONE, false);
        callback(NULL, (Uint8 *)out, sizeof(out));
        for (int i = 0; i < 2048; ++i)
            assert(!out[i]);
        assert(sl_audio_configure(16000, 1));
        for (int i = 0; i < 2048; ++i)
            pcm[i] = 1000;
        assert(!sl_audio_queue(pcm, sizeof(pcm)));
        assert(sl_audio_queued() > 0);
        callback(NULL, (Uint8 *)out, sizeof(out));
        for (int i = 200; i < 2048; i += 2)
            assert(out[i] == out[i + 1] && out[i] > 900);
        sl_audio_clear();
        assert(!sl_audio_queued());
        SDL_PauseAudioDevice(device, 0);
        sl_audio_feedback(SL_CUE_BACK, true);
        SDL_Delay(20);
        sl_audio_shutdown();
    }
    SDL_Quit();
    puts("PASS UI feedback semantics, PCM transparency, cue mixing/mute/resampling and repeated "
         "cleanup");
}
