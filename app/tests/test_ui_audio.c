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
    sl_ui_activate(&m, 102); /* touch uses the same action as the controller */
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
        int16_t pcm[2048], out[2048];
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
                assert(!out[i]);
        }
        sl_audio_suspend();
        assert(!device);
        for (int rate = 8000; rate <= 48000; rate += 8000)
            for (int ch = 1; ch <= 2; ++ch) {
                for (int i = 0; i < 2048; ++i)
                    pcm[i] = (i % 2 ? -1234 : 1234);
                memcpy(out, pcm, sizeof(out));
                sl_audio_feedback(SL_CUE_NONE, true);
                sl_audio_mix(out, 1024 / ch, rate, ch);
                assert(!memcmp(pcm, out, sizeof(out)));
            }
        for (int i = 0; i < 2048; ++i)
            out[i] = 32000;
        sl_audio_feedback(SL_CUE_CONFIRM, true);
        sl_audio_mix(out, 1024, 48000, 2);
        for (int i = 0; i < 2048; ++i)
            assert(out[i] > 25000);
        sl_audio_feedback(SL_CUE_NONE, false);
        memcpy(out, pcm, sizeof(out));
        sl_audio_mix(out, 1024, 48000, 2);
        assert(!memcmp(out, pcm, sizeof(out)));
        /* The stream owns SDL's only output; UI remains fully closed. */
        SDL_AudioSpec want = {.freq = 48000,
                              .format = AUDIO_S16SYS,
                              .channels = 2,
                              .samples = 1024},
                      have;
        SDL_AudioDeviceID stream =
            SDL_OpenAudioDevice(NULL, 0, &want, &have, SDL_AUDIO_ALLOW_SAMPLES_CHANGE);
        assert(stream);
        assert(!SDL_QueueAudio(stream, pcm, sizeof(pcm)));
        assert(SDL_GetQueuedAudioSize(stream) == sizeof(pcm));
        SDL_CloseAudioDevice(stream);
        assert(sl_audio_init());
        sl_audio_feedback(SL_CUE_BACK, true);
        SDL_Delay(20);
        sl_audio_shutdown();
    }
    SDL_Quit();
    puts("PASS original PCM bypass, event mixing, mute and exclusive UI/stream device handoff");
}
