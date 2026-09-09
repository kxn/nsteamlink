#pragma once
#include "ui/ui_model.h"
#include <stdbool.h>
#include <stdint.h>
bool sl_audio_init(void);
void sl_audio_suspend(void);
void sl_audio_shutdown(void);
/* Called only by the UI callback or, while it is closed, the stream worker. */
void sl_audio_mix(int16_t *pcm, int frames, int rate, int channels);
void sl_audio_feedback(sl_ui_cue cue, bool enabled);
