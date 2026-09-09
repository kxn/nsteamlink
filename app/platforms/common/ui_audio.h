#pragma once
#include "ui/ui_model.h"
#include <stdbool.h>
#include <stdint.h>
/* Lifecycle and PCM methods run under media.audio_lock; UI methods are atomic. */
bool sl_audio_init(void);
void sl_audio_shutdown(void);
bool sl_audio_configure(int frequency, int channels);
void sl_audio_clear(void);
uint32_t sl_audio_queued(void);
int sl_audio_queue(const void *pcm, uint32_t bytes);
void sl_audio_feedback(sl_ui_cue cue, bool enabled);
