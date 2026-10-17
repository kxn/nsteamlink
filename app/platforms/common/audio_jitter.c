#include "audio_jitter.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

static int minimum(int a, int b) {
    return a < b ? a : b;
}
static int wrap(int n) {
    return (n + SL_AUDIO_JITTER_CAPACITY) % SL_AUDIO_JITTER_CAPACITY;
}
int sl_audio_jitter_queued(const sl_audio_jitter *j) {
    return wrap(j->write - j->read);
}

bool sl_audio_jitter_init(sl_audio_jitter *j, int frequency, int channels) {
    if (!j || frequency < 1000 || frequency > 192000 || channels < 1 || channels > 8)
        return false;
    memset(j, 0, sizeof(*j));
    j->ring = calloc((size_t)channels * SL_AUDIO_JITTER_CAPACITY, sizeof(float));
    if (!j->ring)
        return false;
    /* BOpenAudio @7bed44..7bedb0 overrides constructor defaults. */
    static const int milliseconds[9] = {70, 80, 60, 40, 10, 500, 50, 5, 10};
    for (int i = 0; i < 9; ++i)
        j->params[i] = frequency * milliseconds[i] / 1000;
    j->params[9] = 1;
    j->channels = channels;
    j->priming = true;
    j->tracked_write = SL_AUDIO_JITTER_CAPACITY;
    j->running_min = SL_AUDIO_JITTER_CAPACITY;
    /* Constructor @7bf0f0..7bf1b8: retain separate float rounding and sinf
     * boundary. Android/host/Switch libm identity is not assumed. */
    for (int i = 0; i < 1024; ++i) {
        float angle = (float)i / 1023.0f;
        angle = angle * 0.5f;
        angle = angle * 0x1.921fb6p+1f;
        float s = sinf(angle);
        j->table[i] = s * s;
    }
    return true;
}

void sl_audio_jitter_destroy(sl_audio_jitter *j) {
    free(j->ring);
    memset(j, 0, sizeof(*j));
}

static float weight(const sl_audio_jitter *j, float phase) {
    /* ARM fcvtzs #10 truncates scaled phase. NaN converts to zero. */
    float scaled = phase * 1024.0f;
    if (!(scaled >= 1.0f))
        return j->table[0];
    if (scaled >= 1023.0f)
        return j->table[1023];
    int index = (int)scaled;
    float fraction = fmaf(phase, 1024.0f, -(float)index);
    return fmaf(j->table[index + 1] - j->table[index], fraction, j->table[index]);
}

static float sum(const sl_audio_jitter *j, int frame) {
    float total = 0.0f;
    for (int ch = 0; ch < j->channels; ++ch)
        total += j->ring[frame * j->channels + ch];
    return total;
}

/* FindBestCrossfadeEndpoint @7ca5b8. No crossing returns the original index. */
static int endpoint(const sl_audio_jitter *j, int start, int distance) {
    int direction = distance < 0 ? -1 : 1;
    int remaining = distance * direction;
    int at = start;
    bool positive = sum(j, at) > 0.0f;
    while (remaining > 1) {
        at = wrap(at + direction);
        bool next = sum(j, at) > 0.0f;
        if (positive != next)
            return at;
        positive = next;
        --remaining;
    }
    return start;
}

/* The two inline target searches have limits 300 and 100, respectively;
 * like FindBestCrossfadeEndpoint they return start if no crossing is found. */
static int search(const sl_audio_jitter *j, int start, int direction, int limit) {
    return endpoint(j, start, direction * limit);
}

int sl_audio_jitter_push(sl_audio_jitter *j, const float *input, int count) {
    int free_frames = SL_AUDIO_JITTER_CAPACITY - sl_audio_jitter_queued(j) - 1;
    int blend = 0;
    if (j->overrun) {
        if (free_frames < count) {
            j->dropped += (uint32_t)count;
            return 0;
        }
        j->overrun = false;
        blend = minimum(sl_audio_jitter_queued(j) - j->params[4], count);
        if (blend > 0) {
            j->write = wrap(j->write - blend);
            free_frames = SL_AUDIO_JITTER_CAPACITY - sl_audio_jitter_queued(j) - 1;
        }
    }
    int accepted = minimum(free_frames, count);
    if (blend <= 0) {
        int first = minimum(accepted, SL_AUDIO_JITTER_CAPACITY - j->write);
        if (first > 0)
            memcpy(j->ring + j->write * j->channels, input,
                   (size_t)first * j->channels * sizeof(float));
        if (accepted > first)
            memcpy(j->ring, input + first * j->channels,
                   (size_t)(accepted - first) * j->channels * sizeof(float));
        j->write = wrap(j->write + accepted);
    } else {
        for (int n = 0; n < accepted; ++n) {
            float *dest = j->ring + j->write * j->channels;
            if (n < blend) {
                float w = weight(j, (float)n / (float)(blend - 1));
                for (int ch = 0; ch < j->channels; ++ch)
                    dest[ch] = fmaf(1.0f - w, dest[ch], w * input[n * j->channels + ch]);
            } else {
                memcpy(dest, input + n * j->channels, (size_t)j->channels * sizeof(float));
            }
            j->write = wrap(j->write + 1);
        }
    }
    if (blend > 0) {
        j->interval = j->adjustment = 0;
    } else {
        j->dropped += (uint32_t)(count - accepted);
        if (free_frames < count)
            j->overrun = true;
    }
    return accepted;
}

static void crossfade(sl_audio_jitter *j, float *out) {
    if (j->cross_step == 0.0f)
        return;
    float w = weight(j, j->cross);
    for (int ch = 0; ch < j->channels; ++ch)
        out[ch] = fmaf(1.0f - w, out[ch], w * j->ring[j->alternate_read * j->channels + ch]);
    j->cross += j->cross_step;
    j->alternate_read = wrap(j->alternate_read + 1);
    if (j->cross_step < 0.0f && j->cross <= 0.0f) {
        /* @7ca8ac: negative fade clears only phase/step; no read switch. */
        j->cross = j->cross_step = 0.0f;
    } else if (j->cross_step > 0.0f && j->cross >= 1.0f) {
        j->cross = j->cross_step = 0.0f;
        j->read = j->alternate_read;
    }
}

static void update_stats(sl_audio_jitter *j, int requested, int remaining) {
    int queued = sl_audio_jitter_queued(j);
    j->missing += (uint32_t)remaining;
    j->interval += requested;
    j->last_queued = queued;
    if (queued < j->running_min)
        j->running_min = queued;
    if (queued > j->running_max)
        j->running_max = queued;
    int old_count = j->observations++;
    float delta = (float)queued - j->running_mean;
    j->running_mean += delta / (float)j->observations;
    j->running_m2 = fmaf(delta, (float)queued - j->running_mean, j->running_m2);
    if (j->interval < j->params[5])
        return;
    int low = j->running_min;
    j->min = low;
    j->max = j->running_max;
    if (old_count >= 2) {
        j->mean = (int)j->running_mean;
        j->variance = (int)(j->running_m2 / (float)old_count);
        j->observations = 0;
        j->running_mean = j->running_m2 = 0.0f;
    }
    j->running_min = SL_AUDIO_JITTER_CAPACITY;
    j->running_max = j->interval = 0;
    if (!j->priming && (low > j->params[1] || low < j->params[3]))
        j->adjustment = low - j->params[2];
}

int sl_audio_jitter_pop(sl_audio_jitter *j, float *output, int requested) {
    int queued = sl_audio_jitter_queued(j);
    if (j->priming && j->fade_step == 0.0f) {
        if (queued < j->params[0]) {
            j->missing += (uint32_t)requested;
            return 0;
        }
        j->priming = false;
        j->interval = j->adjustment = 0;
        if (j->fade < 1.0f)
            j->fade_step = 1.0f / (float)(j->params[6] - 1);
    }
    int saved_write = j->write;
    if (j->attempts && j->write != j->tracked_write)
        j->attempts = 0;
    int target = SL_AUDIO_JITTER_CAPACITY;
    if (!j->priming && j->cross_step == 0.0f) {
        if (j->adjustment) {
            target = search(j, j->read, 1, 300);
        } else if (queued - requested <= j->params[4]) {
            bool zero = true;
            int last = wrap(j->write - 1);
            for (int ch = 0; ch < j->channels; ++ch)
                if (j->ring[last * j->channels + ch] != 0.0f)
                    zero = false;
            if (!zero && j->attempts < j->params[9]) {
                j->adjustment = queued - (requested + j->params[j->attempts == 0 ? 2 : 0]);
                target = endpoint(j, j->read, queued > j->params[7] ? queued - j->params[7] : 0);
            } else {
                j->adjustment = 0;
                j->priming = true;
                if (j->fade_step >= 0.0f && j->fade > 0.0f) {
                    j->fade_step = -1.0f / (float)(queued - 1);
                    ++j->underflow_fades;
                }
            }
        }
    }
    int remaining = requested;
    while (remaining && queued) {
        int segment = minimum(queued, remaining);
        segment = minimum(segment, SL_AUDIO_JITTER_CAPACITY - j->read);
        if (target != SL_AUDIO_JITTER_CAPACITY)
            segment = minimum(segment, wrap(target - j->read));
        if (segment > 0) {
            if (j->fade_step == 0.0f && j->cross_step == 0.0f) {
                memcpy(output, j->ring + j->read * j->channels,
                       (size_t)segment * j->channels * sizeof(float));
                j->read = wrap(j->read + segment);
                remaining -= segment;
                output += segment * j->channels;
            } else {
                for (int n = 0; n < segment; ++n) {
                    if (j->fade_step == 0.0f && j->cross_step == 0.0f)
                        break;
                    memcpy(output, j->ring + j->read * j->channels,
                           (size_t)j->channels * sizeof(float));
                    crossfade(j, output);
                    if (j->fade_step != 0.0f) {
                        float w = weight(j, j->fade);
                        for (int ch = 0; ch < j->channels; ++ch)
                            output[ch] *= w;
                        j->fade += j->fade_step;
                        if (j->fade <= 0.0f) {
                            j->fade = j->fade_step = 0.0f;
                        } else if (j->fade >= 1.0f) {
                            j->fade = 1.0f;
                            j->fade_step = 0.0f;
                        }
                    }
                    j->read = wrap(j->read + 1);
                    output += j->channels;
                    --remaining;
                }
            }
        }
        if (target == j->read) {
            if (j->adjustment > 0) {
                if (j->cross_step == 0.0f) {
                    j->alternate_read = search(j, wrap(j->read + j->adjustment), 1, 100);
                    j->cross = 0.0f;
                    j->cross_step = 1.0f / (float)(j->params[8] - 1);
                    ++j->shrinks;
                }
            } else {
                if (j->cross_step == 0.0f) {
                    j->alternate_read = j->read;
                    j->read = search(j, wrap(j->read + j->adjustment), -1, 100);
                    j->cross = 1.0f;
                    j->cross_step = -1.0f / (float)(j->params[7] - 1);
                    ++j->expands;
                }
                j->interval = 0;
                j->tracked_write = saved_write;
                ++j->attempts;
            }
            target = SL_AUDIO_JITTER_CAPACITY;
            j->adjustment = 0;
        }
        queued = sl_audio_jitter_queued(j);
    }
    update_stats(j, requested, remaining);
    return requested - remaining;
}
