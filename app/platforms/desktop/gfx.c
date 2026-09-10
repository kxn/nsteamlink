#include "gfx_backend.h"
#include <SDL.h>
#include <libavutil/hwcontext.h>
#include <libswscale/swscale.h>
#include <stdlib.h>
#include <string.h>
struct sl_gfx {
    SDL_Window *window;
    SDL_Renderer *renderer;
    SDL_Texture *video;
    AVFrame *download;
    uint64_t video_serial, video_session, video_epoch;
    struct SwsContext *sws;
    int video_width, video_height, format;
    uint64_t serial;
    sl_gfx_counters counters;
    bool recording, failed, readback_requested, readback_valid;
    unsigned char *readback;
};
static SDL_Rect rect(const sl_gfx_rect *r) {
    return (SDL_Rect){r->x, r->y, r->w, r->h};
}
sl_gfx *sl_gfx_create(const sl_gfx_config *config) {
    sl_gfx *g = calloc(1, sizeof(*g));
    if (!g)
        return NULL;
    g->window = SDL_CreateWindow(config->title, 0, 0, config->width, config->height, 0);
    if (!g->window)
        goto fail;
    g->renderer =
        SDL_CreateRenderer(g->window, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!g->renderer)
        g->renderer = SDL_CreateRenderer(g->window, -1, SDL_RENDERER_SOFTWARE);
    if (!g->renderer || SDL_RenderSetLogicalSize(g->renderer, 1280, 720))
        goto fail;
    return g;
fail:
    sl_gfx_destroy(g);
    return NULL;
}
sl_gfx_result sl_gfx_begin(sl_gfx *g) {
    if (g->failed)
        return SL_GFX_ERROR;
    if (g->recording)
        return SL_GFX_BUSY;
    g->recording = true;
    return SL_GFX_READY;
}
sl_gfx_present_result sl_gfx_present(sl_gfx *g) {
    if (!g->recording || g->failed)
        return (sl_gfx_present_result){.result = SL_GFX_ERROR};
    if (g->readback_requested)
        g->readback_valid = SDL_RenderReadPixels(g->renderer, NULL, SDL_PIXELFORMAT_RGBA32,
                                                 g->readback, 1280 * 4) == 0;
    SDL_RenderPresent(g->renderer);
    g->recording = false;
    return (sl_gfx_present_result){SL_GFX_READY, true, true, ++g->serial};
}
void sl_gfx_collect(sl_gfx *g) {
    (void)g;
}
sl_gfx_result sl_gfx_poll_drain(sl_gfx *g) {
    return g->recording ? SL_GFX_BUSY : SL_GFX_READY;
}
bool sl_gfx_healthy(const sl_gfx *g) {
    return g && !g->failed;
}
void sl_gfx_destroy(sl_gfx *g) {
    if (!g)
        return;
    SDL_DestroyTexture(g->video);
    SDL_DestroyRenderer(g->renderer);
    SDL_DestroyWindow(g->window);
    sws_freeContext(g->sws);
    av_frame_free(&g->download);
    free(g->readback);
    free(g);
}
sl_gfx_texture *sl_gfx_create_texture(sl_gfx *g, sl_gfx_format format, sl_gfx_access access, int w,
                                      int h) {
    if (format != SL_GFX_RGBA8)
        return NULL;
    return (void *)SDL_CreateTexture(
        g->renderer, SDL_PIXELFORMAT_RGBA32,
        access == SL_GFX_TARGET ? SDL_TEXTUREACCESS_TARGET : SDL_TEXTUREACCESS_STATIC, w, h);
}
void sl_gfx_destroy_texture(sl_gfx_texture *t) {
    SDL_DestroyTexture((void *)t);
}
int sl_gfx_upload(sl_gfx_texture *t, const sl_gfx_rect *r, const void *pixels, int pitch) {
    SDL_Rect box = r ? rect(r) : (SDL_Rect){0};
    return SDL_UpdateTexture((void *)t, r ? &box : NULL, pixels, pitch);
}
int sl_gfx_texture_blend(sl_gfx_texture *t, sl_gfx_blend b) {
    return SDL_SetTextureBlendMode((void *)t, b ? SDL_BLENDMODE_BLEND : SDL_BLENDMODE_NONE);
}
int sl_gfx_texture_color(sl_gfx_texture *t, uint8_t r, uint8_t g, uint8_t b) {
    return SDL_SetTextureColorMod((void *)t, r, g, b);
}
int sl_gfx_texture_alpha(sl_gfx_texture *t, uint8_t a) {
    return SDL_SetTextureAlphaMod((void *)t, a);
}
int sl_gfx_texture_linear(sl_gfx_texture *t, int linear) {
    return SDL_SetTextureScaleMode((void *)t, linear ? SDL_ScaleModeLinear : SDL_ScaleModeNearest);
}
int sl_gfx_draw_color(sl_gfx *g, uint8_t r, uint8_t b, uint8_t c, uint8_t a) {
    return SDL_SetRenderDrawColor(g->renderer, r, b, c, a);
}
int sl_gfx_draw_blend(sl_gfx *g, sl_gfx_blend b) {
    return SDL_SetRenderDrawBlendMode(g->renderer, b ? SDL_BLENDMODE_BLEND : SDL_BLENDMODE_NONE);
}
int sl_gfx_clear(sl_gfx *g) {
    return SDL_RenderClear(g->renderer);
}
int sl_gfx_fill(sl_gfx *g, const sl_gfx_rect *r) {
    SDL_Rect b = rect(r);
    return SDL_RenderFillRect(g->renderer, &b);
}
int sl_gfx_line(sl_gfx *g, int x, int y, int x2, int y2) {
    return SDL_RenderDrawLine(g->renderer, x, y, x2, y2);
}
int sl_gfx_point(sl_gfx *g, int x, int y) {
    return SDL_RenderDrawPoint(g->renderer, x, y);
}
int sl_gfx_copy(sl_gfx *g, sl_gfx_texture *t, const sl_gfx_rect *src, const sl_gfx_rect *dst) {
    SDL_Rect s = src ? rect(src) : (SDL_Rect){0}, d = dst ? rect(dst) : (SDL_Rect){0};
    return SDL_RenderCopy(g->renderer, (void *)t, src ? &s : NULL, dst ? &d : NULL);
}
int sl_gfx_copy_f(sl_gfx *g, sl_gfx_texture *t, const sl_gfx_rect *src, const sl_gfx_frect *dst) {
    SDL_Rect s = src ? rect(src) : (SDL_Rect){0};
    SDL_FRect d = dst ? (SDL_FRect){dst->x, dst->y, dst->w, dst->h} : (SDL_FRect){0};
    return SDL_RenderCopyF(g->renderer, (void *)t, src ? &s : NULL, dst ? &d : NULL);
}
int sl_gfx_target(sl_gfx *g, sl_gfx_texture *t) {
    return SDL_SetRenderTarget(g->renderer, (void *)t);
}
sl_gfx_texture *sl_gfx_get_target(sl_gfx *g) {
    return (void *)SDL_GetRenderTarget(g->renderer);
}
int sl_gfx_viewport(sl_gfx *g, const sl_gfx_rect *r) {
    SDL_Rect b = r ? rect(r) : (SDL_Rect){0};
    return SDL_RenderSetViewport(g->renderer, r ? &b : NULL);
}
void sl_gfx_get_viewport(sl_gfx *g, sl_gfx_rect *r) {
    SDL_Rect b;
    SDL_RenderGetViewport(g->renderer, &b);
    *r = (sl_gfx_rect){b.x, b.y, b.w, b.h};
}
int sl_gfx_clip(sl_gfx *g, const sl_gfx_rect *r) {
    SDL_Rect b = r ? rect(r) : (SDL_Rect){0};
    return SDL_RenderSetClipRect(g->renderer, r ? &b : NULL);
}
bool sl_gfx_request_readback(sl_gfx *g) {
    if (!g->readback)
        g->readback = malloc(1280u * 720u * 4u);
    g->readback_requested = g->readback != NULL;
    return g->readback_requested;
}
bool sl_gfx_readback(sl_gfx *g, const sl_gfx_rect *r, void *pixels, size_t bytes, int pitch) {
    sl_gfx_rect box = r ? *r : (sl_gfx_rect){0, 0, 1280, 720};
    if (!g->readback_valid || box.x < 0 || box.y < 0 || box.w <= 0 || box.h <= 0 ||
        box.w > 1280 - box.x || box.h > 720 - box.y || pitch < box.w * 4 ||
        bytes < (size_t)pitch * (box.h - 1) + (size_t)box.w * 4)
        return false;
    for (int y = 0; y < box.h; ++y)
        memcpy((unsigned char *)pixels + (size_t)y * pitch,
               g->readback + ((size_t)(box.y + y) * 1280 + box.x) * 4, (size_t)box.w * 4);
    return true;
}
bool sl_gfx_video(sl_gfx *g, sl_video_frame *lease) {
    if (lease)
        ++g->counters.video_draws;
    if (!lease) {
        if (!g->video)
            return false;
        int width = 1280, height = g->video_height * 1280 / g->video_width;
        if (height > 720) {
            height = 720;
            width = g->video_width * 720 / g->video_height;
        }
        SDL_Rect dst = {(1280 - width) / 2, (720 - height) / 2, width, height};
        return SDL_RenderCopy(g->renderer, g->video, NULL, &dst) == 0;
    }
    IHS_FrameIdentity id = IHS_FrameTicketIdentity(lease->ticket);
    if (g->video_serial == id.receiveSerial && g->video_session == id.sessionId &&
        g->video_epoch == id.epoch)
        return sl_gfx_video(g, NULL);
    const AVFrame *f = lease->pixels;
    if (f->hw_frames_ctx) {
        if (!g->download)
            g->download = av_frame_alloc();
        if (!g->download)
            return false;
        av_frame_unref(g->download);
        if (av_hwframe_transfer_data(g->download, f, 0) < 0)
            return false;
        ++g->counters.downloads;
        f = g->download;
    }
    if (f->format != AV_PIX_FMT_YUV420P && f->format != AV_PIX_FMT_NV12)
        return false;
    if (!g->video || g->video_width != f->width || g->video_height != f->height ||
        g->format != f->format) {
        SDL_DestroyTexture(g->video);
        g->video = SDL_CreateTexture(
            g->renderer, f->format == AV_PIX_FMT_NV12 ? SDL_PIXELFORMAT_NV12 : SDL_PIXELFORMAT_IYUV,
            SDL_TEXTUREACCESS_STREAMING, f->width, f->height);
        g->video_width = f->width;
        g->video_height = f->height;
        g->format = f->format;
    }
    if (!g->video)
        return false;
    int result = f->format == AV_PIX_FMT_NV12
                     ? SDL_UpdateNVTexture(g->video, NULL, f->data[0], f->linesize[0], f->data[1],
                                           f->linesize[1])
                     : SDL_UpdateYUVTexture(g->video, NULL, f->data[0], f->linesize[0], f->data[1],
                                            f->linesize[1], f->data[2], f->linesize[2]);
    if (result)
        return false;
    ++g->counters.uploads;
    g->counters.uploaded_bytes += (uint64_t)f->width * f->height * 3 / 2;
    g->video_serial = id.receiveSerial;
    g->video_session = id.sessionId;
    g->video_epoch = id.epoch;
    int width = 1280, height = f->height * 1280 / f->width;
    if (height > 720) {
        height = 720;
        width = f->width * 720 / f->height;
    }
    SDL_Rect dst = {(1280 - width) / 2, (720 - height) / 2, width, height};
    return SDL_RenderCopy(g->renderer, g->video, NULL, &dst) == 0;
}

void sl_gfx_forget_video(sl_gfx *g) {
    SDL_DestroyTexture(g->video);
    g->video = NULL;
    g->video_serial = 0;
}

void sl_gfx_finish(sl_gfx *g) {
    sl_gfx_collect(g);
}

void sl_gfx_get_counters(const sl_gfx *g, sl_gfx_counters *out) {
    *out = g->counters;
}
