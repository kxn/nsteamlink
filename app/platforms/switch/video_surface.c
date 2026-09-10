#include "video_surface.h"
#include <libavutil/hwcontext_nvtegra.h>
#include <stdint.h>

/* ABI: FFmpeg NVTEGRA block-linear allocator uses 64-byte width alignment,
 * 32-line luma height alignment, and two GOBs per block. Runtime checks reject
 * layouts that do not match this contract; the G1 probe verifies pixel/cache
 * behavior for the installed binary, which headers alone cannot establish. */
bool sl_nv_surface_describe(const AVFrame *frame, sl_nv_surface *out) {
    if (!frame || frame->format != AV_PIX_FMT_NVTEGRA || !frame->hw_frames_ctx || !frame->buf[0] ||
        frame->buf[0]->size < sizeof(AVNVTegraFrame) || frame->width <= 0 || frame->height <= 0 ||
        frame->width > 1920 || frame->height > 1080 || (frame->width & 1) || (frame->height & 1) ||
        (frame->flags & AV_FRAME_FLAG_INTERLACED) || frame->crop_left || frame->crop_top ||
        frame->crop_right || frame->crop_bottom)
        return false;
    AVHWFramesContext *context = (void *)frame->hw_frames_ctx->data;
    AVNVTegraFrame *hardware = (void *)frame->buf[0]->data;
    if (!context || context->sw_format != AV_PIX_FMT_NV12 || !hardware->map_ref ||
        hardware->map_ref->size < sizeof(AVNVTegraMap) || context->width < frame->width ||
        context->height < frame->height || context->width > 1920 || context->height > 1088)
        return false;
    AVNVTegraMap *map = (void *)hardware->map_ref->data;
    uintptr_t base = (uintptr_t)av_nvtegra_map_get_addr(map);
    size_t size = av_nvtegra_map_get_size(map);
    uint32_t pitch = (context->width + 63u) & ~63u, height = (context->height + 31u) & ~31u;
    size_t luma = (size_t)pitch * height, chroma = luma / 2;
    if (map->is_linear || !base || (base & 4095) || !size || (size & 4095) ||
        size > 128u * 1024u * 1024u || frame->linesize[0] != (int)pitch ||
        frame->linesize[1] != (int)pitch || (uintptr_t)frame->data[0] != base ||
        (uintptr_t)frame->data[1] < base || (uintptr_t)frame->data[1] - base != luma ||
        luma > size || chroma > size - luma)
        return false;
    *out = (sl_nv_surface){.base = (void *)base,
                           .size = size,
                           .handle = av_nvtegra_map_get_handle(map),
                           .pitch = pitch,
                           .storage_height = height,
                           .offsets = {0, luma},
                           .map = hardware->map_ref,
                           .frames = frame->hw_frames_ctx,
                           .pool = context->pool};
    return true;
}
bool sl_nv_surface_layout(DkDevice device, const sl_nv_surface *surface, unsigned plane,
                          DkImageLayout *layout) {
    if (plane > 1)
        return false;
    DkImageLayoutMaker maker;
    dkImageLayoutMakerDefaults(&maker, device);
    maker.flags = DkImageFlags_UsageVideo | DkImageFlags_CustomTileSize;
    maker.tileSize = DkTileSize_TwoGobs;
    maker.format = plane ? DkImageFormat_RG8_Unorm : DkImageFormat_R8_Unorm;
    maker.dimensions[0] = surface->pitch / (plane ? 2 : 1);
    maker.dimensions[1] = surface->storage_height / (plane ? 2 : 1);
    dkImageLayoutInitialize(layout, &maker);
    size_t limit = plane ? surface->size - surface->offsets[1] : surface->offsets[1];
    uint32_t alignment = dkImageLayoutGetAlignment(layout);
    return alignment && surface->offsets[plane] % alignment == 0 &&
           dkImageLayoutGetSize(layout) <= limit;
}
