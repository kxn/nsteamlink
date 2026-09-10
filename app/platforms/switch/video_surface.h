#pragma once
#include "video_pipeline.h"
#include <deko3d.h>
#include <libavutil/buffer.h>
typedef struct sl_nv_surface {
    void *base;
    size_t size;
    uint32_t handle, pitch, storage_height;
    size_t offsets[2];
    AVBufferRef *map, *frames;
    void *pool;
} sl_nv_surface;
bool sl_nv_surface_describe(const AVFrame *, sl_nv_surface *);
bool sl_nv_surface_layout(DkDevice, const sl_nv_surface *, unsigned plane, DkImageLayout *);
