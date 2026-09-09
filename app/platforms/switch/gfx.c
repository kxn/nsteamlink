#include "gfx_backend.h"
#include "video_surface.h"
#include <deko3d.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <switch.h>

#define BATCHES           2
#define QUADS             4096u
#define DESCRIPTORS       (QUADS * 2)
#define COMMAND_BYTES     (4u * 1024u * 1024u)
#define UNIFORM_BYTES     (QUADS * 256u)
#define DESCRIPTOR_OFFSET UNIFORM_BYTES
#define SAMPLER_OFFSET    (DESCRIPTOR_OFFSET + DESCRIPTORS * sizeof(DkImageDescriptor))
#define DATA_BYTES        ((SAMPLER_OFFSET + 4095u + sizeof(DkSamplerDescriptor)) & ~4095u)
#define UI_BUDGET         (64u * 1024u * 1024u)
/* 32 MiB reserved outside images: two command/data batches, swapchain,
 * shaders, and diagnostic readbacks. Software planes count as image bytes. */
_Static_assert(BATCHES *(COMMAND_BYTES + DATA_BYTES) + 2 * 1280u * 736u * 4u + 65536u +
                       BATCHES * ((1280u * 720u * 4u + 4095u) & ~4095u) <=
                   32u * 1024u * 1024u,
               "96 MiB graphics budget");
#define MAP_BUDGET     (128u * 1024u * 1024u)
#define REFERENCES     1024
#define READBACK_BYTES (1280u * 720u * 4u)

extern const unsigned char nsl_quad_vert[];
extern const size_t nsl_quad_vert_size;
extern const unsigned char nsl_quad_frag[];
extern const size_t nsl_quad_frag_size;

typedef struct image_version {
    sl_resource_ref ref;
    struct sl_gfx *gfx;
    DkMemBlock memory;
    DkImage image;
    size_t bytes;
    unsigned width, height, pitch;
    bool premultiplied, atlas;
    unsigned atlas_page, atlas_slot, x, y;
    sl_gfx_format format;
} image_version;
struct sl_gfx_texture {
    sl_gfx *gfx;
    image_version *versions[BATCHES];
    sl_gfx_access access;
    sl_gfx_format format;
    unsigned width, height;
    sl_gfx_color tint;
    sl_gfx_blend blend;
};
typedef struct imported_map {
    DkMemBlock memory;
    DkImage planes[2];
    AVBufferRef *map;
    void *base;
    size_t bytes;
    uint32_t handle, pitch, height;
    size_t offsets[2];
} imported_map;
typedef struct pool_group {
    sl_resource_ref ref;
    sl_gfx *gfx;
    bool occupied, retiring;
    sl_video_key key;
    void *domain, *pool;
    AVBufferRef *frames;
    imported_map maps[32];
    unsigned count;
} pool_group;
typedef struct batch {
    sl_gpu_batch life;
    sl_resource_ref *references[REFERENCES];
    DkCmdBuf commands;
    DkMemBlock command_memory, data, readback;
    /* WaitFence records a pointer consumed later by QueueSubmitCommands. */
    DkFence fence, available;
    unsigned quads, descriptors;
    bool readback_recorded;
} batch;
typedef struct params {
    float destination[4], uvrect[4], tint[4], viewport[4];
    float row0[4], row1[4], row2[4], options[4];
} params;
_Static_assert(sizeof(params) == 128 && offsetof(params, options) == 112, "shader parameter ABI");
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "renderer references require lock-free atomics");
struct sl_gfx {
    void (*diagnostic)(const char *);
    DkDevice device;
    DkQueue queue;
    DkSwapchain swapchain;
    DkMemBlock framebuffer_memory, code;
    DkImage outputs[2];
    DkShader vertex, fragment;
    batch batches[BATCHES];
    batch *recording;
    unsigned batch_index;
    int output;
    uint64_t serial, readback_serial;
    size_t ui_bytes, map_bytes;
    sl_gfx_counters counters;
    bool failed, readback_requested, readback_valid, finished;
    unsigned char *readback_cpu;
    sl_gfx_rect viewport, clip;
    bool clipped;
    sl_gfx_color color;
    sl_gfx_blend blend;
    sl_gfx_texture *target;
    DkMemBlock atlas[2];
    bool atlas_used[2][256];
    pool_group groups[2], *current_group;
    image_version *software[3][2];
    unsigned software_slot;
    uint64_t software_session, software_epoch, software_serial;
};
static unsigned align_up(unsigned n, unsigned alignment) {
    return (n + alignment - 1) & ~(alignment - 1);
}
static DkMemBlock memory(sl_gfx *g, unsigned bytes, unsigned flags, void *storage) {
    DkMemBlockMaker maker;
    dkMemBlockMakerDefaults(&maker, g->device, bytes);
    maker.flags = flags;
    maker.storage = storage;
    return dkMemBlockCreate(&maker);
}
static void free_image(void *context) {
    image_version *v = context;
    if (v->atlas)
        v->gfx->atlas_used[v->atlas_page][v->atlas_slot] = false;
    else {
        dkMemBlockDestroy(v->memory);
        v->gfx->ui_bytes -= v->bytes;
    }
    free(v);
}
static image_version *create_image(sl_gfx *g, unsigned width, unsigned height, sl_gfx_format format,
                                   bool target) {
    if (!width || !height || width > 4096 || height > 4096)
        return NULL;
    DkImageLayoutMaker maker;
    dkImageLayoutMakerDefaults(&maker, g->device);
    maker.format = format == SL_GFX_R8    ? DkImageFormat_R8_Unorm
                   : format == SL_GFX_RG8 ? DkImageFormat_RG8_Unorm
                                          : DkImageFormat_RGBA8_Unorm;
    maker.dimensions[0] = width;
    maker.dimensions[1] = height;
    if (target)
        maker.flags = DkImageFlags_UsageRender;
    else {
        maker.flags = DkImageFlags_PitchLinear;
        maker.pitchStride = align_up(width * (format == SL_GFX_R8    ? 1
                                              : format == SL_GFX_RG8 ? 2
                                                                     : 4),
                                     256);
    }
    DkImageLayout layout;
    dkImageLayoutInitialize(&layout, &maker);
    unsigned bytes = align_up(dkImageLayoutGetSize(&layout), DK_MEMBLOCK_ALIGNMENT);
    if (!bytes || bytes > UI_BUDGET - g->ui_bytes)
        return NULL;
    image_version *v = calloc(1, sizeof(*v));
    if (!v)
        return NULL;
    v->memory = memory(
        g, bytes, DkMemBlockFlags_CpuUncached | DkMemBlockFlags_GpuCached | DkMemBlockFlags_Image,
        NULL);
    if (!v->memory) {
        free(v);
        return NULL;
    }
    v->gfx = g;
    v->bytes = bytes;
    v->width = width;
    v->height = height;
    v->format = format;
    v->pitch = target ? 0 : maker.pitchStride;
    v->premultiplied = target;
    dkImageInitialize(&v->image, &layout, v->memory, 0);
    sl_resource_init(&v->ref, free_image, v);
    g->ui_bytes += bytes;
    return v;
}
/* Fixed cells include a transparent border. The logical LRU can evict a
 * glyph while Recording/Submitted pins keep its cell immutable. No per-miss
 * full-atlas upload or growing overflow atlas is permitted. */
static image_version *create_glyph(sl_gfx *g, unsigned width, unsigned height) {
    if (!width || !height || width > 126 || height > 126)
        return NULL;
    for (unsigned page = 0; page < 2; ++page) {
        if (!g->atlas[page]) {
            if (4u * 1024u * 1024u > UI_BUDGET - g->ui_bytes)
                return NULL;
            g->atlas[page] = memory(g, 4u * 1024u * 1024u,
                                    DkMemBlockFlags_CpuUncached | DkMemBlockFlags_GpuCached |
                                        DkMemBlockFlags_Image,
                                    NULL);
            if (!g->atlas[page])
                return NULL;
            g->ui_bytes += 4u * 1024u * 1024u;
        }
        for (unsigned slot = 0; slot < 256; ++slot)
            if (!g->atlas_used[page][slot]) {
                image_version *v = calloc(1, sizeof(*v));
                if (!v)
                    return NULL;
                *v = (image_version){.gfx = g,
                                     .memory = g->atlas[page],
                                     .width = width,
                                     .height = height,
                                     .pitch = 2048,
                                     .format = SL_GFX_R8,
                                     .atlas = true,
                                     .atlas_page = page,
                                     .atlas_slot = slot,
                                     .x = (slot % 16) * 128 + 1,
                                     .y = (slot / 16) * 128 + 1};
                unsigned char *cpu = dkMemBlockGetCpuAddr(v->memory);
                for (unsigned y = v->y - 1; y < v->y + 127; ++y)
                    memset(cpu + (size_t)y * 2048 + v->x - 1, 0, 128);
                DkImageLayoutMaker maker;
                dkImageLayoutMakerDefaults(&maker, g->device);
                maker.format = DkImageFormat_R8_Unorm;
                maker.dimensions[0] = maker.dimensions[1] = 2048;
                maker.flags = DkImageFlags_PitchLinear;
                maker.pitchStride = 2048;
                DkImageLayout layout;
                dkImageLayoutInitialize(&layout, &maker);
                dkImageInitialize(&v->image, &layout, v->memory, 0);
                sl_resource_init(&v->ref, free_image, v);
                g->atlas_used[page][slot] = true;
                return v;
            }
    }
    return NULL; /* a missing glyph cannot evict an in-flight cell */
}
static void free_group(void *context) {
    pool_group *group = context;
    for (unsigned i = 0; i < group->count; ++i) {
        imported_map *map = &group->maps[i];
        dkMemBlockDestroy(map->memory);
        group->gfx->map_bytes -= map->bytes;
        av_buffer_unref(&map->map);
    }
    av_buffer_unref(&group->frames);
    sl_video_release_mapping(group->domain);
    ++group->gfx->counters.retired_groups;
    group->occupied = false;
}
static void retire_groups(sl_gfx *g, pool_group *keep) {
    for (unsigned i = 0; i < 2; ++i)
        if (g->groups[i].occupied && &g->groups[i] != keep)
            g->groups[i].retiring = true;
    g->current_group = keep;
}
void sl_gfx_collect(sl_gfx *g) {
    if (!g)
        return;
    for (unsigned i = 0; i < BATCHES; ++i) {
        batch *b = &g->batches[i];
        if (b->life.state != SL_BATCH_SUBMITTED)
            continue;
        DkResult result = dkFenceWait(&b->fence, 0);
        if (result == DkResult_Success) {
            if (b->readback_recorded && b->life.serial > g->readback_serial) {
                memcpy(g->readback_cpu, dkMemBlockGetCpuAddr(b->readback), READBACK_BYTES);
                g->readback_serial = b->life.serial;
                g->readback_valid = true;
            }
            sl_batch_complete(&b->life, b->life.serial);
        } else if (result != DkResult_Timeout) {
            sl_batch_quarantine(&b->life);
            g->failed = true;
        }
    }
    for (unsigned i = 0; i < 2; ++i) {
        pool_group *group = &g->groups[i];
        if (group->occupied && group->retiring && atomic_load(&group->ref.references) == 1)
            sl_resource_release(&group->ref);
    }
}
static bool shader(sl_gfx *g, DkShader *shader, const unsigned char *source, size_t bytes,
                   unsigned offset) {
    if (bytes < 16 || bytes > 65536u - offset - DK_SHADER_CODE_UNUSABLE_SIZE ||
        memcmp(source, "DKSH", 4))
        return false;
    memcpy((unsigned char *)dkMemBlockGetCpuAddr(g->code) + offset, source, bytes);
    DkShaderMaker maker;
    dkShaderMakerDefaults(&maker, g->code, offset);
    dkShaderInitialize(shader, &maker);
    return dkShaderIsValid(shader);
}
static void device_diagnostic(void *context, const char *where, DkResult result,
                              const char *message) {
    sl_gfx *g = context;
    char line[512];
    snprintf(line, sizeof(line), "deko result=%u where=%s message=%s", result, where ? where : "?",
             message ? message : "?");
    g->diagnostic(line);
    if (result != DkResult_Success)
        g->failed = true;
}
sl_gfx *sl_gfx_create(const sl_gfx_config *config) {
    if (config->width != 1280 || config->height != 720)
        return NULL;
    sl_gfx *g = calloc(1, sizeof(*g));
    if (!g)
        return NULL;
    DkDeviceMaker device;
    dkDeviceMakerDefaults(&device);
    g->diagnostic = config->diagnostic;
    if (g->diagnostic) {
        device.userData = g;
        device.cbDebug = device_diagnostic;
    }
    g->device = dkDeviceCreate(&device);
    if (!g->device)
        goto fail;
    DkQueueMaker queue;
    dkQueueMakerDefaults(&queue, g->device);
    queue.flags = DkQueueFlags_Graphics;
    g->queue = dkQueueCreate(&queue);
    if (!g->queue)
        goto fail;
    DkImageLayoutMaker maker;
    dkImageLayoutMakerDefaults(&maker, g->device);
    maker.format = DkImageFormat_RGBA8_Unorm;
    maker.dimensions[0] = 1280;
    maker.dimensions[1] = 720;
    maker.flags = DkImageFlags_UsageRender | DkImageFlags_UsagePresent;
    DkImageLayout layout;
    dkImageLayoutInitialize(&layout, &maker);
    unsigned bytes = align_up(dkImageLayoutGetSize(&layout), dkImageLayoutGetAlignment(&layout));
    g->framebuffer_memory = memory(g, align_up(bytes * 2, 4096),
                                   DkMemBlockFlags_GpuCached | DkMemBlockFlags_Image, NULL);
    if (!g->framebuffer_memory)
        goto fail;
    const DkImage *outputs[2];
    for (unsigned i = 0; i < 2; ++i) {
        dkImageInitialize(&g->outputs[i], &layout, g->framebuffer_memory, i * bytes);
        outputs[i] = &g->outputs[i];
    }
    DkSwapchainMaker swapchain;
    dkSwapchainMakerDefaults(&swapchain, g->device, nwindowGetDefault(), outputs, 2);
    g->swapchain = dkSwapchainCreate(&swapchain);
    if (!g->swapchain)
        goto fail;
    g->code = memory(g, 65536,
                     DkMemBlockFlags_CpuUncached | DkMemBlockFlags_GpuCached | DkMemBlockFlags_Code,
                     NULL);
    if (!g->code || !shader(g, &g->vertex, nsl_quad_vert, nsl_quad_vert_size, 0) ||
        !shader(g, &g->fragment, nsl_quad_frag, nsl_quad_frag_size,
                align_up(nsl_quad_vert_size, 256)))
        goto fail;
    for (unsigned i = 0; i < BATCHES; ++i) {
        batch *b = &g->batches[i];
        sl_batch_init(&b->life, b->references, REFERENCES);
        b->command_memory =
            memory(g, COMMAND_BYTES, DkMemBlockFlags_CpuUncached | DkMemBlockFlags_GpuCached, NULL);
        b->data =
            memory(g, DATA_BYTES, DkMemBlockFlags_CpuUncached | DkMemBlockFlags_GpuCached, NULL);
        DkCmdBufMaker command;
        dkCmdBufMakerDefaults(&command, g->device);
        b->commands = dkCmdBufCreate(&command);
        if (!b->command_memory || !b->data || !b->commands)
            goto fail;
    }
    g->viewport = (sl_gfx_rect){0, 0, 1280, 720};
    g->color = (sl_gfx_color){0, 0, 0, 255};
    return g;
fail:
    sl_gfx_destroy(g);
    return NULL;
}
static void bind_target(sl_gfx *g, const DkImage *image) {
    DkImageView view;
    dkImageViewDefaults(&view, image);
    dkCmdBufBarrier(g->recording->commands, DkBarrier_Primitives, DkInvalidateFlags_Image);
    dkCmdBufBindRenderTarget(g->recording->commands, &view, NULL);
}
sl_gfx_result sl_gfx_begin(sl_gfx *g) {
    sl_gfx_collect(g);
    if (g->failed || g->finished)
        return SL_GFX_ERROR;
    if (g->recording)
        return SL_GFX_BUSY;
    batch *b = NULL;
    for (unsigned i = 0; i < BATCHES; ++i)
        if (g->batches[i].life.state == SL_BATCH_FREE) {
            b = &g->batches[i];
            g->batch_index = i;
            break;
        }
    if (!b)
        return SL_GFX_BUSY;
    if (g->serial == UINT64_MAX || !sl_batch_begin(&b->life, ++g->serial)) {
        g->failed = true;
        return SL_GFX_ERROR;
    }
    b->quads = b->descriptors = 0;
    b->readback_recorded = false;
    dkCmdBufClear(b->commands);
    dkCmdBufAddMemory(b->commands, b->command_memory, 0, COMMAND_BYTES);
    dkSwapchainAcquireImage(g->swapchain, &g->output, &b->available);
    g->recording = b;
    dkCmdBufWaitFence(b->commands, &b->available);
    dkCmdBufBarrier(b->commands, DkBarrier_Full,
                    DkInvalidateFlags_L2Cache | DkInvalidateFlags_Image |
                        DkInvalidateFlags_Descriptors | DkInvalidateFlags_Shader);
    g->target = NULL;
    g->viewport = (sl_gfx_rect){0, 0, 1280, 720};
    g->clipped = false;
    bind_target(g, &g->outputs[g->output]);
    DkRasterizerState raster;
    dkRasterizerStateDefaults(&raster);
    raster.cullMode = DkFace_None; /* Screen-space UI quads are two-sided. */
    DkColorWriteState write;
    dkColorWriteStateDefaults(&write);
    dkCmdBufBindRasterizerState(b->commands, &raster);
    dkCmdBufBindColorWriteState(b->commands, &write);
    const DkShader *shaders[] = {&g->vertex, &g->fragment};
    dkCmdBufBindShaders(b->commands, DkStageFlag_Vertex | DkStageFlag_Fragment, shaders, 2);
    DkGpuAddr address = dkMemBlockGetGpuAddr(b->data);
    dkCmdBufBindImageDescriptorSet(b->commands, address + DESCRIPTOR_OFFSET, DESCRIPTORS);
    dkCmdBufBindSamplerDescriptorSet(b->commands, address + SAMPLER_OFFSET, 1);
    DkSampler sampler;
    dkSamplerDefaults(&sampler);
    sampler.minFilter = sampler.magFilter = DkFilter_Linear;
    sampler.wrapMode[0] = sampler.wrapMode[1] = DkWrapMode_ClampToEdge;
    dkSamplerDescriptorInitialize(
        (void *)((unsigned char *)dkMemBlockGetCpuAddr(b->data) + SAMPLER_OFFSET), &sampler);
    return SL_GFX_READY;
}
sl_gfx_present_result sl_gfx_present(sl_gfx *g) {
    batch *b = g->recording;
    if (!b)
        return (sl_gfx_present_result){.result = SL_GFX_ERROR};
    if (g->readback_requested) {
        DkImageView source;
        dkImageViewDefaults(&source, &g->outputs[g->output]);
        DkImageRect region = {0, 0, 0, 1280, 720, 1};
        DkCopyBuf destination = {dkMemBlockGetGpuAddr(b->readback), 1280 * 4, 0};
        dkCmdBufBarrier(b->commands, DkBarrier_Full, 0);
        if (g->diagnostic && b->life.serial == 1)
            g->diagnostic("present: record-readback");
        dkCmdBufCopyImageToBuffer(b->commands, &source, &region, &destination, 0);
        b->readback_recorded = true;
    }
    if (g->diagnostic && b->life.serial == 1)
        g->diagnostic("present: record-fence");
    dkCmdBufSignalFence(b->commands, &b->fence, true);
    sl_batch_submit(&b->life);
    if (g->diagnostic && b->life.serial == 1)
        g->diagnostic("present: submit-commands");
    dkQueueSubmitCommands(g->queue, dkCmdBufFinishList(b->commands));
    if (g->diagnostic && b->life.serial == 1)
        g->diagnostic("present: queue-present");
    dkQueuePresentImage(g->queue, g->swapchain, g->output);
    if (g->diagnostic && b->life.serial == 1)
        g->diagnostic("present: returned");
    g->recording = NULL;
    return (sl_gfx_present_result){g->failed ? SL_GFX_ERROR : SL_GFX_READY, true, true,
                                   b->life.serial};
}
sl_gfx_result sl_gfx_poll_drain(sl_gfx *g) {
    sl_gfx_collect(g);
    if (g->failed)
        return SL_GFX_ERROR;
    for (unsigned i = 0; i < BATCHES; ++i)
        if (g->batches[i].life.state != SL_BATCH_FREE)
            return SL_GFX_BUSY;
    return SL_GFX_READY;
}
bool sl_gfx_healthy(const sl_gfx *g) {
    return g && !g->failed;
}
void sl_gfx_forget_video(sl_gfx *g) {
    retire_groups(g, NULL);
    for (unsigned i = 0; i < 3; ++i)
        for (unsigned p = 0; p < 2; ++p) {
            if (g->software[i][p])
                sl_resource_release(&g->software[i][p]->ref);
            g->software[i][p] = NULL;
        }
    g->software_serial = 0;
}
void sl_gfx_finish(sl_gfx *g) {
    if (!g || g->finished)
        return;
    /* A faulted queue cannot prove that the decoder backing is no longer in use.
     * Escalate to the platform fatal screen; never return dirty state to hbmenu. */
    if (g->queue && dkQueueIsInErrorState(g->queue))
        fatalThrow(MAKERESULT(Module_Libnx, LibnxError_BadInput));
    if (g->queue)
        dkQueueWaitIdle(g->queue);
    if (g->queue && dkQueueIsInErrorState(g->queue))
        fatalThrow(MAKERESULT(Module_Libnx, LibnxError_BadInput));
    for (unsigned i = 0; i < BATCHES; ++i) {
        batch *b = &g->batches[i];
        if (b->life.state == SL_BATCH_RECORDING)
            sl_batch_cancel(&b->life);
        else if (b->life.state != SL_BATCH_FREE)
            sl_batch_device_stopped(&b->life, b->life.serial);
    }
    g->recording = NULL;
    sl_gfx_forget_video(g);
    sl_gfx_collect(g);
    g->finished = true;
}
void sl_gfx_destroy(sl_gfx *g) {
    if (!g)
        return;
    /* SDK idle is the final device/compositor cleanup boundary; a timeout is
     * never substituted for proof that imported memory is no longer read. */
    sl_gfx_finish(g);
    for (unsigned i = 0; i < BATCHES; ++i) {
        batch *b = &g->batches[i];
        if (b->life.state == SL_BATCH_RECORDING)
            sl_batch_cancel(&b->life);
        else if (b->life.state != SL_BATCH_FREE)
            sl_batch_device_stopped(&b->life, b->life.serial);
    }
    sl_gfx_forget_video(g);
    for (unsigned i = 0; i < 2; ++i)
        if (g->groups[i].occupied)
            sl_resource_release(&g->groups[i].ref);
    for (unsigned i = 0; i < BATCHES; ++i) {
        batch *b = &g->batches[i];
        if (b->commands)
            dkCmdBufDestroy(b->commands);
        if (b->command_memory)
            dkMemBlockDestroy(b->command_memory);
        if (b->data)
            dkMemBlockDestroy(b->data);
        if (b->readback)
            dkMemBlockDestroy(b->readback);
    }
    for (unsigned i = 0; i < 2; ++i)
        if (g->atlas[i])
            dkMemBlockDestroy(g->atlas[i]);
    if (g->queue)
        dkQueueDestroy(g->queue);
    if (g->swapchain)
        dkSwapchainDestroy(g->swapchain);
    if (g->framebuffer_memory)
        dkMemBlockDestroy(g->framebuffer_memory);
    if (g->code)
        dkMemBlockDestroy(g->code);
    if (g->device)
        dkDeviceDestroy(g->device);
    free(g->readback_cpu);
    free(g);
}
sl_gfx_texture *sl_gfx_create_texture(sl_gfx *g, sl_gfx_format format, sl_gfx_access access,
                                      int width, int height) {
    if (width <= 0 || height <= 0 || g->failed)
        return NULL;
    sl_gfx_texture *texture = calloc(1, sizeof(*texture));
    if (!texture)
        return NULL;
    *texture = (sl_gfx_texture){.gfx = g,
                                .width = width,
                                .height = height,
                                .format = format,
                                .access = access,
                                .tint = {255, 255, 255, 255}};
    unsigned count = access == SL_GFX_TARGET ? BATCHES : 1;
    for (unsigned i = 0; i < count; ++i) {
        texture->versions[i] =
            format == SL_GFX_R8 && access == SL_GFX_STATIC
                ? create_glyph(g, width, height)
                : create_image(g, width, height, format, access == SL_GFX_TARGET);
        if (!texture->versions[i]) {
            sl_gfx_destroy_texture(texture);
            return NULL;
        }
    }
    return texture;
}
void sl_gfx_destroy_texture(sl_gfx_texture *texture) {
    if (!texture)
        return;
    for (unsigned i = 0; i < BATCHES; ++i)
        if (texture->versions[i])
            sl_resource_release(&texture->versions[i]->ref);
    free(texture);
}
int sl_gfx_upload(sl_gfx_texture *texture, const sl_gfx_rect *region, const void *data, int pitch) {
    if (!texture || texture->access == SL_GFX_TARGET || region)
        return -1;
    image_version *v = texture->versions[0];
    unsigned row = texture->width * (texture->format == SL_GFX_R8    ? 1
                                     : texture->format == SL_GFX_RG8 ? 2
                                                                     : 4);
    if (pitch < (int)row || !data)
        return -1;
    if (atomic_load(&v->ref.references) > 1) {
        image_version *next = v->atlas ? create_glyph(texture->gfx, texture->width, texture->height)
                                       : create_image(texture->gfx, texture->width, texture->height,
                                                      texture->format, false);
        if (!next)
            return -1;
        sl_resource_release(&v->ref);
        v = texture->versions[0] = next;
    }
    ++texture->gfx->counters.uploads;
    texture->gfx->counters.uploaded_bytes += (uint64_t)row * texture->height;
    unsigned char *destination =
        (unsigned char *)dkMemBlockGetCpuAddr(v->memory) + (size_t)v->y * v->pitch + v->x;
    for (unsigned y = 0; y < v->height; ++y)
        memcpy(destination + (size_t)y * v->pitch, (const unsigned char *)data + (size_t)y * pitch,
               row);
    return 0;
}
int sl_gfx_texture_blend(sl_gfx_texture *t, sl_gfx_blend b) {
    if (!t)
        return -1;
    t->blend = b;
    return 0;
}
int sl_gfx_texture_color(sl_gfx_texture *t, uint8_t r, uint8_t g, uint8_t b) {
    if (!t)
        return -1;
    t->tint.r = r;
    t->tint.g = g;
    t->tint.b = b;
    return 0;
}
int sl_gfx_texture_alpha(sl_gfx_texture *t, uint8_t a) {
    if (!t)
        return -1;
    t->tint.a = a;
    return 0;
}
int sl_gfx_texture_linear(sl_gfx_texture *t, int linear) {
    (void)linear;
    return t ? 0 : -1;
}
int sl_gfx_draw_color(sl_gfx *g, uint8_t r, uint8_t b, uint8_t c, uint8_t a) {
    g->color = (sl_gfx_color){r, b, c, a};
    return 0;
}
int sl_gfx_draw_blend(sl_gfx *g, sl_gfx_blend b) {
    g->blend = b;
    return 0;
}
int sl_gfx_clear(sl_gfx *g) {
    if (!g->recording)
        return -1;
    /* Clear the entire attachment, independent of the previous draw's scissor. */
    unsigned width = g->target ? g->target->width : 1280;
    unsigned height = g->target ? g->target->height : 720;
    DkViewport viewport = {0, 0, (float)width, (float)height, 0, 1};
    DkScissor scissor = {0, 0, width, height};
    dkCmdBufSetViewports(g->recording->commands, 0, &viewport, 1);
    dkCmdBufSetScissors(g->recording->commands, 0, &scissor, 1);
    sl_gfx_color c = g->color;
    dkCmdBufClearColorFloat(g->recording->commands, 0, DkColorMask_RGBA, c.r / 255.f, c.g / 255.f,
                            c.b / 255.f, c.a / 255.f);
    return 0;
}
static bool draw_quad(sl_gfx *g, params *p, const DkImage *first, const DkImage *second,
                      sl_gfx_blend blend) {
    batch *b = g->recording;
    if (!b)
        return false;
    if (b->quads >= QUADS || b->descriptors + 2 > DESCRIPTORS) {
        g->failed = true;
        return false;
    }
    sl_gfx_rect bounds = g->viewport;
    if (g->clipped) {
        sl_gfx_rect clip = {g->clip.x + bounds.x, g->clip.y + bounds.y, g->clip.w, g->clip.h};
        sl_gfx_intersect(&bounds, &clip, &bounds);
    }
    sl_gfx_rect target = {0, 0, g->target ? (int)g->target->width : 1280,
                          g->target ? (int)g->target->height : 720};
    sl_gfx_intersect(&bounds, &target, &bounds);
    if (!bounds.w || !bounds.h)
        return true;
    DkViewport viewport = {(float)g->viewport.x,
                           (float)g->viewport.y,
                           (float)g->viewport.w,
                           (float)g->viewport.h,
                           0,
                           1};
    DkScissor scissor = {bounds.x, bounds.y, bounds.w, bounds.h};
    dkCmdBufSetViewports(b->commands, 0, &viewport, 1);
    dkCmdBufSetScissors(b->commands, 0, &scissor, 1);
    DkColorState color;
    dkColorStateDefaults(&color);
    dkColorStateSetBlendEnable(&color, 0, blend == SL_GFX_BLEND_ALPHA);
    dkCmdBufBindColorState(b->commands, &color);
    DkBlendState state;
    dkBlendStateDefaults(&state);
    dkBlendStateSetFactors(&state, DkBlendFactor_One, DkBlendFactor_InvSrcAlpha, DkBlendFactor_One,
                           DkBlendFactor_InvSrcAlpha);
    dkCmdBufBindBlendStates(b->commands, 0, &state, 1);
    unsigned char *cpu = dkMemBlockGetCpuAddr(b->data);
    p->viewport[0] = g->viewport.w;
    p->viewport[1] = g->viewport.h;
    memcpy(cpu + b->quads * 256, p, sizeof(*p));
    DkGpuAddr address = dkMemBlockGetGpuAddr(b->data) + b->quads * 256;
    dkCmdBufBindUniformBuffer(b->commands, DkStage_Vertex, 0, address, 256);
    dkCmdBufBindUniformBuffer(b->commands, DkStage_Fragment, 0, address, 256);
    const DkImage *images[2] = {first, second ? second : first};
    if (first)
        for (unsigned i = 0; i < 2; ++i) {
            DkImageView view;
            dkImageViewDefaults(&view, images[i]);
            dkImageDescriptorInitialize(
                (void *)(cpu + DESCRIPTOR_OFFSET + b->descriptors * sizeof(DkImageDescriptor)),
                &view, false, false);
            dkCmdBufBindTexture(b->commands, DkStage_Fragment, i,
                                dkMakeTextureHandle(b->descriptors++, 0));
        }
    dkCmdBufBarrier(b->commands, DkBarrier_None,
                    DkInvalidateFlags_Image | DkInvalidateFlags_Descriptors |
                        DkInvalidateFlags_Shader);
    dkCmdBufDraw(b->commands, DkPrimitive_Triangles, 6, 1, 0, 0);
    ++b->quads;
    return true;
}
static params quad(sl_gfx_frect rectangle, sl_gfx_color tint) {
    return (params){.destination = {rectangle.x, rectangle.y, rectangle.w, rectangle.h},
                    .uvrect = {0, 0, 1, 1},
                    .tint = {tint.r / 255.f, tint.g / 255.f, tint.b / 255.f, tint.a / 255.f}};
}
int sl_gfx_fill(sl_gfx *g, const sl_gfx_rect *r) {
    params p = quad((sl_gfx_frect){r->x, r->y, r->w, r->h}, g->color);
    return draw_quad(g, &p, NULL, NULL, g->blend) ? 0 : -1;
}
int sl_gfx_point(sl_gfx *g, int x, int y) {
    sl_gfx_rect r = {x, y, 1, 1};
    return sl_gfx_fill(g, &r);
}
int sl_gfx_line(sl_gfx *g, int x, int y, int x2, int y2) {
    if (y == y2 || x == x2) {
        sl_gfx_rect r = {x < x2 ? x : x2, y < y2 ? y : y2, abs(x2 - x) + 1, abs(y2 - y) + 1};
        return sl_gfx_fill(g, &r);
    }
    int dx = abs(x2 - x), sx = x < x2 ? 1 : -1, dy = -abs(y2 - y), sy = y < y2 ? 1 : -1,
        error = dx + dy;
    for (;;) {
        if (sl_gfx_point(g, x, y))
            return -1;
        if (x == x2 && y == y2)
            return 0;
        int twice = 2 * error;
        if (twice >= dy) {
            error += dy;
            x += sx;
        }
        if (twice <= dx) {
            error += dx;
            y += sy;
        }
    }
}
int sl_gfx_copy_f(sl_gfx *g, sl_gfx_texture *t, const sl_gfx_rect *source,
                  const sl_gfx_frect *destination) {
    if (!t || !g->recording || g->target == t)
        return -1;
    image_version *v = t->versions[t->access == SL_GFX_TARGET ? g->batch_index : 0];
    if (!sl_batch_pin(&g->recording->life, &v->ref))
        return -1;
    sl_gfx_frect dst =
        destination ? *destination : (sl_gfx_frect){0, 0, g->viewport.w, g->viewport.h};
    params p = quad(dst, t->tint);
    p.options[0] = v->format == SL_GFX_R8 ? 2 : 1;
    p.options[1] = v->premultiplied;
    if (source) {
        p.uvrect[0] = (float)source->x / v->width;
        p.uvrect[1] = (float)source->y / v->height;
        p.uvrect[2] = (float)source->w / v->width;
        p.uvrect[3] = (float)source->h / v->height;
    }
    if (v->atlas) {
        p.uvrect[0] = (v->x + (source ? source->x : 0)) / 2048.f;
        p.uvrect[1] = (v->y + (source ? source->y : 0)) / 2048.f;
        p.uvrect[2] = (source ? source->w : (int)v->width) / 2048.f;
        p.uvrect[3] = (source ? source->h : (int)v->height) / 2048.f;
    }
    return draw_quad(g, &p, &v->image, NULL, t->blend) ? 0 : -1;
}
int sl_gfx_copy(sl_gfx *g, sl_gfx_texture *t, const sl_gfx_rect *src, const sl_gfx_rect *dst) {
    sl_gfx_frect d = dst ? (sl_gfx_frect){dst->x, dst->y, dst->w, dst->h} : (sl_gfx_frect){0};
    return sl_gfx_copy_f(g, t, src, dst ? &d : NULL);
}
int sl_gfx_target(sl_gfx *g, sl_gfx_texture *t) {
    if (!g->recording || (t && t->access != SL_GFX_TARGET))
        return -1;
    const DkImage *image = &g->outputs[g->output];
    if (t) {
        image_version *v = t->versions[g->batch_index];
        if (!sl_batch_pin(&g->recording->life, &v->ref))
            return -1;
        image = &v->image;
    }
    bind_target(g, image);
    g->target = t;
    g->clipped = false;
    g->viewport = (sl_gfx_rect){0, 0, t ? (int)t->width : 1280, t ? (int)t->height : 720};
    return 0;
}
sl_gfx_texture *sl_gfx_get_target(sl_gfx *g) {
    return g->target;
}
int sl_gfx_viewport(sl_gfx *g, const sl_gfx_rect *r) {
    g->viewport = r ? *r : (sl_gfx_rect){0, 0, 1280, 720};
    return 0;
}
void sl_gfx_get_viewport(sl_gfx *g, sl_gfx_rect *r) {
    *r = g->viewport;
}
int sl_gfx_clip(sl_gfx *g, const sl_gfx_rect *r) {
    g->clipped = r != NULL;
    if (r)
        g->clip = *r;
    return 0;
}
bool sl_gfx_request_readback(sl_gfx *g) {
    if (g->recording)
        return false;
    if (!g->readback_cpu)
        g->readback_cpu = malloc(READBACK_BYTES);
    if (!g->readback_cpu)
        return false;
    for (unsigned i = 0; i < BATCHES; ++i) {
        batch *b = &g->batches[i];
        if (!b->readback)
            b->readback = memory(g, align_up(READBACK_BYTES, 4096),
                                 DkMemBlockFlags_CpuUncached | DkMemBlockFlags_GpuCached, NULL);
        if (!b->readback)
            return false;
    }
    g->readback_requested = true;
    return true;
}
bool sl_gfx_readback(sl_gfx *g, const sl_gfx_rect *r, void *pixels, size_t bytes, int pitch) {
    sl_gfx_collect(g);
    sl_gfx_rect box = r ? *r : (sl_gfx_rect){0, 0, 1280, 720};
    if (!g->readback_valid || box.x < 0 || box.y < 0 || box.w <= 0 || box.h <= 0 ||
        box.w > 1280 - box.x || box.h > 720 - box.y || pitch < box.w * 4 ||
        bytes < (size_t)pitch * (box.h - 1) + (size_t)box.w * 4)
        return false;
    for (int y = 0; y < box.h; ++y)
        memcpy((unsigned char *)pixels + (size_t)y * pitch,
               g->readback_cpu + ((size_t)(box.y + y) * 1280 + box.x) * 4, (size_t)box.w * 4);
    return true;
}
static imported_map *import_surface(sl_gfx *g, sl_video_frame *frame, const sl_nv_surface *surface,
                                    pool_group **owner) {
    pool_group *group = NULL;
    for (unsigned i = 0; i < 2; ++i) {
        pool_group *candidate = &g->groups[i];
        if (!candidate->occupied)
            continue;
        bool same_key = candidate->key.session == frame->key.session &&
                        candidate->key.epoch == frame->key.epoch;
        if (same_key && candidate->frames->data == surface->frames->data)
            group = candidate;
        else {
            if (surface->pool && candidate->pool == surface->pool)
                return NULL;
            for (unsigned m = 0; m < candidate->count; ++m)
                if (candidate->maps[m].base == surface->base ||
                    candidate->maps[m].map->data == surface->map->data)
                    return NULL;
        }
    }
    bool created = false;
    if (!group) {
        for (unsigned i = 0; i < 2; ++i)
            if (!g->groups[i].occupied) {
                group = &g->groups[i];
                break;
            }
        if (!group)
            return NULL;
        AVBufferRef *frames = av_buffer_ref(surface->frames);
        if (!frames)
            return NULL;
        *group = (pool_group){.gfx = g,
                              .occupied = true,
                              .key = frame->key,
                              .frames = frames,
                              .pool = surface->pool,
                              .domain = sl_video_hold_mapping(frame)};
        sl_resource_init(&group->ref, free_group, group);
        created = true;
    }
    for (unsigned i = 0; i < group->count; ++i) {
        imported_map *map = &group->maps[i];
        if (map->map->data == surface->map->data) {
            if (map->base != surface->base || map->bytes != surface->size ||
                map->handle != surface->handle || map->pitch != surface->pitch ||
                map->height != surface->storage_height || map->offsets[0] != surface->offsets[0] ||
                map->offsets[1] != surface->offsets[1])
                return NULL;
            *owner = group;
            return map;
        }
    }
    if (group->retiring || group->count == 32 || surface->size > MAP_BUDGET - g->map_bytes)
        goto fail;
    DkImageLayout layouts[2];
    if (!sl_nv_surface_layout(g->device, surface, 0, &layouts[0]) ||
        !sl_nv_surface_layout(g->device, surface, 1, &layouts[1]))
        goto fail;
    AVBufferRef *backing = av_buffer_ref(surface->map);
    if (!backing)
        goto fail;
    DkMemBlock block =
        memory(g, surface->size,
               DkMemBlockFlags_CpuUncached | DkMemBlockFlags_GpuCached | DkMemBlockFlags_Image,
               surface->base);
    if (!block) {
        av_buffer_unref(&backing);
        goto fail;
    }
    imported_map *map = &group->maps[group->count++];
    *map = (imported_map){.memory = block,
                          .map = backing,
                          .base = surface->base,
                          .bytes = surface->size,
                          .handle = surface->handle,
                          .pitch = surface->pitch,
                          .height = surface->storage_height,
                          .offsets = {surface->offsets[0], surface->offsets[1]}};
    for (unsigned p = 0; p < 2; ++p)
        dkImageInitialize(&map->planes[p], &layouts[p], block, surface->offsets[p]);
    g->map_bytes += surface->size;
    ++g->counters.imports;
    *owner = group;
    return map;
fail:
    if (created)
        sl_resource_release(&group->ref);
    return NULL;
}
static bool yuv_params(const AVFrame *f, params *p, unsigned pitch, unsigned height) {
    bool full = f->color_range == AVCOL_RANGE_JPEG;
    bool bt709 = f->colorspace == AVCOL_SPC_BT709 ||
                 (f->colorspace == AVCOL_SPC_UNSPECIFIED && f->width >= 1280);
    if (f->colorspace != AVCOL_SPC_BT709 && f->colorspace != AVCOL_SPC_UNSPECIFIED &&
        f->colorspace != AVCOL_SPC_SMPTE170M && f->colorspace != AVCOL_SPC_BT470BG)
        return false;
    float y = full ? 1.f : 255.f / 219.f, scale = full ? 1.f : 255.f / 224.f;
    float rv = (bt709 ? 1.5748f : 1.402f) * scale, gu = (bt709 ? -.187324f : -.344136f) * scale;
    float gv = (bt709 ? -.468124f : -.714136f) * scale, bu = (bt709 ? 1.8556f : 1.772f) * scale;
    float offset = full ? 0.f : -16.f / 255.f * y;
    p->row0[0] = y;
    p->row0[2] = rv;
    p->row0[3] = offset - rv * 128.f / 255.f;
    p->row1[0] = y;
    p->row1[1] = gu;
    p->row1[2] = gv;
    p->row1[3] = offset - (gu + gv) * 128.f / 255.f;
    p->row2[0] = y;
    p->row2[1] = bu;
    p->row2[3] = offset - bu * 128.f / 255.f;
    p->options[0] = 3;
    p->viewport[2] = 1.f / pitch;
    p->viewport[3] = 1.f / height;
    if (f->chroma_location == AVCHROMA_LOC_UNSPECIFIED || f->chroma_location == AVCHROMA_LOC_LEFT)
        p->options[2] = .5f / pitch;
    else if (f->chroma_location == AVCHROMA_LOC_TOPLEFT) {
        p->options[2] = .5f / pitch;
        p->options[3] = .5f / height;
    } else if (f->chroma_location != AVCHROMA_LOC_CENTER)
        return false;
    p->uvrect[2] = (float)f->width / pitch;
    p->uvrect[3] = (float)f->height / height;
    return true;
}
static bool software_video(sl_gfx *g, sl_video_frame *frame, params *p) {
    const AVFrame *f = frame->pixels;
    if ((f->format != AV_PIX_FMT_NV12 && f->format != AV_PIX_FMT_YUV420P) || f->width <= 0 ||
        f->height <= 0 || f->width > 1920 || f->height > 1080 || (f->width & 1) ||
        (f->height & 1) || f->linesize[0] < f->width ||
        f->linesize[1] < (f->format == AV_PIX_FMT_NV12 ? f->width : f->width / 2) ||
        (f->format == AV_PIX_FMT_YUV420P && f->linesize[2] < f->width / 2))
        return false;
    if (!yuv_params(f, p, f->width, f->height))
        return false;
    IHS_FrameIdentity identity = IHS_FrameTicketIdentity(frame->ticket);
    bool same = g->software_serial == identity.receiveSerial &&
                g->software_session == identity.sessionId && g->software_epoch == identity.epoch;
    unsigned slot = g->software_slot;
    if (!same) {
        bool found = false;
        for (unsigned i = 0; i < 3; ++i) {
            if (g->software_serial && i == g->software_slot)
                continue;
            if ((!g->software[i][0] || atomic_load(&g->software[i][0]->ref.references) == 1) &&
                (!g->software[i][1] || atomic_load(&g->software[i][1]->ref.references) == 1)) {
                slot = i;
                found = true;
                break;
            }
        }
        if (!found)
            return false;
        for (unsigned plane = 0; plane < 2; ++plane) {
            image_version *v = g->software[slot][plane];
            unsigned width = f->width / (plane ? 2 : 1), height = f->height / (plane ? 2 : 1);
            if (!v || v->width != width || v->height != height) {
                image_version *next =
                    create_image(g, width, height, plane ? SL_GFX_RG8 : SL_GFX_R8, false);
                if (!next)
                    return false;
                if (v)
                    sl_resource_release(&v->ref);
                v = g->software[slot][plane] = next;
            }
            unsigned char *data = dkMemBlockGetCpuAddr(v->memory);
            for (unsigned row = 0; row < height; ++row) {
                unsigned char *dst = data + (size_t)row * v->pitch;
                if (plane && f->format == AV_PIX_FMT_YUV420P) {
                    for (unsigned x = 0; x < width; ++x) {
                        dst[2 * x] = f->data[1][(size_t)row * f->linesize[1] + x];
                        dst[2 * x + 1] = f->data[2][(size_t)row * f->linesize[2] + x];
                    }
                } else
                    memcpy(dst, f->data[plane] + (size_t)row * f->linesize[plane], f->width);
            }
        }
    }
    for (unsigned plane = 0; plane < 2; ++plane)
        if (!sl_batch_pin(&g->recording->life, &g->software[slot][plane]->ref))
            return false;
    bool drawn = draw_quad(g, p, &g->software[slot][0]->image, &g->software[slot][1]->image,
                           SL_GFX_BLEND_NONE);
    if (drawn) {
        g->software_slot = slot;
        ++g->counters.uploads;
        g->counters.uploaded_bytes += (uint64_t)f->width * f->height * 3 / 2;
        g->software_serial = identity.receiveSerial;
        g->software_session = identity.sessionId;
        g->software_epoch = identity.epoch;
        retire_groups(g, NULL);
    }
    return drawn;
}
bool sl_gfx_video(sl_gfx *g, sl_video_frame *frame) {
    if (!frame || !g->recording)
        return false;
    ++g->counters.video_draws;
    const AVFrame *f = frame->pixels;
    if (!f->width || !f->height)
        return false;
    int width = 1280, height = f->height * 1280 / f->width;
    if (height > 720) {
        height = 720;
        width = f->width * 720 / f->height;
    }
    params p = quad((sl_gfx_frect){(1280 - width) / 2, (720 - height) / 2, width, height},
                    (sl_gfx_color){255, 255, 255, 255});
    if (!f->hw_frames_ctx)
        return software_video(g, frame, &p);
    sl_nv_surface surface;
    if (!sl_nv_surface_describe(f, &surface) ||
        !yuv_params(f, &p, surface.pitch, surface.storage_height))
        return false;
    pool_group *group = NULL;
    imported_map *map = import_surface(g, frame, &surface, &group);
    if (!map)
        return false;
    if (!sl_batch_pin(&g->recording->life, &frame->ref) ||
        !sl_batch_pin(&g->recording->life, &group->ref)) {
        if (group != g->current_group)
            group->retiring = true;
        return false;
    }
    /* NVDEC receive completion and texture visibility are separate. Conservatively
     * invalidate both L2 and texture caches before sampling even a cache hit. */
    dkCmdBufBarrier(g->recording->commands, DkBarrier_Full,
                    DkInvalidateFlags_L2Cache | DkInvalidateFlags_Image);
    bool drawn = draw_quad(g, &p, &map->planes[0], &map->planes[1], SL_GFX_BLEND_NONE);
    if (drawn)
        retire_groups(g, group);
    else if (group != g->current_group)
        group->retiring = true;
    return drawn;
}

void sl_gfx_get_counters(const sl_gfx *g, sl_gfx_counters *out) {
    *out = g->counters;
    out->image_bytes = g->ui_bytes;
    out->imported_bytes = g->map_bytes;
    for (unsigned i = 0; i < 2; ++i)
        if (g->groups[i].occupied) {
            ++out->pool_groups;
            out->maps += g->groups[i].count;
        }
    for (unsigned i = 0; i < BATCHES; ++i)
        out->busy_batches += g->batches[i].life.state != SL_BATCH_FREE;
}
