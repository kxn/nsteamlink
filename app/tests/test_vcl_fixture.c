#include "vcl_fixture_probe.h"
#include <assert.h>
#include <stdio.h>
int main(int argc, char **argv) {
    assert(argc == 2);
    sl_video_pipeline *p = sl_video_create();
    assert(p);
    for (unsigned i = 0; i < 2; ++i) {
        const vcl_spec *s = &vcl_specs[i];
        char path[4096];
        snprintf(path, sizeof(path), "%s/%s.h264", argv[1], s->name);
        FILE *f = fopen(path, "rb");
        assert(f);
        size_t size = (size_t)s->key_bytes + s->p_bytes;
        unsigned char *data = calloc(1, size + AV_INPUT_BUFFER_PADDING_SIZE);
        assert(data);
        assert(fread(data, 1, size, f) == size && fgetc(f) == EOF);
        assert(!fclose(f));
        vcl_result r;
        const vcl_callbacks cb = {0};
#if NSL_VCL_CAPABILITY_TEST
        bool guard = false;
#else
        bool guard = i == 1;
#endif
        bool ok = vcl_run(p, (sl_video_key){i + 1, 1}, s, data, size, false, guard, &cb, &r);
        if (!ok)
            fprintf(stderr, "VCL %s failed=%s inputs=%u pictures=%u\n", s->name, r.failure,
                    r.inputs, r.pictures);
        assert(ok && r.stopped &&
               (guard ? r.guarded && r.inputs == 1 && !r.pictures : r.pictures == 2));
        sl_video_reap(p);
        free(data);
    }
    assert(sl_video_destroy(p));
    puts("VCL fixture: real I_PCM key/skip-P pixels; product guard and capability scope distinct");
    return 0;
}
