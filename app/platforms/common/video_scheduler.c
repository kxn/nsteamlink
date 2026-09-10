#include "video_scheduler.h"
static bool same(sl_video_key a, sl_video_key b) { return a.session==b.session && a.epoch==b.epoch; }
void sl_video_scheduler_init(sl_video_scheduler *s, bool enabled) {
    s->key=(sl_video_key){0}; sl_pacer_reset(&s->control,enabled);
}
static bool sync(sl_video_scheduler *s, sl_video_pipeline *p, uint64_t *pending) {
    sl_publication_snapshot snap;
    /* Fixed upper bound even if publisher outruns this reader. No frame refs. */
    for(unsigned i=0;i<SL_PUBLICATIONS/SL_PUBLICATION_READ;++i) {
        if (!sl_video_publications(p,s->key,s->control.available,&snap)) {
            sl_video_scheduler_init(s,s->control.enabled); return false;
        }
        if (!same(s->key,snap.key)) {
            sl_pacer_reset(&s->control,s->control.enabled); s->key=snap.key;
        }
        for(unsigned j=0;j<snap.count;++j)
            sl_pacer_publish(&s->control,snap.items[j].seq,snap.items[j].us);
        *pending=snap.pending;
        if (s->control.available>=snap.latest) return true;
    }
    return false; /* no speculative waiting with an incomplete history */
}
bool sl_video_scheduler_wait(sl_video_scheduler *s, sl_video_pipeline *p, uint64_t now) {
    uint64_t pending=0;
    return sync(s,p,&pending) && sl_pacer_wait(&s->control,now,pending);
}
void sl_video_scheduler_feedback(sl_video_scheduler *s, sl_video_pipeline *p,
    const sl_video_frame *candidate, uint64_t take_us, uint64_t submit_us, bool success) {
    uint64_t pending=0;
    /* Publication can race between planning and take. Read it before crediting P;
     * no cohort is settled until the next wait, after this result is known. */
    if (!sync(s,p,&pending)) return;
    if (candidate && !same(s->key,candidate->key)) return;
    sl_pacer_submit(&s->control,candidate?candidate->publish_seq:0,take_us,submit_us,success);
}
