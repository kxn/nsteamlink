/* Opt-in on-device stream observation, compiled only into a test build.
 * Uses the normal UI command and lifecycle; no new worker or exit path. */
typedef struct sl_stream_smoke {
    uint64_t began, requested, first_frame, duration_ms;
    bool announced, finished;
} sl_stream_smoke;

static void sl_stream_smoke_tick(sl_stream_smoke *s, application *a) {
    if (!s->duration_ms || s->finished)
        return;
    uint64_t now = a->ui.now;
    if (!s->announced) {
        s->announced = true;
        s->began = now;
        sl_log("smoke: stage=waiting_host build=" NSL_APP_VERSION);
    }
    if (!s->requested) {
        if (a->runtime && a->ui.page == SL_HOME) {
            sl_host_registry *r = &a->ui.store.registry;
            for (int offset = 0; offset < r->count; ++offset) {
                int index = (r->selected + offset) % r->count;
                sl_host *h = &r->hosts[index];
                if (!h->paired || !sl_host_online(h, now))
                    continue;
                r->selected = index;
                sl_ui_action(&a->ui, SL_START, 0); /* normal Desktop action */
                if (a->ui.command.type == SL_CMD_STREAM) {
                    s->requested = now;
                    sl_log("smoke: stage=connecting target=paired_host app=desktop");
                }
                break;
            }
        }
        if (!s->requested && now - s->began >= 30000) {
            sl_log("smoke: result=inconclusive reason=no_online_paired_host");
            s->finished = true;
        }
        return;
    }
    sl_runtime_facts facts;
    if (!sl_runtime_read_facts(a->runtime, &facts))
        return;
    if (!s->first_frame && facts.presented) {
        s->first_frame = now;
        sl_log("smoke: stage=first_frame");
    }
    if (facts.failed || facts.requests_closed || a->ui.page == SL_ERROR ||
        a->ui.page == SL_PIN) {
        char line[224];
        snprintf(line, sizeof(line),
                 "smoke: result=interrupted elapsed_ms=%llu first_frame=%d failed=%d closed=%d page=%d",
                 (unsigned long long)(now - s->requested), s->first_frame != 0,
                 facts.failed, facts.requests_closed, a->ui.page);
        sl_log(line);
        s->finished = true;
    } else if (!s->first_frame && now - s->requested >= 45000) {
        sl_log("smoke: result=inconclusive reason=no_first_frame");
        s->finished = true;
    } else if (s->first_frame && now - s->first_frame >= s->duration_ms) {
        sl_log("smoke: result=observed_window_complete session_remains_active=1");
        s->finished = true;
    }
}
