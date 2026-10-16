#include "sdr_policy.h"
#include <limits.h>
#include <string.h>

int32_t sl_sdr_comparison_score(int32_t forward, int32_t reverse) {
    if (forward == INT_MAX || reverse == INT_MAX)
        return forward;
    return (int32_t)(((int64_t)forward + reverse) / 2);
}
static bool better(const sl_sdr_candidate *a, const sl_sdr_candidate *b) {
    if (a->score != b->score) return a->score < b->score;
    if (a->migration != b->migration) return a->migration < b->migration;
    return a->shutdown_seconds > b->shutdown_seconds;
}
static void probe(sl_sdr_selection *s, const sl_sdr_candidate *c, int i) {
    if (!c[i].ping_pending) s->probe[i] = true;
}
bool sl_sdr_select(const sl_sdr_candidate *c, size_t count, int32_t primary, int32_t backup,
                   bool migration_pending, int64_t now, sl_sdr_selection *out) {
    if (!out || count > SL_SDR_CANDIDATES || (!c && count)) return false;
    sl_sdr_selection s = {.primary = -1, .backup = -1};
    int sorted[SL_SDR_CANDIDATES], n = 0;
    bool current_valid = false;
    for (size_t i = 0; i < count; ++i) {
        if (!c[i].eligible) continue;
        int at = n++;
        while (at && better(&c[i], &c[sorted[at - 1]])) {
            sorted[at] = sorted[at - 1];
            --at;
        }
        sorted[at] = (int)i;
        current_valid |= (int)i == primary;
    }
    if (!n) { *out = s; return true; }
    s.primary = current_valid ? primary : sorted[0];
    const sl_sdr_candidate *best = &c[sorted[0]];
    if (current_valid) {
        const sl_sdr_candidate *current = &c[primary];
        for (int k = 0; k < n && sorted[k] != primary; ++k) {
            int i = sorted[k];
            const sl_sdr_candidate *candidate = &c[i];
            /* Keep the sample's f32 rounding and truncation; do not replace
             * this threshold with a percentage comparison on integer scores. */
            volatile float fraction = 0.1f * (float)candidate->maximum;
            float threshold = (float)candidate->maximum + 10.0f + fraction;
            if (!migration_pending && current->minimum < (int32_t)threshold &&
                current->shutdown_seconds >= best->shutdown_seconds)
                break;
            bool fresh = candidate->last_received + 250000 >= now;
            bool urgent = current->draining || current->alternate_penalty > 8190 ||
                best->migration == -1 || current->migration == 1;
            bool large_benefit = candidate->maximum + 50 < current->minimum &&
                 best->other_penalty + 50 < current->other_penalty;
            if (urgent || current->gap || large_benefit) {
                if (fresh && (urgent || !current->gap || candidate->last_received >= current->last_received)) {
                    s.primary = i;
                    break;
                }
                probe(&s, c, i);
                continue;
            }
            bool needs_probe = candidate->front_samples < 3 || candidate->front_oldest + 5000000 < now;
            bool due = candidate->last_ping_sent + 200000 <= now || candidate->bucket_end <= now;
            bool confirmed = !needs_probe && best->buckets >= 15 && fresh;
            if (confirmed && current->buckets >= 15) {
                s.primary = i;
                break;
            }
            if (current->buckets < 15 && due)
                probe(&s, c, primary); /* Candidate's clock, deliberately. */
            if (needs_probe || !fresh || (!confirmed && due))
                probe(&s, c, i);
        }
    }
    /* The P2P caller first removes active entries with no target token. The
     * base selector itself retains an old backup when no other POP qualifies. */
    if (current_valid && s.primary == primary && backup >= 0 &&
        (size_t)backup < count && backup != s.primary)
        s.backup = backup;
    for (int k = 0; k < n; ++k)
        if (c[sorted[k]].cluster != c[s.primary].cluster) {
            s.backup = sorted[k];
            break;
        }
    *out = s;
    return true;
}
unsigned sl_sdr_expire(sl_sdr_timeouts *t, int64_t now) {
    unsigned events = 0;
    if (t->ping_deadline && t->ping_deadline <= now) {
        t->ping_deadline = 0;
        ++t->ping_failures;
        events |= SL_SDR_TIMEOUT_PING;
    }
    if (t->ping_failures >= ((!t->last_received && !t->established) ? 2u : 4u))
        return events | SL_SDR_TIMEOUT_REMOVE;
    if (t->request_deadline && t->request_deadline <= now) {
        t->request_deadline = 0;
        events |= SL_SDR_TIMEOUT_REQUEST;
        if (++t->request_failures >= 4)
            return events | SL_SDR_TIMEOUT_REMOVE;
        if (!(t->request_failures & 1))
            events |= SL_SDR_TIMEOUT_REPROBE;
    }
    return events;
}
bool sl_sdr_warn_downtime(sl_sdr_downtime *t, int32_t seconds, float random_seconds, int64_t now) {
    if (!(random_seconds >= 45.0f && random_seconds <= 60.0f)) return false;
    int64_t shutdown = now + (int64_t)seconds * 1000000;
    if (t->known && shutdown >= t->shutdown - 3000000) return false;
    t->known = true;
    t->shutdown = shutdown;
    t->avoid = shutdown - (int64_t)(random_seconds * 1000000.0f);
    return true;
}
bool sl_sdr_probe_priority(const sl_sdr_probe_input *p, bool need_primary, bool need_backup, float *out) {
    if (p->special > 0 && p->probes < 8) { *out = -1e30f; return true; }
    bool ordinary = p->pop_type == 1;
    bool unreachable = p->failures >= 4 || p->reachability < 0;
    float numerator;
    if (p->ping < 0) {
        if (p->probes < 4 || !unreachable) {
            *out = p->estimate + (p->tier >= 1 && p->special <= 0 ? 10000.0f : 0);
            return true;
        }
        numerator = (float)(int)(p->estimate + 2000.0f);
    } else numerator = (float)(p->ping + 50);
    if (p->probes >= 8) {
        if (!ordinary && !need_primary && p->special < 1) return false;
        if (p->ping >= 0 && p->front_samples >= 3 && p->received >= 8 &&
            (!need_primary || p->since_received <= 120000000)) return false;
        if (!need_backup && unreachable && p->since_sent < 120000000) return false;
    }
    numerator += ordinary ? 0.0f : 75.0f;
    float age = p->since_sent > 0 ? (float)p->since_sent / 1000000.0f : 0.0f;
    *out = 20000.0f + numerator / (age + 0.5f);
    return true;
}
bool sl_sdr_routing_ready(int ordinary, int measured, int fast, int medium, int broad, int64_t age) {
    int threshold = ordinary * 80 / 100;
    if (threshold > 15) threshold = 15;
    return measured >= threshold && (age > 7000000 || fast >= 1 || medium >= 2 || broad >= 4);
}
static void remove_address(sl_sdr_failure_cache *c, unsigned i) {
    memmove(c->entries + i, c->entries + i + 1, (--c->count - i) * sizeof(c->entries[0]));
}
bool sl_sdr_address_failed(const sl_sdr_failure_cache *c, uint64_t address) {
    for (unsigned i = 0; i < c->count; ++i)
        if (c->entries[i].address == address) return true;
    return false;
}
void sl_sdr_fail_address(sl_sdr_failure_cache *c, uint64_t address, unsigned advertised, int64_t now) {
    bool unreachable = c->failures > 4 || c->count >= 2;
    bool removed = false;
    for (unsigned i = 0; i < c->count; ++i)
        if (c->entries[i].address == address) { remove_address(c, i); removed = true; break; }
    if (!removed && c->count && (c->count >= 3 || c->count >= advertised)) remove_address(c, 0);
    c->entries[c->count++] = (sl_sdr_failed_address){address, now};
    if (unreachable) c->reachability = -1;
}
void sl_sdr_expire_addresses(sl_sdr_failure_cache *c, unsigned advertised, int64_t now) {
    for (unsigned i = c->count; i-- > 0;)
        if (c->entries[i].failed + 120000000 < now) remove_address(c, i);
    if (c->count && c->count >= advertised) remove_address(c, 0);
    if (c->last_probe + 120000000 < now) c->failures = 0;
}
void sl_sdr_address_received(sl_sdr_failure_cache *c, uint64_t address) {
    for (unsigned i = 0; i < c->count; ++i)
        if (c->entries[i].address == address) { remove_address(c, i); break; }
    c->failures = 0;
    c->reachability = 1;
}
