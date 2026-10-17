#include "sdr_policy.h"
#include <limits.h>
#include <string.h>
#include <stdlib.h>

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
static bool probe_unreachable(const sl_sdr_probe_input *p) {
    return p->failures >= 4 || (p->failures >= 2 && p->failed_addresses > 0) || p->reachability < 0;
}
bool sl_sdr_front_eligible(int pop_type, int ping, int reachability, int special) {
    return ping >= 0 && ((reachability >= 1 && pop_type == 1) || special >= 1);
}
typedef struct advert_order { int32_t key[5]; unsigned index; } advert_order;
static int advert_compare(const void *left, const void *right) {
    const advert_order *a=left, *b=right;
    for (unsigned i=0; i<5; ++i)
        if (a->key[i] != b->key[i]) return a->key[i] < b->key[i] ? -1 : 1;
    return (a->index > b->index)-(a->index < b->index);
}
static int32_t advert_score(int32_t value, bool new_item) {
    if (value > 9999) return SL_SDR_UNKNOWN;
    return new_item ? value+value/15+5 : value;
}
bool sl_sdr_old_metric_valid(int32_t current, int32_t previous, int32_t low, int32_t high) {
    if (current < 0 || previous < 0) return false;
    int32_t minimum=current < previous ? current : previous;
    int64_t difference=(int64_t)current-previous;
    if (difference < 0) difference=-difference;
    return difference < 5+minimum/15 || (low >= 0 && previous >= low && previous <= high);
}
bool sl_sdr_mark_advertisement(const sl_sdr_advert_cluster *clusters, size_t nc,
    const sl_sdr_advert_route *routes, size_t nr, bool old_mode,
    uint8_t *cluster_ranks, uint8_t *route_ranks) {
    if (nc > SL_SDR_CANDIDATES || nr > SL_SDR_ADVERT_ROUTES_MAX ||
        (nc && (!clusters || !cluster_ranks)) || (nr && (!routes || !route_ranks))) return false;
    advert_order *order=malloc((nr > nc ? nr : nc)*sizeof(*order)+1);
    uint8_t *ranks=calloc(nr+1,1), cranks[SL_SDR_CANDIDATES]={0};
    if (!order || !ranks) { free(order); free(ranks); return false; }
    bool ok=false;
    for (size_t i=0; i<nr; ++i) {
        const sl_sdr_advert_route *r=&routes[i];
        if (r->local >= nc || r->remote >= nc || r->forward < 0 || r->reverse < 0) goto done;
        if (r->forced) {
            if (old_mode && !r->old_member) goto done;
            ranks[i]=4;
        }
    }
    for (unsigned pass=0; pass<4; ++pass) {
        for (size_t i=0; i<nr; ++i) {
            const sl_sdr_advert_route *r=&routes[i];
            int32_t forward=r->forced ? -SL_SDR_UNKNOWN : advert_score(r->forward,old_mode && !r->old_member);
            int32_t reverse=r->forced ? -SL_SDR_UNKNOWN : advert_score(r->reverse,old_mode && !r->old_member);
            int32_t first=(pass==1 || pass==2) ? reverse : forward;
            int32_t second=(pass==1 || pass==2) ? forward : reverse;
            advert_order entry={.index=(unsigned)i};
            entry.key[0]=pass < 2 ? -r->internal : first;
            entry.key[1]=pass < 2 ? first : second;
            entry.key[2]=pass < 2 ? second : -r->internal;
            entry.key[3]=(int32_t)r->local; entry.key[4]=(int32_t)r->remote;
            order[i]=entry;
        }
        qsort(order,nr,sizeof(*order),advert_compare);
        for (size_t position=0; position<nr && position<4; ++position) {
            unsigned i=order[position].index;
            if (position < 2) {
                if (old_mode && !routes[i].old_member) goto done;
                ranks[i]=3;
            } else if (!ranks[i]) ranks[i]=1;
        }
    }
    for (size_t i=0; i<nc; ++i) {
        const sl_sdr_advert_cluster *c=&clusters[i];
        cranks[i]=c->remote_used && c->ping >= 0 ? 2 : 0;
        int64_t score=(int64_t)c->ping+c->penalty;
        if (score < 0 || score > INT_MAX) goto done;
        order[i]=(advert_order){.key={advert_score((int32_t)score,old_mode && !c->old_member),
            (int32_t)i,0,0,0},.index=(unsigned)i};
    }
    for (size_t i=0; i<nr; ++i) {
        unsigned local=routes[i].local;
        if (ranks[i] > cranks[local]) cranks[local]=ranks[i];
        if (old_mode && cranks[local] >= 3 && !clusters[local].old_member) goto done;
    }
    qsort(order,nc,sizeof(*order),advert_compare);
    for (size_t position=0; position<nc && position<6; ++position) {
        unsigned i=order[position].index;
        if (clusters[i].ping < 0 || clusters[i].special < 0) break;
        if (position < 4) {
            if (old_mode && !clusters[i].old_member) goto done;
            if (cranks[i] < 3) cranks[i]=3;
        } else if (!cranks[i]) cranks[i]=1;
    }
    if (nc) memcpy(cluster_ranks,cranks,nc);
    if (nr) memcpy(route_ranks,ranks,nr);
    ok=true;
done:
    free(order); free(ranks);
    return ok;
}
bool sl_sdr_order_advertisement(const sl_sdr_advert_cluster *clusters, size_t nc,
    const sl_sdr_advert_route *routes, size_t nr, bool old_mode,
    const uint8_t *cluster_ranks, const uint8_t *route_ranks,
    unsigned *cluster_order, unsigned *route_order) {
    if (nc > SL_SDR_CANDIDATES || nr > SL_SDR_ADVERT_ROUTES_MAX ||
        (nc && (!clusters || !cluster_ranks || !cluster_order)) ||
        (nr && (!routes || !route_ranks || !route_order))) return false;
    for (size_t i=0; i<nc; ++i) {
        int64_t value=(int64_t)clusters[i].ping+clusters[i].penalty;
        if (value < 0 || value > INT_MAX) return false;
    }
    for (size_t i=0; i<nr; ++i)
        if (routes[i].local >= nc || routes[i].remote >= nc ||
            routes[i].forward < 0 || routes[i].reverse < 0) return false;
    advert_order *order=malloc((nr > nc ? nr : nc)*sizeof(*order)+1);
    if (!order) return false;
    for (size_t i=0; i<nc; ++i)
        order[i]=(advert_order){.key={-(int32_t)cluster_ranks[i],
            advert_score(clusters[i].ping+clusters[i].penalty,old_mode && !clusters[i].old_member),
            (int32_t)i,0,0},.index=(unsigned)i};
    qsort(order,nc,sizeof(*order),advert_compare);
    for (size_t i=0; i<nc; ++i) cluster_order[i]=order[i].index;
    for (size_t i=0; i<nr; ++i)
        order[i]=(advert_order){.key={-(int32_t)route_ranks[i],
            routes[i].forced ? -SL_SDR_UNKNOWN : advert_score(routes[i].forward,old_mode && !routes[i].old_member),
            (int32_t)routes[i].local,(int32_t)routes[i].remote,0},.index=(unsigned)i};
    qsort(order,nr,sizeof(*order),advert_compare);
    for (size_t i=0; i<nr; ++i) route_order[i]=order[i].index;
    free(order);
    return true;
}
bool sl_sdr_probe_priority(const sl_sdr_probe_input *p, bool active_connection, bool need_backup, float *out) {
    if (p->special > 0 && p->probes < 8) { *out = -1e30f; return true; }
    bool ordinary = p->pop_type == 1;
    bool unreachable = probe_unreachable(p);
    float numerator;
    if (p->ping < 0) {
        if (p->probes < 4 || !unreachable) {
            *out = p->estimate + (p->tier >= 1 && p->special <= 0 ? 10000.0f : 0);
            return true;
        }
        numerator = (float)(int)(p->estimate + 2000.0f);
    } else numerator = (float)(p->ping + 50);
    if (p->probes >= 8) {
        if (!ordinary && !active_connection && p->special < 1) return false;
        if (p->ping >= 0 && p->front_samples >= 3 && p->received >= 8 &&
            (!active_connection || p->since_received <= 120000000)) return false;
        if (!need_backup && unreachable && p->since_sent < 120000000) return false;
    }
    numerator += ordinary ? 0.0f : 75.0f;
    float age = p->since_sent > 0 ? (float)p->since_sent / 1000000.0f : 0.0f;
    *out = 20000.0f + numerator / (age + 0.5f);
    return true;
}
bool sl_sdr_plan_probes(const sl_sdr_probe_input *inputs, size_t count, int nearest_limit,
    bool active_connection, bool need_backup, sl_sdr_probe_plan *out) {
    if (!out || count > SL_SDR_CANDIDATES || (count && !inputs)) return false;
    sl_sdr_probe_plan plan = {.cutoff=1e30f,.budget=need_backup || !active_connection ? 10u : 1u};
    unsigned nonfailed = 0, initial_other = 0, measured_tier_zero = 0;
    unsigned limit = nearest_limit > 5 ? (unsigned)nearest_limit : 5;
    for (size_t i=0; i<count; ++i) {
        const sl_sdr_probe_input *p=&inputs[i];
        bool unreachable=probe_unreachable(p);
        nonfailed += !unreachable;
        bool ordinary=p->pop_type == 1;
        if (ordinary && p->tier == 0) measured_tier_zero += p->ping >= 0;
        else if (p->special <= 0 && p->tier >= 1 && nonfailed > limit) continue;
        float priority;
        if (!sl_sdr_probe_priority(p,active_connection,need_backup,&priority)) continue;
        plan.candidates[plan.count++]=(sl_sdr_probe_candidate){(unsigned)i,priority};
        if (!(p->special > 0 && p->probes < 8) && p->ping < 0 &&
            (p->probes < 4 || !unreachable) && !(p->tier >= 1 && p->special <= 0))
            ++initial_other;
    }
    if (initial_other > measured_tier_zero) plan.cutoff=10000.0f;
    *out=plan;
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
int sl_sdr_state_action(int state) {
    switch (state) {
    case -3: case 0: return SL_SDR_STATE_IGNORE;
    case -2: case 1: case 2: case 3: return SL_SDR_STATE_THINK;
    case -1: case 4: case 5: return SL_SDR_STATE_CLOSE;
    default: return SL_SDR_STATE_INVALID;
    }
}
int sl_sdr_established_action(int state) {
    int action = sl_sdr_state_action(state);
    return action == SL_SDR_STATE_IGNORE ? SL_SDR_STATE_INVALID : action;
}
bool sl_sdr_clean_active(const bool *desired, size_t count, int32_t *primary, int32_t *backup) {
    if (!primary || !backup || count > SL_SDR_CANDIDATES || (!desired && count)) return false;
    if (*primary < 0 || (size_t)*primary >= count || !desired[*primary]) *primary = -1;
    if (*backup < 0 || (size_t)*backup >= count || !desired[*backup] || *backup == *primary) *backup = -1;
    if (*primary < 0) { *primary = *backup; *backup = -1; }
    return true;
}
static sl_sdr_latency *latency_get(sl_sdr_latencies *cache, uint32_t pop, bool create) {
    if (!cache || cache->count > SL_SDR_CANDIDATES) return NULL;
    for (size_t i=0; i<cache->count; ++i)
        if (cache->entries[i].pop == pop) return &cache->entries[i];
    if (!create || cache->count == SL_SDR_CANDIDATES) return NULL;
    sl_sdr_latency *entry=&cache->entries[cache->count++];
    *entry=(sl_sdr_latency){.pop=pop,.ping=-1};
    return entry;
}
const sl_sdr_latency *sl_sdr_latency_find(const sl_sdr_latencies *cache, uint32_t pop) {
    if (!cache || cache->count > SL_SDR_CANDIDATES) return NULL;
    for (size_t i=0; i<cache->count; ++i)
        if (cache->entries[i].pop == pop) return &cache->entries[i];
    return NULL;
}
bool sl_sdr_latencies_begin(sl_sdr_latencies *cache, uint32_t flags, int64_t now) {
    if (!cache || cache->count > SL_SDR_CANDIDATES || (flags & 1)) return false;
    for (size_t i=0; i<cache->count; ++i) cache->entries[i].measured=0;
    cache->last_full=now;
    return true;
}
bool sl_sdr_latency_measure(sl_sdr_latencies *cache, uint32_t pop, int32_t ping, bool p2p, int64_t now) {
    sl_sdr_latency *entry=latency_get(cache,pop,true);
    if (!entry) return false;
    *entry=(sl_sdr_latency){.pop=pop,.ping=ping,.flags=p2p ? 0x20000000u : 0,.measured=now};
    return true;
}
void sl_sdr_latency_estimate(sl_sdr_latencies *cache, uint32_t pop, int32_t ping) {
    sl_sdr_latency *entry=latency_get(cache,pop,true);
    if (entry && !entry->measured) entry->ping=ping;
}
void sl_sdr_latency_exception(sl_sdr_latencies *cache, uint32_t pop, uint32_t flags, int32_t penalty) {
    sl_sdr_latency *entry=latency_get(cache,pop,false);
    if (entry) { entry->flags |= flags; entry->penalty=penalty; }
}
int32_t sl_sdr_cluster_penalty(int32_t incoming) {
    return incoming < 0 ? 0 : incoming > 5000 ? 5000 : incoming;
}
bool sl_sdr_route_estimates(const int32_t *front, size_t count, const sl_sdr_edge *edges,
    size_t edge_count, int32_t *out) {
    if (count > SL_SDR_CANDIDATES || edge_count > SL_SDR_CANDIDATES*SL_SDR_CANDIDATES ||
        (!front && count) || (!out && count) || (!edges && edge_count)) return false;
    for (size_t i=0; i<edge_count; ++i)
        if (edges[i].source >= count || edges[i].target >= count) return false;
    int32_t upper[SL_SDR_CANDIDATES], lower[SL_SDR_CANDIDATES];
    for (size_t i=0; i<count; ++i) {
        upper[i]=front[i] >= 0 ? front[i] : SL_SDR_UNKNOWN;
        lower[i]=front[i];
    }
    for (unsigned pass=0; pass<3; ++pass) {
        bool changed=false;
        for (size_t source=0; source<count; ++source) {
            if ((uint32_t)upper[source] > 2000) continue;
            for (size_t i=0; i<edge_count; ++i) {
                const sl_sdr_edge *edge=&edges[i];
                if (edge->source != source || edge->ping < 0 || front[edge->target] >= 0) continue;
                int64_t candidate=(int64_t)upper[source]+edge->ping;
                /* Such an overflow makes the original assert that the
                 * estimate is non-negative; reject this invalid graph. */
                if (candidate > INT_MAX) return false;
                if (candidate < upper[edge->target]) {
                    upper[edge->target]=(int32_t)candidate; changed=true;
                }
                if (front[source] >= 0) {
                    int32_t bound=upper[source]-edge->ping;
                    if (bound < 0) bound=0;
                    if (bound > lower[edge->target]) lower[edge->target]=bound;
                }
            }
        }
        if (!changed) break;
    }
    for (size_t i=0; i<count; ++i)
        if (front[i] < 0 && upper[i] < SL_SDR_UNKNOWN && lower[i] >= 0)
            upper[i]=(int32_t)(((int64_t)upper[i]+lower[i])/2);
    if (count) memcpy(out,upper,count*sizeof(*out));
    return true;
}
bool sl_sdr_router_ping_ms(uint32_t timestamp, int64_t now, int32_t *ping) {
    int32_t age=(int32_t)((uint32_t)now-timestamp);
    if (!ping || age > 10000000 || (age < 0 && ((timestamp & 1) || age < -2000))) return false;
    *ping=age < 0 ? 0 : age/1000;
    return true;
}
bool sl_sdr_router_cookie(uint32_t cookie, uint32_t root_cookie, uint32_t session_id, bool have_session) {
    return cookie==root_cookie || (have_session && cookie==session_id);
}
size_t sl_sdr_ping_request_size(int64_t last_full, int64_t now) {
    return last_full > now-5000000 ? 100 : 1300;
}

static bool stats_aggressive(const sl_sdr_stats_probe *s, int64_t now) {
    return s->activity == 0 && s->failures > 0 && s->last_immediate_request+200000 <= now;
}
static bool stats_keepalive(const sl_sdr_stats_probe *s, int64_t now) {
    return s->pending && ((s->activity == 0 && s->last_received+10000000 <= now) ||
        (s->activity == 1 && s->last_received+60000000 <= now));
}
uint32_t sl_sdr_stats_request_flags(const sl_sdr_stats_probe *r,
    const sl_sdr_stats_probe *e, int request, int mode, uint32_t flags, bool content, int64_t now) {
    bool relay_opportunity = false, e2e_opportunity = false;
    if (request == 3 || stats_aggressive(r, now)) flags |= 5;
    else if (request == 2 || stats_keepalive(r, now)) flags |= 1;
    else if (r->activity == 0) {
        relay_opportunity = r->last_ping+5000000 < now;
        if (r->last_ping+7000000 < now) flags |= 1;
    }
    if (mode >= 1) {
        if ((request == 3 && mode == 2) || stats_aggressive(e, now)) flags |= 7;
        else if ((request == 2 && mode == 2) || stats_keepalive(e, now)) flags |= 2;
        else if (e->activity == 0) {
            e2e_opportunity = e->last_ping+5000000 < now;
            if (e->last_ping+7000000 < now) flags |= 2;
        }
    }
    if (flags || content) {
        if (relay_opportunity) flags |= 1;
        if (e2e_opportunity) flags |= 2;
    }
    return flags;
}
