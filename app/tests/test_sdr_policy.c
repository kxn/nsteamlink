#include "sdr_policy.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>

/* Boundary fixtures mirror the fixed APK's observed outcomes, not the helper
 * implementation. The broader original-instruction differential audit lives
 * in tools/steam-sdr-implementation-audit.py and needs the private fixed ELF. */
int main(void) {
    const int64_t now = 1000000000;
    assert(sl_sdr_comparison_score(20, INT_MAX) == 20);
    assert(sl_sdr_comparison_score(INT_MAX, 20) == INT_MAX);
    assert(sl_sdr_comparison_score(20, SL_SDR_UNKNOWN) == 134217737);
    sl_sdr_candidate c[2] = {
        {.score=44,.minimum=44,.maximum=44,.shutdown_seconds=INT_MAX,.buckets=15,
         .front_samples=3,.cluster=0,.last_received=now,.front_oldest=now,
         .last_ping_sent=now,.bucket_end=now+1000000,.eligible=true},
        {.score=22,.minimum=22,.maximum=22,.shutdown_seconds=INT_MAX,.buckets=15,
         .front_samples=3,.cluster=1,.last_received=now,.front_oldest=now,
         .last_ping_sent=now,.bucket_end=now+1000000,.eligible=true}};
    sl_sdr_selection s;
    assert(sl_sdr_select(c, 2, 0, 1, false, now, &s) && s.primary==1 && s.backup==0);
    c[1].last_received = now-250001;
    assert(sl_sdr_select(c, 2, 0, 1, false, now, &s) && s.primary==0 && s.probe[1]);
    c[1].last_received = now-250000;
    assert(sl_sdr_select(c, 2, 0, 1, false, now, &s) && s.primary==1);
    c[1].front_oldest = now-5000001;
    assert(sl_sdr_select(c, 2, 0, 1, false, now, &s) && s.primary==0 && s.probe[1]);
    c[1].front_oldest = now-5000000;
    c[1].buckets = 14;
    assert(sl_sdr_select(c, 2, 0, 1, false, now, &s) && s.primary==0 && !s.probe[1]);
    c[1].last_ping_sent = now-200000;
    assert(sl_sdr_select(c, 2, 0, 1, false, now, &s) && s.primary==0 && s.probe[1]);
    /* Switching primary first resets the active list to one item. An old
     * backup does not survive that reset when every eligible relay shares
     * the new primary's cluster. */
    sl_sdr_candidate same_pop[3] = {c[0], c[0], c[0]};
    same_pop[0].score = same_pop[0].minimum = same_pop[0].maximum = 80;
    same_pop[0].draining = true;
    same_pop[1].eligible = false;
    same_pop[2].score = same_pop[2].minimum = same_pop[2].maximum = 20;
    assert(sl_sdr_select(same_pop, 3, 0, 1, false, now, &s) && s.primary==2 && s.backup==-1);
    bool target[3] = {false,true,true};
    int32_t primary=0, backup=1;
    assert(sl_sdr_clean_active(target,3,&primary,&backup) && primary==1 && backup==-1);
    /* A surviving backup becomes current before hysteresis is evaluated.
     * Its 33 ms score remains within the new 22 ms candidate's threshold. */
    sl_sdr_candidate promoted[3] = {c[0], c[0], c[0]};
    promoted[0].eligible=false;
    promoted[1].score=promoted[1].minimum=promoted[1].maximum=33;
    promoted[2].score=promoted[2].minimum=promoted[2].maximum=22;
    promoted[1].cluster=1; promoted[2].cluster=2;
    assert(sl_sdr_select(promoted,3,primary,backup,false,now,&s) && s.primary==1);
    sl_sdr_latencies latency={0};
    assert(sl_sdr_latency_measure(&latency,10,30,false,now));
    sl_sdr_latency_exception(&latency,10,4,7000); /* Not subject to cluster clamp. */
    assert(sl_sdr_latencies_begin(&latency,0,now+1));
    const sl_sdr_latency *edge=sl_sdr_latency_find(&latency,10);
    assert(edge && !edge->measured && edge->ping==30 && edge->penalty==7000 && edge->flags==4);
    sl_sdr_latency_estimate(&latency,10,40);
    assert(edge->ping==40 && edge->penalty==7000 && !edge->measured);
    assert(sl_sdr_latency_measure(&latency,10,50,true,now+2));
    sl_sdr_latency_estimate(&latency,10,1);
    assert(edge->ping==50 && !edge->penalty && edge->flags==0x20000000 && edge->measured==now+2);
    sl_sdr_latency_exception(&latency,20,4,9);
    assert(!sl_sdr_latency_find(&latency,20));
    assert(!sl_sdr_latencies_begin(&latency,1,now+3) && edge->measured==now+2);
    assert(sl_sdr_cluster_penalty(-1)==0 && sl_sdr_cluster_penalty(7000)==5000);
    sl_sdr_timeouts t = {.request_deadline=now,.request_failures=1};
    assert(sl_sdr_expire(&t, now) == (SL_SDR_TIMEOUT_REQUEST|SL_SDR_TIMEOUT_REPROBE));
    t = (sl_sdr_timeouts){.ping_deadline=now+1,.ping_failures=1};
    assert(!sl_sdr_expire(&t, now));
    assert(sl_sdr_expire(&t, now+1) == (SL_SDR_TIMEOUT_PING|SL_SDR_TIMEOUT_REMOVE));
    sl_sdr_downtime d = {0};
    assert(sl_sdr_warn_downtime(&d, 120, 45, now));
    assert(d.shutdown==now+120000000 && d.avoid==now+75000000);
    assert(!sl_sdr_warn_downtime(&d, 117, 60, now));
    assert(sl_sdr_warn_downtime(&d, 116, 60, now));
    assert(d.shutdown==now+116000000 && d.avoid==now+56000000);
    sl_sdr_failure_cache f = {.last_probe=now,.failures=4,.reachability=1};
    sl_sdr_fail_address(&f, 1, 10, now);
    sl_sdr_expire_addresses(&f, 10, now+120000000);
    assert(f.count==1 && f.failures==4);
    sl_sdr_expire_addresses(&f, 10, now+120000001);
    assert(!f.count && !f.failures);
    assert(!sl_sdr_routing_ready(20, 14, 1, 2, 4, 8000000));
    assert(!sl_sdr_routing_ready(20, 15, 0, 0, 0, 7000000));
    assert(sl_sdr_routing_ready(20, 15, 0, 0, 0, 7000001));
    assert(sl_sdr_established_action(-2)==SL_SDR_STATE_THINK);
    assert(sl_sdr_established_action(-1)==SL_SDR_STATE_CLOSE);
    assert(sl_sdr_established_action(0)==SL_SDR_STATE_INVALID);
    assert(sl_sdr_state_action(-3)==SL_SDR_STATE_IGNORE);
    assert(sl_sdr_state_action(5)==SL_SDR_STATE_CLOSE);
    puts("PASS SDR policy boundaries");
    return 0;
}
