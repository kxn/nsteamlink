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
    const int32_t fronts[]={-1,-1,-1,-1,20};
    const sl_sdr_edge edges[]={{4,3,10},{3,2,10},{2,1,10},{1,0,10}};
    int32_t estimate[5];
    assert(sl_sdr_route_estimates(fronts,5,edges,4,estimate));
    assert(estimate[0]==SL_SDR_UNKNOWN && estimate[1]==50 && estimate[2]==40 && estimate[3]==20 && estimate[4]==20);
    const sl_sdr_edge invalid_edge={4,5,10};
    assert(!sl_sdr_route_estimates(fronts,5,&invalid_edge,1,estimate) && estimate[1]==50);
    int32_t ping;
    assert(sl_sdr_router_ping_ms((uint32_t)now+2000,now,&ping) && ping==0);
    assert(!sl_sdr_router_ping_ms((uint32_t)now+1,now,&ping));
    assert(sl_sdr_router_ping_ms((uint32_t)now-10000000,now,&ping) && ping==10000);
    assert(!sl_sdr_router_ping_ms((uint32_t)now-10000001,now,&ping));
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
    /* Native nearest-N fixtures: healthy/unknown clusters count toward the
     * prefix, failed clusters do not, and tier zero bypasses that limit. */
    sl_sdr_probe_input probes[7];
    for (unsigned i=0; i<7; ++i)
        probes[i]=(sl_sdr_probe_input){.ping=-1,.pop_type=1,.tier=1,.estimate=5000};
    sl_sdr_probe_plan plan;
    assert(sl_sdr_plan_probes(probes,7,0,true,false,&plan) && plan.count==5 && plan.budget==1);
    probes[0].reachability=-1;
    assert(sl_sdr_plan_probes(probes,7,5,true,true,&plan) && plan.count==6 && plan.budget==10);
    probes[6].tier=0;
    assert(sl_sdr_plan_probes(probes,7,5,true,false,&plan) && plan.count==7 && plan.cutoff==10000);
    probes[0].tier=0; probes[0].ping=20;
    assert(sl_sdr_plan_probes(probes,7,5,true,false,&plan) && plan.cutoff>10000);
    assert(!sl_sdr_plan_probes(NULL,1,20,true,false,&plan));
    /* A connected client can remeasure stale accurate samples even while
     * retaining its primary. Activity is independent of primary absence. */
    sl_sdr_probe_input stale={.ping=20,.probes=8,.received=8,.front_samples=3,
        .pop_type=1,.tier=1,.since_received=120000001};
    float priority;
    assert(sl_sdr_probe_priority(&stale,true,false,&priority));
    assert(!sl_sdr_probe_priority(&stale,false,false,&priority));
    assert(!sl_sdr_front_eligible(2,20,1,0));
    assert(sl_sdr_front_eligible(2,20,-1,1));
    assert(!sl_sdr_front_eligible(1,-1,1,1));
    assert(!sl_sdr_front_eligible(1,20,0,0));
    assert(sl_sdr_front_eligible(1,20,1,0));
    sl_sdr_advert_cluster ac[8]; sl_sdr_advert_route ar[8];
    uint8_t cr[8],rr[8];
    for (unsigned i=0; i<8; ++i) {
        ac[i]=(sl_sdr_advert_cluster){.ping=20+(int)i,.old_member=true};
        ar[i]=(sl_sdr_advert_route){.local=i,.remote=(i+1)%8,.forward=70+(int)i,
            .reverse=INT_MAX,.old_member=true};
    }
    assert(sl_sdr_mark_advertisement(ac,8,ar,8,false,cr,rr));
    for (unsigned i=0; i<8; ++i) {
        assert(cr[i]==(i<4 ? 3 : i<6 ? 1 : 0));
        assert(rr[i]==(i<2 ? 3 : i<4 ? 1 : 0));
    }
    ar[7].forced=true;
    assert(sl_sdr_mark_advertisement(ac,8,ar,8,false,cr,rr) && rr[7]==3 && cr[7]==3);
    unsigned co[8],ro[8];
    assert(sl_sdr_order_advertisement(ac,8,ar,8,false,cr,rr,co,ro));
    /* The forced primary must lead the wire list even at a larger POP index. */
    assert(ro[0]==7 && ro[1]==0 && co[0]==0 && co[4]==7);
    ar[7].old_member=false;
    assert(!sl_sdr_mark_advertisement(ac,8,ar,8,true,cr,rr) && rr[7]==3);
    assert(sl_sdr_old_metric_valid(20,26,20,30));
    assert(!sl_sdr_old_metric_valid(20,31,20,30));
    assert(!sl_sdr_old_metric_valid(0,5,-1,-1));
    assert(sl_sdr_established_action(-2)==SL_SDR_STATE_THINK);
    assert(sl_sdr_established_action(-1)==SL_SDR_STATE_CLOSE);
    assert(sl_sdr_established_action(0)==SL_SDR_STATE_INVALID);
    assert(sl_sdr_state_action(-3)==SL_SDR_STATE_IGNORE);
    assert(sl_sdr_state_action(5)==SL_SDR_STATE_CLOSE);
    puts("PASS SDR policy boundaries");
    return 0;
}
