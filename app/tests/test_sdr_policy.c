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
    puts("PASS SDR policy boundaries");
    return 0;
}
