#include "frame_pacer.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
static uint64_t digest=1469598103934665603ULL;
static void simulate(unsigned phase, unsigned input_period, unsigned output_period, bool enabled,
                     unsigned jitter, unsigned pause) {
    sl_frame_pacer p; sl_pacer_reset(&p,enabled);
    uint64_t next_input=1000+phase, next_output=1000, seq=0, pending=0;
    unsigned used=0, available=0, longest=0;
    uint64_t previous=0, first_lock=0;
    for(uint64_t now=1000;now<6000000;now+=500) {
        if(now>=next_input) {
            ++seq; sl_pacer_publish(&p,seq,now); pending=seq;
            if(now>=2000000) ++available;
            int delta=jitter ? (int)((seq*17)% (2*jitter+1))-(int)jitter : 0;
            next_input+=input_period+delta;
            if(pause && seq==80) next_input+=pause;
        }
        bool wait=sl_pacer_wait(&p,now,pending);
        if(p.active && !first_lock) first_lock=now;
        digest=(digest^(now+pending*3+wait))*1099511628211ULL;
        if(wait) continue;
        if(now<next_output) continue; /* BUSY: no scheduler feedback */
        sl_pacer_submit(&p,pending,now,now,true);
        if(now>=2000000 && pending) {
            ++used;
            if(previous && now-previous>longest) longest=(unsigned)(now-previous);
            previous=now;
        }
        pending=0;
        /* Fixed display opportunities; late CPU polling doesn't change period. */
        do { next_output+=output_period; } while(next_output<=now);
    }
    sl_pacer_settle(&p,true);
    assert(p.settled==p.available);
#if NSL_DIAGNOSTICS
    assert(p.presented<=p.available);
    assert(p.settled_presented==p.presented);
#endif
    if(enabled && !pause && input_period>=output_period) {
        double ratio=(double)used/available;
        if(ratio<.98) fprintf(stderr,"phase=%u input=%u output=%u ratio=%f\n",phase,input_period,output_period,ratio);
        assert(ratio>=.98);
        assert(longest<input_period*3);
        assert(p.active);
        assert(first_lock && first_lock<2000000);
    }
}
/* An alternating +/- publication phase makes fixed-slot redraw lose every
 * other frame. Waiting for the actual publication must recover utilization. */
static double alternating(bool enabled) {
    sl_frame_pacer p; sl_pacer_reset(&p,enabled);
    uint64_t pending=0, seq=0, next_input=17000, next_slot=17000;
    unsigned a=0, shown=0;
    for(uint64_t now=1000;now<6000000;now+=250) {
        if(now>=next_input) {
            ++seq; sl_pacer_publish(&p,seq,now); pending=seq;
            if(now>2000000) ++a;
            next_input=17000+seq*16667+(seq%2?750:0);
        }
        bool wait=sl_pacer_wait(&p,now,pending);
        digest=(digest^(now+pending*3+wait))*1099511628211ULL;
        if(wait) continue;
        if(now<next_slot) continue;
        sl_pacer_submit(&p,pending,now,now,true);
        if(now>2000000 && pending) ++shown;
        pending=0;
        do { next_slot+=16667; } while(next_slot<=now);
    }
    return (double)shown/a;
}
/* Unlike the original slot model, begin here blocks the CPU until an output
 * is returned. Decoder publications continue during that blocking call. */
static double blocking(bool enabled,unsigned phase,unsigned amplitude,unsigned *active_out) {
    sl_frame_pacer p; sl_pacer_reset(&p,enabled);
    uint64_t now=1000,next_slot=17000,next_pub=17000+phase,seq=0,pending=0;
    unsigned a=0,shown=0,active=0,calls=0;
    while(now<8000000) {
        while(next_pub<=now) {
            ++seq; sl_pacer_publish(&p,seq,next_pub); pending=seq;
            if(next_pub>2000000) ++a;
            next_pub=17000+phase+seq*16667+(seq%2?amplitude:0);
        }
        bool wait=sl_pacer_wait(&p,now,pending);
        digest=(digest^(now+pending*3+wait))*1099511628211ULL;
        if(now>2000000) { ++calls; active+=p.active; }
        if(wait) { now+=500; continue; }
        if(now<next_slot) now=next_slot;
        while(next_pub<=now) {
            ++seq; sl_pacer_publish(&p,seq,next_pub); pending=seq;
            if(next_pub>2000000) ++a;
            next_pub=17000+phase+seq*16667+(seq%2?amplitude:0);
        }
        sl_pacer_submit(&p,pending,now,now+100,true);
        if(now>2000000 && pending) ++shown;
        pending=0;
        do { next_slot+=16667; } while(next_slot<=now);
        now+=1000;
    }
    *active_out=100*active/calls;
    return (double)shown/a;
}
static void deadline_and_holdover(void) {
    sl_frame_pacer p; sl_pacer_reset(&p,true);
    for(uint64_t i=1;i<=30;++i) {
        uint64_t t=i*16667;
        sl_pacer_publish(&p,i,t);
        sl_pacer_wait(&p,t,i);
        sl_pacer_submit(&p,i,t,t,true);
    }
    uint64_t t=30*16667+1000;
    assert(sl_pacer_wait(&p,t,0)); uint64_t end=p.wait_deadline;
    /* BUSY returns without submit; subsequent retries retain the deadline. */
    for(unsigned i=1;i<=10;++i) {
        sl_pacer_wait(&p,t+i*100,0);
        assert(p.wait_deadline==end);
    }
    assert(!sl_pacer_wait(&p,end+1,0)); assert(p.wait_deadline==end);
    double old=p.input.value;
    for(uint64_t now=end+1;now<t+300000;now+=16667) {
        sl_pacer_wait(&p,now,0);
        sl_pacer_submit(&p,0,now,now,true);
    }
    sl_pacer_publish(&p,31,t+300000); /* input outage, renderer kept running */
    assert(p.input.value==old);
#if NSL_DIAGNOSTICS
    assert(p.holdovers);
#endif
    assert(!sl_pacer_wait(&p,t+300000,31)); /* available frame wins */
    assert(p.input.value==old);
    sl_pacer_reset(&p,true);
    uint64_t now=1000;
    for(unsigned i=0;i<20;++i) { sl_pacer_submit(&p,0,now,now,true); now+=16667; }
    for(unsigned i=0;i<30;++i) { now+=33334; p.gated=true; sl_pacer_submit(&p,0,now,now,true); }
    assert(fabs(p.output.value-33334)<1);
    for(unsigned i=0;i<30;++i) { now+=16667; p.gated=true; sl_pacer_submit(&p,0,now,now,true); }
    assert(fabs(p.output.value-16667)<1);
}
int main(void) {
    for(unsigned phase=0;phase<16667;phase+=257) {
        simulate(phase,16667,16667,true,0,0);
        simulate(phase,16680,16667,true,0,0);
        simulate(phase,33333,16667,true,0,0);
        simulate(phase,16667,16667,false,0,0);
    }
    simulate(3000,16667,16667,true,200,0);
    simulate(3000,16667,16667,true,0,300000);
    simulate(3000,8333,16667,true,0,0);
    sl_frame_pacer p; sl_pacer_reset(&p,true);
    sl_pacer_publish(&p,1,1000); sl_pacer_publish(&p,2,2000);
    sl_pacer_submit(&p,1,1500,1600,true); /* publish races recording */
    sl_pacer_settle(&p,false); assert(p.settled==1 && p.history[1].presented);
    sl_pacer_submit(&p,2,2000,2100,false);
    sl_pacer_settle(&p,true); assert(p.available==2 && p.last_presented==1);
    sl_pacer_publish(&p,1000,100000); assert(p.available==1000 && !p.active);
    sl_pacer_settle(&p,true); assert(p.last_presented==1);
    sl_pacer_reset(&p,true); assert(!p.available && !p.last_presented);
    deadline_and_holdover();
    for(unsigned phase=0;phase<16667;phase+=1024) {
        unsigned active;
        double ratio=blocking(true,phase,3000,&active);
        if(ratio<.98 || active<95) fprintf(stderr,"blocking phase=%u ratio=%.4f active=%u\n",phase,ratio,active);
        assert(ratio>=.98 && active>=95);
    }
    unsigned active;
    double blocked_base=blocking(false,0,3000,&active);
    double blocked_adapt=blocking(true,0,3000,&active);
    printf("blocking acquire, 3ms alternating arrival: baseline=%.6f adaptive=%.6f active=%u%%\n",blocked_base,blocked_adapt,active);
    assert(blocked_base<.8 && blocked_adapt>=.98);
    double baseline=alternating(false), adaptive=alternating(true);
    printf("alternating publication: baseline=%.6f adaptive=%.6f\n",baseline,adaptive);
    assert(baseline<.8 && adaptive>=.98);
    printf("decision digest: %llu\n",(unsigned long long)digest);
    puts("frame pacer: random phases, rates, jitter, outage and cohorts PASS");
}
