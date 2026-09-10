#include "frame_pacer.h"
#include <string.h>
#include <math.h>
static double clamp(double x,double lo,double hi) { return x<lo?lo:x>hi?hi:x; }
static void sort(double *a,unsigned n) {
    for(unsigned i=1;i<n;++i) {
        double x=a[i]; unsigned j=i;
        while(j && a[j-1]>x) { a[j]=a[j-1]; --j; }
        a[j]=x;
    }
}
/* Fit publication time over several frames. Alternating short/long intervals
 * don't imply alternating frame rates. Missing metadata starts a fresh run. */
static void input_sample(sl_frame_pacer *p,uint64_t seq,uint64_t us) {
    sl_pacer_period *v=&p->input;
    if(v->last && (us<=v->last || (v->value>0 && us-v->last>8*v->value))) {
        p->input_run=0;
#if NSL_DIAGNOSTICS
        ++p->holdovers;
#endif
        v->phase=us; /* keep the last useful period through an outage */
    }
    v->last=us;
    if(p->input_run<SL_PACER_WINDOW) ++p->input_run;
    unsigned n=p->input_run;
    if(n<5) return;
    double rates[SL_PACER_WINDOW], projected[SL_PACER_WINDOW]; unsigned nr=0;
    for(unsigned i=0;i+4<n;++i) {
        uint64_t newer=seq-i, older=newer-4;
        uint64_t hi=p->history[newer%SL_PACER_HISTORY].us;
        uint64_t lo=p->history[older%SL_PACER_HISTORY].us;
        if(hi>lo) rates[nr++]=(double)(hi-lo)/4.;
    }
    if(!nr) return;
    sort(rates,nr);
    double estimate=rates[nr/2];
    if(v->value<=0) v->value=estimate;
    else v->value+= (estimate-v->value)*.25;
    for(unsigned i=0;i<n;++i)
        projected[i]=(double)p->history[(seq-i)%SL_PACER_HISTORY].us+i*v->value;
    sort(projected,n);
    v->phase=projected[n/2];
    /* Robust phase error, not max-minus-min of adjacent arrival intervals. */
    for(unsigned i=0;i<n;++i) projected[i]=fabs(projected[i]-v->phase);
    sort(projected,n);
    double uncertainty=projected[(n-1)*9/10];
    v->jitter=fmax(uncertainty,v->jitter*.9);
    v->count=n;
}
static void output_sample(sl_pacer_period *v,double gap) {
    if(gap<=0) return;
    v->samples[v->cursor++%SL_PACER_WINDOW]=gap;
    if(v->count<SL_PACER_WINDOW) ++v->count;
    double a[SL_PACER_WINDOW]; memcpy(a,v->samples,v->count*sizeof(double));
    sort(a,v->count); v->value=a[v->count/2];
}
static void restart_timing(sl_frame_pacer *p) {
    memset(&p->input,0,sizeof(p->input)); memset(&p->output,0,sizeof(p->output));
    p->input_run=0; p->active=false; p->wait_deadline=0;
#if NSL_DIAGNOSTICS
    p->diag_first_input=p->diag_start_us=0;
    p->diag_ready=p->diag_wait=false;
#endif
    p->gated=p->last_gated=false;
    p->last_submit=p->last_empty=0;
    p->window_a=p->window_p=p->early=p->slow_outputs=p->fast_outputs=0;
    p->late_need=p->extra_guard=0;
}
void sl_pacer_reset(sl_frame_pacer *p,bool enabled) {
    memset(p,0,sizeof(*p)); p->enabled=enabled;
}
void sl_pacer_publish(sl_frame_pacer *p,uint64_t seq,uint64_t us) {
    if(!seq || seq<=p->available) return;
#if NSL_DIAGNOSTICS
    if(!p->diag_first_input) p->diag_first_input=us;
#endif
    if(seq-p->available>1) {
#if NSL_DIAGNOSTICS
        p->unobserved+=seq-p->available-1;
        ++p->holdovers;
#endif
        p->input_run=0; p->window_a=p->window_p=0; /* retain output capacity */
    }
    unsigned slot=seq%SL_PACER_HISTORY;
    p->history[slot].seq=seq; p->history[slot].us=us;
    p->history[slot].presented=false;
    p->available=seq;
    input_sample(p,seq,us);
    if(p->last_empty && us>=p->last_empty && p->output.value>0 &&
       us-p->last_empty<p->output.value) {
        ++p->early;
        p->late_need=fmax(p->late_need,(double)(us-p->last_empty));
    }
    p->last_empty=0;
}
static void feedback(sl_frame_pacer *p) {
    if(p->window_a<32) return;
    double ts=p->output.value;
    double ceiling=ts>0?fmin(1.,p->input.value/ts):1.;
    double ratio=(double)p->window_p/p->window_a;
    /* Only an observed premature redraw supplies a correction direction.
     * A skipped sequence alone cannot distinguish resource pressure from phase. */
    if(ts>0 && p->early && ratio<ceiling-.02)
        p->extra_guard=fmin(ts*.5,fmax(p->extra_guard,p->late_need));
    else if(ratio>=ceiling-.02) p->extra_guard*=.9;
    p->window_a=p->window_p=p->early=0; p->late_need=0;
}
void sl_pacer_settle(sl_frame_pacer *p,bool finish) {
    uint64_t end=p->available;
    if(!finish && end) --end;
    if(end<=p->settled) return;
    if(end-p->settled>SL_PACER_HISTORY) {
        p->settled=end-SL_PACER_HISTORY; p->window_a=p->window_p=0;
    }
    while(p->settled<end) {
        uint64_t seq=++p->settled; unsigned slot=seq%SL_PACER_HISTORY;
        if(p->history[slot].seq!=seq) { p->window_a=p->window_p=0; continue; }
        bool shown=p->history[slot].presented;
#if NSL_DIAGNOSTICS
        p->settled_presented+=shown;
#endif
        ++p->window_a; p->window_p+=shown;
        feedback(p);
    }
}
bool sl_pacer_wait(sl_frame_pacer *p,uint64_t now,uint64_t pending) {
    double span=fmax(p->input.value,p->output.value);
#if NSL_DIAGNOSTICS
    if(p->diag_last && now>=p->diag_last && span>0 && now-p->diag_last<=span*8.) {
        uint64_t dt=now-p->diag_last;
        if(p->diag_ready) p->diag_ready_us+=dt;
        if(p->diag_wait) p->diag_wait_us+=dt;
    }
    p->diag_last=now; p->diag_wait=false;
#endif
    if(p->last_call && (now<p->last_call || (span>0 && now-p->last_call>span*8.)))
        restart_timing(p); /* actual main-loop suspension, not arrival jitter */
    p->last_call=now; sl_pacer_settle(p,false);
    p->active=p->input.value>0 && p->output.count>=8;
#if NSL_DIAGNOSTICS
    p->diag_ready=p->enabled && p->active;
    if(p->diag_ready && !p->diag_start_us && p->diag_first_input && now>=p->diag_first_input)
        p->diag_start_us=now-p->diag_first_input;
#endif
    if(!p->enabled || !p->active || pending || !p->last_submit) {
        p->wait_deadline=0; return false;
    }
    if(!p->wait_deadline) {
        double tv=p->input.value,ts=p->output.value;
        double guard=clamp(p->input.jitter+p->extra_guard,fmin(tv/32.,ts*.5),ts*.5);
        double prediction=p->input.phase+tv+guard;
        /* No busy-wait and no rolling extension of an expired deadline. For
         * lower-rate video keep the normal UI cadence instead of waiting a frame. */
        double extra=tv<=ts*1.25?guard:0;
        double service=(double)p->last_submit+ts+extra;
        p->wait_deadline=(uint64_t)fmax(1.,fmin(prediction,service));
    }
    if(now<p->wait_deadline) {
#if NSL_DIAGNOSTICS
        p->diag_wait=true; ++p->deferred;
#endif
        p->gated=true; return true;
    }
    return false;
}
void sl_pacer_submit(sl_frame_pacer *p,uint64_t seq,uint64_t take_us,
                     uint64_t submit_us,bool success) {
    if(!success) { p->gated=false; p->wait_deadline=0; return; }
    if(p->last_submit && submit_us>p->last_submit) {
        double gap=(double)(submit_us-p->last_submit);
        bool direct=!p->gated && !p->last_gated;
        if(p->output.value>0 && gap>p->output.value*1.75) ++p->slow_outputs;
        else p->slow_outputs=0;
        if(p->output.value>0 && gap<p->output.value*.75) ++p->fast_outputs;
        else p->fast_outputs=0;
        /* Self-wait is capped at 1.5 output periods. Repeated longer intervals
         * require capacity remeasurement even if every draw has been gated. */
        if(direct || p->slow_outputs>=4 || p->fast_outputs>=4) output_sample(&p->output,gap);
    }
    p->last_gated=p->gated; p->gated=false; p->wait_deadline=0;
    p->last_submit=submit_us;
    if(!seq) { p->last_empty=take_us; return; }
    if(seq<=p->last_presented || seq>p->available) return;
    p->last_presented=seq;
#if NSL_DIAGNOSTICS
    ++p->presented;
#endif
    unsigned slot=seq%SL_PACER_HISTORY;
    if(p->history[slot].seq==seq) p->history[slot].presented=true;
}
