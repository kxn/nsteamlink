#include "services/launch_watch.h"
#include <assert.h>
int main(void) {
    sl_launch_watch s = {.target = 7};
    sl_launch_activity(&s, 3, 413080, 0);
    sl_launch_status(&s, true, false, true, 1);
    sl_launch_status(&s, true, false, true, 2);
    assert(!sl_launch_finished(&s)); /* splash isn't game completion */
    sl_launch_activity(&s, 2, 7, 10);
    sl_launch_frame(&s, 10);
    sl_launch_status(&s, true, true, true, 3);
    assert(!s.played && !s.running_seen);
    sl_launch_frame(&s, 11);
    sl_launch_status(&s, true, true, true, 4);
    sl_launch_activity(&s, 3, 413080, 12);
    sl_launch_status(&s, true, true, true, 5);
    assert(!sl_launch_finished(&s)); /* Alt-Tab */
    sl_launch_status(&s, true, false, true, 6);
    sl_launch_status(&s, true, false, true, 6);
    assert(!sl_launch_finished(&s)); /* duplicate */
    sl_launch_status(&s, false, false, true, 7);
    sl_launch_status(&s, true, false, true, 8);
    assert(!sl_launch_finished(&s)); /* missing field breaks confirmation */
    sl_launch_activity(&s, 4, 0, 12);
    sl_launch_status(&s, true, false, true, 9);
    assert(!sl_launch_finished(&s)); /* secure desktop */
    sl_launch_activity(&s, 3, 413080, 12);
    sl_launch_status(&s, true, false, true, 10);
    sl_launch_status(&s, true, false, true, 11);
    assert(sl_launch_finished(&s));
    s = (sl_launch_watch){.target = 7}; /* B then A: no inherited evidence */
    sl_launch_activity(&s, 3, 413080, 0);
    sl_launch_status(&s, true, false, true, 12);
    sl_launch_status(&s, true, false, true, 13);
    assert(!sl_launch_finished(&s));
    s = (sl_launch_watch){0}; /* Steam-first never auto-ends */
    sl_launch_activity(&s, 2, 7, 0);
    sl_launch_frame(&s, 1);
    sl_launch_status(&s, true, true, true, 1);
    sl_launch_activity(&s, 3, 413080, 1);
    sl_launch_status(&s, true, false, true, 2);
    sl_launch_status(&s, true, false, true, 3);
    assert(!sl_launch_finished(&s));
}
