#pragma once
#include <stdbool.h>
#include <stdint.h>

typedef enum sl_network_test_phase {
    SL_TEST_IDLE,
    SL_TEST_REQUESTING,
    SL_TEST_RUNNING,
    SL_TEST_RESULT,
    SL_TEST_CONTINUING,
    SL_TEST_FAILED,
} sl_network_test_phase;
/* Persistent worker-owned snapshot, independent of the bounded event queue.
 * recommendation: original Panel codes 0 none, 1 Fast, 2 Enhanced. */
typedef struct sl_network_test_view {
    uint64_t generation, revision;
    sl_network_test_phase phase;
    bool test_only, bandwidth_test;
    bool control_error; /* Same owner, different dialog from media/test failure. */
    uint32_t target_kbps, previous_target_kbps;
    float progress, loss_percent, mean_ms, deviation_ms;
    unsigned rating, recommendation;
    char error[192];
} sl_network_test_view;
