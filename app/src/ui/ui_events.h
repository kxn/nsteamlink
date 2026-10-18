#pragma once
#include "platform/runtime.h"
void sl_ui_runtime_event(sl_ui_model *m, const sl_runtime_event *event);
void sl_ui_network_test(sl_ui_model *, const sl_network_test_view *);

#include "services/stream_preferences.h"
bool sl_ui_stream_preferences(sl_ui_model *, const sl_stream_preferences *, uint64_t revision);
