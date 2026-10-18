#include "ui_events.h"
#include "services/i18n.h"
#include <stdio.h>
#include <string.h>
void sl_ui_runtime_event(sl_ui_model *m, const sl_runtime_event *event) {
    sl_runtime_event e = *event;
    if (e.type == SL_EVENT_HOST) {
        sl_host *h = sl_host_observe(&m->store.registry, &e.host, m->now);
        if (h && m->page == SL_CONNECTING && !m->intent.host.id &&
            !strcmp(m->intent.text, h->address)) {
            m->store.registry.selected = (int)(h - m->store.registry.hosts);
            m->page = SL_HOME;
            sl_ui_action(m, SL_START, 0);
        }
        return;
    }
    if (e.type != SL_EVENT_CLOSED && e.generation != m->generation)
        return;
    switch (e.type) {
    case SL_EVENT_UPDATE:
        snprintf(m->update_version, sizeof(m->update_version), "%.15s", e.text);
        break;
    case SL_EVENT_UPDATE_RESULT:
        if (m->page != SL_UPDATING)
            break;
        m->update_succeeded = e.account != 0;
        snprintf(m->error, sizeof(m->error), "%s", e.text);
        m->page = SL_UPDATE_RESULT;
        m->entered_at = m->now;
        m->focus = 0;
        break;
    case SL_EVENT_SHORTCUT:
        if (m->page != SL_INSTALLING)
            break;
        snprintf(m->error, sizeof(m->error), "%s", e.text);
        m->page = SL_INSTALL_RESULT;
        m->entered_at = m->now;
        m->focus = 9;
        break;
    case SL_EVENT_STREAM_AUTHORIZATION:
        if (m->page != SL_CONNECTING && m->page != SL_NETWORK_TEST && m->page != SL_PAIRING)
            break;
        if (m->page == SL_PAIRING && m->pairing_code[0])
            break;
        m->page = SL_PAIRING;
        m->pair_code_at = m->now;
        snprintf(m->pairing_code, sizeof(m->pairing_code), "%.4s", e.text);
        break;
    case SL_EVENT_STREAM_RESUMED: {
        if (m->page != SL_PAIRING && m->page != SL_CONNECTING && m->page != SL_NETWORK_TEST)
            break;
        sl_host *h = sl_host_find(&m->store.registry, e.host.id);
        if (h) {
            h->paired = e.host.paired;
            h->account = e.host.account;
            h->has_secret = e.host.has_secret;
            memcpy(h->secret, e.host.secret, sizeof(h->secret));
            m->intent.host = *h;
        }
        m->pairing_code[0] = 0;
        m->page = e.account ? SL_NETWORK_TEST : SL_CONNECTING;
        break;
    }
    case SL_EVENT_CODE:
        if (m->page != SL_PAIRING || m->pairing_code[0])
            break;
        m->pair_code_at = m->now;
        snprintf(m->pairing_code, sizeof(m->pairing_code), "%.4s", e.text);
        break;
    case SL_EVENT_SAVING:
        if (m->page != SL_PAIRING)
            break;
        m->page = SL_SAVING;
        break;
    case SL_EVENT_AUTHORIZED: {
        if (m->page != SL_PAIRING && m->page != SL_SAVING)
            break;
        sl_host *h = sl_host_find(&m->store.registry, e.host.id);
        if (h) {
            if (h->account != e.account)
                memset(h->games, 0, sizeof(h->games));
            h->paired = true;
            h->account = e.account;
            h->has_secret = e.host.has_secret;
            memcpy(h->secret, e.host.secret, sizeof(h->secret));
            m->intent.host = *h;
            m->page = SL_CONNECTING;
            m->command = m->intent;
            m->command.generation = m->generation;
            m->command.type = SL_CMD_STREAM;
            m->command.quality = m->store.quality;
            m->command.bitrate_kbps = m->store.bitrate_kbps;
            m->command.unreliable_fec = m->store.unreliable_fec;
        } else
            sl_ui_error(m, sl_tr(SL_T_HOST_REMOVED));
        break;
    }
    case SL_EVENT_PIN:
        m->page = SL_PIN;
        m->input[0] = 0;
        m->focus = 0;
        break;
    case SL_EVENT_FAILURE:
        if (m->streaming) {
            m->streaming = false;
            m->debug = false;
        }
        sl_ui_error(m, e.text);
        break;
    case SL_EVENT_FIRST_FRAME:
        if (m->page == SL_CONNECTING)
            sl_ui_connected(m);
        break;
    case SL_EVENT_STOPPED:
        sl_ui_stopped(m, e.account != 0);
        break;
    case SL_EVENT_ACTIVITY: {
        sl_host *h = sl_host_find(&m->store.registry, e.host.id);
        sl_host_activity(h, e.account, &e.game);
        if (m->command.type == SL_CMD_NONE)
            m->command = (sl_command){.type = SL_CMD_SAVE,
                                      .generation = m->generation,
                                      .language = sl_i18n_language(),
                                      .update_check = m->update_check};
        break;
    }
    case SL_EVENT_CLOSED:
        m->closing = true;
        m->page = SL_CLOSING;
        break;
    default:
        break;
    }
    sl_ui_layout(m);
}

void sl_ui_network_test(sl_ui_model *m, const sl_network_test_view *view) {
    if (view->generation != m->generation ||
        (m->network_test.generation == view->generation &&
         view->revision <= m->network_test.revision) ||
        (m->page != SL_CONNECTING && m->page != SL_NETWORK_TEST && m->page != SL_NETWORK_RESULT))
        return;
    m->network_test = *view;
    sl_page before = m->page;
    if (view->phase == SL_TEST_REQUESTING || view->phase == SL_TEST_RUNNING)
        m->page = SL_NETWORK_TEST;
    else if (view->phase == SL_TEST_RESULT) {
        m->page = SL_NETWORK_RESULT;
        m->focus = 103; /* The apply/continue row; footer B keeps the old settings. */
    } else if (view->phase == SL_TEST_CONTINUING)
        m->page = SL_CONNECTING;
    else if (view->phase == SL_TEST_FAILED) {
        sl_ui_error(m, view->error);
        m->cancel_only_error = true;
        m->focus = 101;
    } else
        return;
    if (m->page != before)
        m->entered_at = m->now;
    sl_ui_layout(m);
}

bool sl_ui_stream_preferences(sl_ui_model *m, const sl_stream_preferences *prefs,
                              uint64_t revision) {
    /* A local action awaiting submit owns the visible controls. After submit,
     * older worker snapshots cannot undo it; a matching/newer snapshot can. */
    if (m->command.type != SL_CMD_NONE || revision < m->settings_revision)
        return false;
    bool changed = m->store.quality != prefs->quality ||
                   m->store.bitrate_kbps != prefs->bitrate_kbps ||
                   m->store.unreliable_fec != prefs->unreliable_fec;
    m->settings_revision = revision;
    m->store.quality = prefs->quality;
    m->store.bitrate_kbps = prefs->bitrate_kbps;
    m->store.unreliable_fec = prefs->unreliable_fec;
    if (changed)
        sl_ui_layout(m);
    return true;
}
