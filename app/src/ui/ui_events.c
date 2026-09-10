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
    case SL_EVENT_SHORTCUT:
        if (m->page != SL_INSTALLING)
            break;
        snprintf(m->error, sizeof(m->error), "%s", e.text);
        m->page = SL_INSTALL_RESULT;
        m->entered_at = m->now;
        m->focus = 9;
        break;
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
            m->intent.host = *h;
            m->page = SL_CONNECTING;
            m->command = m->intent;
            m->command.generation = m->generation;
            m->command.type = SL_CMD_STREAM;
            m->command.quality = m->store.quality;
            m->command.bitrate_kbps = m->store.bitrate_kbps;
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
        if (e.account == 1) {
            if (m->page != SL_CONNECTING)
                break;
            sl_host *h = sl_host_find(&m->store.registry, m->intent.host.id);
            if (h) {
                h->paired = false;
                m->intent.host = *h;
                if (m->repair_attempted) {
                    sl_ui_error(m, e.text);
                    break;
                }
                m->repair_attempted = true;
                m->page = SL_PAIRING;
                m->pairing_code[0] = 0;
                m->command = m->intent;
                m->command.generation = m->generation;
                m->command.type = SL_CMD_PAIR;
                break;
            }
        }
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
            m->command = (sl_command){
                .type = SL_CMD_SAVE, .generation = m->generation, .language = sl_i18n_language()};
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
