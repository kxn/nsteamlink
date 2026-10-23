/* Execute the production input owner/Guide adapter and real IHS encryption,
 * report serialization, and queue. Only platform notification/clock/controller
 * handle terminals and selected queue admission failures are fixtures. */
#include "../platforms/common/media.c"
#include "test_session.h"
#include "hid/manager.h"
#include "hid/sdl/src/sdl_hid_common.h"
#include "session/channels/ch_control.h"
#include <assert.h>

static uint64_t clock_ms;
static bool intent, focus = true, redirected, reject_queue;
static unsigned admission_failures;
static uint16_t held_buttons;
static int16_t expected_axis;
Uint64 __wrap_SDL_GetTicks64(void) { return clock_ms; }
bool __wrap_sl_events_foreground(void) { return focus; }
bool __wrap_sl_events_capture_guide(bool allowed) { redirected = allowed; return true; }
bool __wrap_sl_events_take_capture_guide(void) { bool value = intent; intent = false; return value; }
SDL_Joystick *__wrap_SDL_GameControllerGetJoystick(SDL_GameController *controller) {
    return (SDL_Joystick *)controller;
}
SDL_JoystickID __wrap_SDL_JoystickInstanceID(SDL_Joystick *joystick) {
    return (SDL_JoystickID)(uintptr_t)joystick;
}
IHS_SendAdmission __real_IHS_SessionQueuePacketResult(IHS_Session *, const IHS_SessionPacket *, bool);
IHS_SendAdmission __wrap_IHS_SessionQueuePacketResult(IHS_Session *s, const IHS_SessionPacket *p,
                                                     bool reliable) {
    if (reject_queue) {
        ++admission_failures;
        return IHS_SendAdmissionTooLarge; /* Deterministic rejected admission, no transport teardown. */
    }
    return __real_IHS_SessionQueuePacketResult(s, p, reliable);
}
static IHS_HIDManagedDevice *device(IHS_Session *s, int joystick, unsigned id) {
    IHS_HIDManagedDevice *m = calloc(1, sizeof(*m));
    assert(m);
    m->manager = s->hidManager;
    m->id = id;
    m->lock = IHS_MutexCreate();
    m->device = IHS_HIDDeviceSDLCreate(NULL, (SDL_Gamepad *)(uintptr_t)joystick, false);
    assert(m->device && m->lock);
    m->device->managed = m;
    IHS_HIDReportHolderInit(&m->reportHolder, id);
    m->device->cls->opened(m->device);
    IHS_ArrayListAppend(&s->hidManager->devices, &m);
    return m;
}
typedef struct { IHS_SessionPacket packet; bool reliable; } queued;
static unsigned reports(IHS_Session *s, unsigned target, uint16_t expected) {
    unsigned count = 0;
    queued *q;
    while ((q = (void *)IHS_QueuePoll(s->sendQueue))) {
        assert(q->reliable && *IHS_BufferPointer(&q->packet.body) == k_EStreamControlRemoteHID);
        IHS_BufferOffsetBy(&q->packet.body, 1);
        IHS_Buffer plain = IHS_BUFFER_INIT(4096, 0);
        uint64_t sequence;
        IHS_SessionFrameDecryptResult result =
            IHS_SessionFrameDecrypt(s, &q->packet.body, &plain, 0, &sequence);
        assert(result == IHS_SessionFrameDecryptOK || result == IHS_SessionFrameDecryptSequenceMismatch);
        CRemoteHIDMsg *envelope = cremote_hidmsg__unpack(NULL, plain.size, IHS_BufferPointer(&plain));
        assert(envelope && envelope->has_data);
        CHIDMessageFromRemote *message =
            chidmessage_from_remote__unpack(NULL, envelope->data.len, envelope->data.data);
        assert(message && message->reports);
        for (size_t i = 0; i < message->reports->n_device_reports; ++i) {
            CHIDMessageFromRemote__DeviceInputReports__DeviceInputReport *d =
                message->reports->device_reports[i];
            for (size_t j = 0; j < d->n_reports; ++j) {
                CHIDDeviceInputReport *r = d->reports[j];
                assert(r->has_full_report && r->full_report.len == 72 && r->full_report.data[27] == 3);
                uint16_t buttons = r->full_report.data[16] | (uint16_t)r->full_report.data[17] << 8;
                if (d->device == target) {
                    assert(buttons == (expected | held_buttons));
                    assert((int16_t)(r->full_report.data[0] | (uint16_t)r->full_report.data[1] << 8) == expected_axis);
                    ++count;
                }
                else assert(buttons == 0); /* First device must never receive the target's Guide. */
            }
        }
        chidmessage_from_remote__free_unpacked(message, NULL);
        cremote_hidmsg__free_unpacked(envelope, NULL);
        IHS_BufferClear(&plain, true);
        IHS_SessionPacketClear(&q->packet, true);
        IHS_QueueItemFree((void *)q);
    }
    return count;
}
static void tick(uint64_t now, bool request, bool enabled) {
    clock_ms = now;
    intent = request;
    sl_media_capture_guide(enabled);
}
int main(void) {
    IHS_Init();
    IHS_Session *s = IHS_TestSessionCreate();
    assert(s);
    IHS_TimerTaskStopImmediate(s->retransmission.timer);
    s->state.connectionState = IHS_SessionConnectionStateConnected;
    s->state.streamingInput = true;
    IHS_HIDManagedDevice *other = device(s, 41, 1), *target = device(s, 42, 2);
    assert(!IHS_HIDSDLInputReady(NULL, 42) && !IHS_HIDSDLInputReady(s, 99));
    assert(IHS_HIDDeviceStartInputReports(other->device, 72) == 0);
    assert(!IHS_HIDSDLInputReady(s, 42)); /* Another device's ready state is insufficient. */
    assert(IHS_HIDDeviceStartInputReports(target->device, 72) == 0);
    assert(IHS_HIDSDLInputReady(s, 42));
    s->state.connectionState = IHS_SessionConnectionStateNegotiating;
    assert(!IHS_HIDSDLInputReady(s, 42));
    s->state.connectionState = IHS_SessionConnectionStateConnected;
    IHS_SessionHIDSendReport(s);
    assert(reports(s, 2, 0) == 1);
    assert(!pthread_mutex_init(&state_lock, NULL) && !pthread_mutex_init(&hid_lifecycle_lock, NULL));
    locks_ready = true;
    hid_session = s; hid_session_enabled = true; hid_controller_id = 42;
    atomic_store(&input_gate, true); atomic_store(&capture_blocked, false);
    sl_input_event a = {.type = SL_BUTTON, .code = SL_KEY_A, .value = 1};
    sl_media_input(&a, NULL);
    a = (sl_input_event){.type = SL_AXIS, .code = 0, .value = 1234};
    sl_media_input(&a, NULL);
    held_buttons = 1; expected_axis = 1234;
    tick(100, true, true);
    assert(redirected && capture_pulse.admitted && reports(s, 2, 0x20) == 1);
    tick(101, true, true);
    assert(reports(s, 2, 0x20) == 0); /* A second notification cannot extend the pulse. */
    tick(150, false, true);
    assert(!capture_pulse.held && reports(s, 2, 0) == 1);
    /* Rejected local queue admission advances the diagnostic sequence but must
     * NOT certify a press. Full refresh allows retry despite baseline advance. */
    reject_queue = true;
    tick(200, true, true);
    assert(capture_pulse.held && !capture_pulse.admitted && admission_failures);
    reject_queue = false;
    tick(220, false, true);
    assert(capture_pulse.admitted && reports(s, 2, 0x20) == 1);
    reject_queue = true;
    tick(270, false, true);
    assert(capture_pulse.releasing && !capture_pulse.held);
    IHS_HIDDeviceSDL *raw = (void *)target->device;
    assert(!(raw->states.current.buttons & 0x20)); /* Even failed release clears local state. */
    reject_queue = false;
    tick(290, false, true);
    assert(!capture_pulse.releasing && reports(s, 2, 0) == 1); /* Forced release despite unchanged baseline. */
    tick(350, true, true);
    assert(reports(s, 2, 0x20) == 1);
    reject_queue = true;
    held_buttons = 0; expected_axis = 0; /* Local gate neutralizes all ordinary input too. */
    sl_media_gate(false);
    assert(!capture_pulse.held && capture_pulse.releasing);
    reject_queue = false;
    tick(370, true, true);
    assert(!redirected && !capture_pulse.releasing && reports(s, 2, 0) == 1);
    sl_media_gate(true);
    tick(400, true, true); assert(reports(s, 2, 0x20) == 1);
    tick(401, false, false); assert(!redirected && reports(s, 2, 0) == 1); /* OFF cancels. */
    s->state.streamingInput = false;
    tick(500, true, true);
    assert(!redirected && !capture_pulse.held && !IHS_HIDSDLInputReady(s, 42));
    s->state.streamingInput = true;
    focus = false;
    tick(550, true, true); assert(!redirected && !capture_pulse.held);
    focus = true;
    tick(600, true, true); assert(reports(s, 2, 0x20) == 1);
    stream_media_set_hid_session(NULL, false);
    assert(!capture_pulse.held && !capture_pulse.releasing && reports(s, 2, 0) >= 1);
    tick(700, true, true); assert(!redirected && !capture_pulse.held);
    locks_ready = false;
    pthread_mutex_destroy(&hid_lifecycle_lock); pthread_mutex_destroy(&state_lock);
    IHS_SessionDestroy(s);
    IHS_Quit();
    puts("PASS target readiness, real encrypted Guide down/up, admission failure, gate/OFF/focus/session cleanup");
}
