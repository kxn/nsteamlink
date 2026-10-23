/* Real media owner, runtime stop_session, SDL virtual controller and IHS HID
 * manager. The native sensor call is paused at its platform boundary. An
 * expired borrow is recorded without dereferencing freed memory, so the old
 * implementation must return valid JSON rather than crash as a counterexample.
 * This does not exercise libnx IPC, a physical IMU or real Steam transport.
 */
#include "../platforms/common/media.c"
#include "test_session.h"
#include "hid/manager.h"
#include "hid/provider.h"
#include "hid/sdl/src/sdl_hid_common.h"
#include <assert.h>
#include <errno.h>

void sensor_lifetime_stop_session(IHS_Session *);
static pthread_mutex_t probe_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t probe_wake = PTHREAD_COND_INITIALIZER;
static pthread_t retire_thread, coordinator_thread;
static bool retire_thread_ready, armed, poll_entered, release_poll, poll_returned;
static bool start_retire, retire_attempted, retired, protected_borrow, late_borrow, injected;
static IHS_Session *probe_session;
static unsigned poll_calls;

int __real_pthread_mutex_lock(pthread_mutex_t *);
int __wrap_pthread_mutex_lock(pthread_mutex_t *mutex) {
    if (mutex == &hid_lifecycle_lock && retire_thread_ready &&
        pthread_equal(pthread_self(), retire_thread)) {
        assert(!__real_pthread_mutex_lock(&probe_lock));
        retire_attempted = true;
        pthread_cond_broadcast(&probe_wake);
        pthread_mutex_unlock(&probe_lock);
    }
    return __real_pthread_mutex_lock(mutex);
}

static void wait_flag(bool *flag) {
    struct timespec deadline;
    assert(!clock_gettime(CLOCK_REALTIME, &deadline));
    deadline.tv_sec += 5; /* Test liveness only, never a protocol timer. */
    while (!*flag)
        assert(!pthread_cond_timedwait(&probe_wake, &probe_lock, &deadline));
}
void __wrap_sl_sensors_poll(IHS_Session *session, int joystick_id) {
    if (!armed)
        return;
    ++poll_calls;
    assert(session == probe_session && joystick_id == hid_controller_id);
    assert(!pthread_mutex_lock(&probe_lock));
    poll_entered = true;
    pthread_cond_broadcast(&probe_wake);
    wait_flag(&release_poll);
    late_borrow = retired;
    pthread_mutex_unlock(&probe_lock);
    if (!late_borrow) {
        const float gyro[3] = {1, 2, 3}, accel[3] = {0, 0, 9.81f};
        injected = IHS_HIDSDLInjectSensor(session, joystick_id, gyro, accel);
    }
    assert(!pthread_mutex_lock(&probe_lock));
    poll_returned = true;
    pthread_cond_broadcast(&probe_wake);
    pthread_mutex_unlock(&probe_lock);
}
static void *retire_owner(void *context) {
    (void)context;
    assert(!pthread_mutex_lock(&probe_lock));
    wait_flag(&start_retire);
    pthread_mutex_unlock(&probe_lock);
    sensor_lifetime_stop_session(probe_session);
    assert(!pthread_mutex_lock(&probe_lock));
    retired = true;
    pthread_cond_broadcast(&probe_wake);
    pthread_mutex_unlock(&probe_lock);
    return NULL;
}
static void *coordinate(void *context) {
    (void)context;
    assert(!pthread_mutex_lock(&probe_lock));
    wait_flag(&poll_entered);
    /* Retirement is still gated here, and the HID flush worker never takes
     * this mutex. EBUSY therefore observes the media thread's actual lease,
     * not a timing guess or a lock held by the competing retirement thread. */
    int locked = pthread_mutex_trylock(&hid_lifecycle_lock);
    assert(locked == 0 || locked == EBUSY);
    protected_borrow = locked == EBUSY;
    if (!locked)
        pthread_mutex_unlock(&hid_lifecycle_lock);
    start_retire = true;
    pthread_cond_broadcast(&probe_wake);
    wait_flag(&retire_attempted);
    if (!protected_borrow)
        wait_flag(&retired); /* Deterministically expose the expired old borrow. */
    release_poll = true;
    pthread_cond_broadcast(&probe_wake);
    pthread_mutex_unlock(&probe_lock);
    return NULL;
}
bool __wrap_IHS_BaseSend(IHS_Base *base, IHS_SocketAddress address, const IHS_Buffer *wire) {
    (void)base;
    (void)address;
    (void)wire;
    return true; /* No host or wire/ACK success claim. */
}
typedef struct {
    unsigned polls;
    bool protected_borrow, late_borrow, injected, retired, poll_returned;
    bool worker_joined, unbound, detached, initial_neutral;
} observation;
static observation one(IHS_HIDProvider *provider) {
    retire_thread_ready = armed = poll_entered = release_poll = poll_returned = false;
    start_retire = retire_attempted = retired = protected_borrow = late_borrow = injected = false;
    poll_calls = 0;
    probe_session = IHS_TestSessionCreate();
    assert(probe_session);
    IHS_TimerTaskStopImmediate(probe_session->retransmission.timer);
    probe_session->state.connectionState = IHS_SessionConnectionStateConnected;
    probe_session->state.streamingInput = true;
    assert(provider->manager == NULL);
    IHS_SessionHIDAddProvider(probe_session, provider);
    char path[64];
    snprintf(path, sizeof(path), "sdl://%d", (int)hid_controller_id);
    IHS_HIDManagedDevice *managed = IHS_HIDManagerOpenDevice(probe_session->hidManager, path);
    assert(managed && !IHS_HIDDeviceStartInputReports(managed->device, 72));
    IHS_HIDDeviceLock(managed->device);
    IHS_HIDStateSDL *initial = &((IHS_HIDDeviceSDL *)managed->device)->states.current;
    bool initial_neutral = !initial->buttons && !initial->flags && !initial->eventTimestampUs;
    for (unsigned i = 0; i < 6; ++i)
        initial_neutral &= initial->axes[i] == 0;
    IHS_HIDDeviceUnlock(managed->device);
    stream_media_set_hid_session(probe_session, true);
    sl_media_gate(true);
    armed = true;
    assert(!pthread_create(&retire_thread, NULL, retire_owner, NULL));
    retire_thread_ready = true;
    assert(!pthread_create(&coordinator_thread, NULL, coordinate, NULL));
    sl_media_collect(); /* Native sensor work stays on this media/SDL thread. */
    assert(!pthread_join(coordinator_thread, NULL));
    assert(!pthread_join(retire_thread, NULL));
    armed = false;
    sl_media_collect();
    return (observation){poll_calls, protected_borrow, late_borrow, injected, retired,
        poll_returned, !hid_flush_started && !atomic_load(&hid_flush_running),
        provider->manager == NULL, hid_session == NULL, initial_neutral};
}
int main(void) {
    assert(!setenv("SDL_AUDIODRIVER", "dummy", 1));
    assert(!setenv("SDL_VIDEODRIVER", "dummy", 1));
    assert(!setenv("SDL_RENDER_DRIVER", "software", 1));
    assert(stream_media_init(NULL));
    int virtual_index = SDL_JoystickAttachVirtual(SDL_JOYSTICK_TYPE_GAMECONTROLLER, 6, 16, 0);
    assert(virtual_index >= 0);
    sl_media_collect();
    assert(hid_controller_id >= 0);
    IHS_Init();
    IHS_HIDProvider *provider = stream_media_create_hid_provider();
    assert(provider);
    sl_gfx *root = gfx;
    SDL_JoystickID controller = hid_controller_id;
    observation rounds[2];
    rounds[0] = one(provider);
    rounds[1] = one(provider);
    bool roots_retained = gfx == root && hid_controller_id == controller;
    stream_media_destroy_hid_provider(provider);
    IHS_Quit();
    assert(!SDL_JoystickDetachVirtual(virtual_index));
    stream_media_shutdown();
    bool final_clean = !sdl_ready && !locks_ready && !video;
    printf("{\"rounds\":[");
    for (unsigned i = 0; i < 2; ++i) {
        observation o = rounds[i];
        printf("%s{\"polls\":%u,\"protected_borrow\":%s,\"destroy_before_poll_return\":%s,"
               "\"injected_into_live_session\":%s,\"retired\":%s,\"poll_returned\":%s,"
               "\"hid_worker_joined\":%s,\"provider_unbound\":%s,\"session_detached\":%s,\"initial_neutral\":%s}",
               i ? "," : "", o.polls, o.protected_borrow ? "true" : "false", o.late_borrow ? "true" : "false",
               o.injected ? "true" : "false", o.retired ? "true" : "false", o.poll_returned ? "true" : "false",
               o.worker_joined ? "true" : "false", o.unbound ? "true" : "false", o.detached ? "true" : "false",
               o.initial_neutral ? "true" : "false");
    }
    printf("],\"roots_retained\":%s,\"final_clean\":%s}\n",
           roots_retained ? "true" : "false", final_clean ? "true" : "false");
    pthread_cond_destroy(&probe_wake);
    pthread_mutex_destroy(&probe_lock);
    return 0;
}
