/* Same local accepted-material/UDP peer boundary as session_recovery_runtime,
 * now with the actual application run loop, renderer, UI actions, admission,
 * lifecycle facts and gate. No private application policy is copied here. */
#define NSL_RECOVERY_APPLICATION 1
#include "session_recovery_runtime.c"
#include "platform/application.h"
#include "artwork.h"
#include "app_lifecycle.h"
#ifdef NSL_RECOVERY_MANAGER
#include "crypto.h"
#endif

static atomic_uint peer_ready, peer_stop, peer_done, peer_media;
static atomic_bool gate;
static sl_gfx *first_root;
static int virtual_controller;
static bool app_closed, overlay_closed_gate, overlay_restored_gate, root_retained = true;
static unsigned ui_round, ui_stage;
static uint64_t stream_generation, app_deadline;
static observation results[3];
static const uint8_t *encoded_video;
static size_t encoded_size;
static unsigned callbacks_before, destroys_before;
static sl_video_frame *held_frame;
static bool frame_held_once, deferred_replacement, wrong_cleanup_owner;
static uint64_t first_generation, cleanup_generation, replacement_generation;
static uint64_t next_ui_generation;
static atomic_bool abort_peer;
static atomic_uint trace_stage, trace_page, trace_phase;
static atomic_bool trace_connected;
bool __real_sl_app_allow_remote(const sl_app_lifecycle *, bool);
bool __wrap_sl_app_allow_remote(const sl_app_lifecycle *a, bool wants) {
    atomic_store(&trace_phase, a->phase);
    atomic_store(&trace_connected, a->connected);
    return __real_sl_app_allow_remote(a, wants);
}

bool __wrap_sl_http_global_acquire(void) { return false; }
sl_artwork *__wrap_sl_artwork_create(const char *path, sl_artwork_fetch_fn fetch, void *context) {
    (void)path; (void)fetch; (void)context;
    return NULL; /* Artwork network owners are outside this fixture. */
}
sl_runtime *__real_sl_runtime_create(const sl_auth_store *);
sl_runtime *__wrap_sl_runtime_create(const sl_auth_store *s) {
    sl_runtime *r = __real_sl_runtime_create(s);
    atomic_store(&actor, r);
    return r;
}
bool __real_sl_runtime_submit(sl_runtime *, const sl_command *, const sl_auth_store *);
bool __wrap_sl_runtime_submit(sl_runtime *r, const sl_command *c, const sl_auth_store *s) {
    if (c->type == SL_CMD_STREAM) {
        assert(c->generation > atomic_load(&requested) && !c->test_only && !atomic_load(&launched));
        if (ui_round == 1) first_generation = c->generation;
        if (ui_round == 2) results[0].video_clean = sl_media_video_clean();
#ifndef NSL_RECOVERY_MANAGER
        admitted_command = *c;
#endif
        assert(stream_generation == c->generation);
        atomic_store(&requested, (unsigned)c->generation);
#ifdef NSL_RECOVERY_MANAGER
        return __real_sl_runtime_submit(r, c, s);
#else
        return true; /* Given accepted launch, beyond control ticket production. */
#endif
    }
    bool ok = __real_sl_runtime_submit(r, c, s);
    if (c->type == SL_CMD_STOP && held_frame && ui_round == 2) {
        /* Pin a real retired image until the real application has queued a
         * replacement's stop. This fixes the interleaving without a sleep or
         * changing runtime facts, clocks or cleanup results. */
        deferred_replacement = true;
        cleanup_generation = c->generation;
        replacement_generation = next_ui_generation;
        assert(sl_resource_release(&held_frame->ref));
        held_frame = NULL;
    }
    return ok;
}
bool __real_sl_video_select(sl_video_pipeline *, sl_video_selection *);
bool __wrap_sl_video_select(sl_video_pipeline *p, sl_video_selection *selection) {
    bool ok = __real_sl_video_select(p, selection);
    sl_video_frame *f = ok ? selection->frame : NULL;
    if (f && !frame_held_once) {
        assert(sl_resource_retain(&f->ref));
        held_frame = f; frame_held_once = true;
    }
    return ok;
}
bool __real_stream_media_init(stream_media_log_fn);
bool __wrap_stream_media_init(stream_media_log_fn log) {
    bool ok = __real_stream_media_init(log);
    assert(ok);
    first_root = sl_media_gfx();
    virtual_controller = SDL_JoystickAttachVirtual(SDL_JOYSTICK_TYPE_GAMECONTROLLER, 6, 16, 0);
    assert(virtual_controller >= 0);
    return ok;
}
void __real_stream_media_shutdown(void);
void __wrap_stream_media_shutdown(void) {
    assert(!SDL_JoystickDetachVirtual(virtual_controller));
    __real_stream_media_shutdown();
    app_closed = !sl_media_gfx();
}
void __real_sl_media_gate(bool);
void __wrap_sl_media_gate(bool value) {
    __real_sl_media_gate(value);
    atomic_store(&gate, value);
}
void __real_sl_ui_runtime_event(sl_ui_model *, const sl_runtime_event *);
void __wrap_sl_ui_runtime_event(sl_ui_model *ui, const sl_runtime_event *e) {
#ifdef NSL_RECOVERY_CLOUD
    if (e->type == SL_EVENT_HOST) {
        if (e->discovery_source == SL_DISCOVERY_INTERNET) atomic_fetch_add(&cloud_ui_hosts, 1);
        if (e->discovery_source == SL_DISCOVERY_LAN) atomic_fetch_add(&cloud_lan_hosts, 1);
    }
#endif
    __real_sl_ui_runtime_event(ui, e);
    assert(e->type != SL_EVENT_FAILURE);
    if (ui_round && e->type == SL_EVENT_STOPPED && e->generation == stream_generation) {
        results[ui_round-1].stopped = true;
        results[ui_round-1].unexpected = e->account != 0;
    }
}
void __real_sl_ui_tick(sl_ui_model *, uint64_t);
void __wrap_sl_ui_tick(sl_ui_model *ui, uint64_t now) {
    __real_sl_ui_tick(ui, now);
    atomic_store(&trace_stage, ui_stage); atomic_store(&trace_page, ui->page);
    assert(now_ms() < app_deadline);
    sl_runtime *r = atomic_load(&actor);
    if (!r) return;
    root_retained &= first_root == sl_media_gfx();
    if (!ui_stage && atomic_load(&peer_ready) == ui_round+1 && ui->page == SL_HOME
#ifdef NSL_RECOVERY_MANAGER
        && ui->store.registry.count && sl_host_online(&ui->store.registry.hosts[0], ui->now)
#endif
        ) {
        ++ui_round;
#ifndef NSL_RECOVERY_MANAGER
        sl_runtime_event found = {.type = SL_EVENT_HOST, .host = ui->store.registry.hosts[0],
                                 .discovery_source = SL_DISCOVERY_LAN};
        sl_ui_runtime_event(ui, &found); /* Given visible-host fixture input. */
#endif
        callbacks_before = atomic_load(&disconnects); destroys_before = atomic_load(&destroyed);
        sl_ui_action(ui, SL_START, 0);
        assert(ui->page == SL_CONNECTING);
        next_ui_generation = ui->generation;
        stream_generation = ui->generation; /* UI owns the pending intent before SDK admission. */
        ui_stage = 1;
        return;
    }
    if (!ui_round || !ui_stage) return;
    observation *out = &results[ui_round-1];
    sl_runtime_facts facts;
    stream_media_snapshot snap;
    stream_media_get_snapshot(&snap);
    if (sl_runtime_read_facts(r, &facts) && facts.request_id == stream_generation &&
        facts.session_id && snap.session_id == facts.session_id) {
        out->session_id = facts.session_id;
        out->displayed |= snap.first_frame_displayed;
        out->audio |= snap.audio_active && snap.audio_frames > 0;
    }
    if (ui_round == 2 && ui_stage == 1 && out->displayed && out->audio && ui->page == SL_HOME &&
        atomic_load(&trace_phase) == SL_APP_STREAMING && !atomic_load(&gate)) {
        /* Runnable old-behavior counterexample: retire normally instead of
         * using a crash or timeout as evidence that the UI lost ownership. */
        wrong_cleanup_owner = true;
        atomic_store(&abort_peer, true);
        sl_ui_action(ui, SL_BACK, 0); assert(ui->page == SL_EXIT);
        sl_ui_action(ui, SL_CONFIRM_EXIT, 0); ui_stage = 6;
        return;
    }
    if (ui_stage == 1 && out->displayed && out->audio && ui->page == SL_STREAM && atomic_load(&gate)) {
        if (ui_round == 1) {
            sl_ui_action(ui, SL_OPEN_MENU, 0);
            assert(ui->page == SL_MENU);
            ui_stage = 2;
        } else {
            atomic_store(&peer_stop, ui_round);
            ui_stage = 4;
        }
    } else if (ui_stage == 2 && ui->page == SL_MENU && !atomic_load(&gate)) {
        overlay_closed_gate = true;
        sl_ui_action(ui, SL_BACK, 0);
        assert(ui->page == SL_MENU && ui->leaving); /* Real tick completes the fade. */
        ui_stage = 3;
    } else if (ui_stage == 3 && ui->page == SL_STREAM && atomic_load(&gate)) {
        overlay_restored_gate = true;
        atomic_store(&peer_stop, ui_round);
        ui_stage = 4;
    } else if (ui_stage == 4 && out->stopped && !atomic_load(&gate) &&
               (ui_round == 1 || sl_media_video_clean())) {
        out->ui_error = ui->page == SL_ERROR && !ui->streaming;
        out->ui_home = ui->page == SL_HOME && !ui->streaming;
        out->callbacks = atomic_load(&disconnects)-callbacks_before;
        out->destroys = atomic_load(&destroyed)-destroys_before;
        out->host_stop = atomic_load(&last_host_stop); out->timed_out = atomic_load(&last_timed_out);
        out->audio_closed = !atomic_load(&stream_audio_device);
        out->video_clean = sl_media_video_clean();
        out->hid_unbound = r->provider && !r->provider->manager;
        if (ui_round == 2) {
            assert(ui->page == SL_ERROR);
            sl_ui_action(ui, SL_BACK, 0);
            assert(ui->page == SL_STOPPING);
            ui_stage = 5;
        } else {
            assert(ui->page == SL_HOME);
            ui_stage = 5;
        }
    } else if (ui_stage == 5 && ui->page == SL_HOME && !atomic_load(&gate)) {
        out->returned_home = true;
        atomic_store(&peer_done, ui_round);
        if (ui_round == 3) {
            sl_ui_action(ui, SL_BACK, 0);
            assert(ui->page == SL_EXIT);
            sl_ui_action(ui, SL_CONFIRM_EXIT, 0);
            ui_stage = 6;
        } else ui_stage = 0;
    }
}

#ifdef NSL_RECOVERY_MANAGER
static unsigned control_discoveries, control_requests, control_cancels, control_tokens;
static uint32_t launch_ids[3];
static void control_reply(const struct sockaddr_in *to, ERemoteClientBroadcastMsg tag,
                           const ProtobufCMessage *body) {
    uint8_t wire[2048] = {255, 255, 255, 255, 33, 76, 95, 160};
    CMsgRemoteClientBroadcastHeader h = CMSG_REMOTE_CLIENT_BROADCAST_HEADER__INIT;
    h.has_client_id = h.has_instance_id = h.has_msg_type = true;
    h.client_id = 7; h.instance_id = 1; h.msg_type = tag;
    size_t hs = protobuf_c_message_get_packed_size(&h.base), ms = protobuf_c_message_get_packed_size(body);
    assert(hs+ms+16 <= sizeof(wire));
    IHS_WriteUInt32LE(wire+8, (uint32_t)hs); protobuf_c_message_pack(&h.base, wire+12);
    IHS_WriteUInt32LE(wire+12+hs, (uint32_t)ms); protobuf_c_message_pack(body, wire+16+hs);
    size_t size = hs+ms+16;
#ifdef NSL_RECOVERY_CLOUD
    (void)to;
    cloud_fixture_notify(wire, size);
#else
    assert(sendto(fixture_control_fd, wire, size, 0, (const void *)to, sizeof(*to)) == (ssize_t)size);
#endif
}
static void control_receive_bytes(const uint8_t *raw, size_t size, const struct sockaddr_in *from) {
    assert(size >= 16 && !memcmp(raw, "\xff\xff\xff\xff\x21\x4c\x5f\xa0", 8));
    uint32_t hs, ms;
    IHS_ReadUInt32LE(raw+8, &hs); assert(hs <= (size_t)size-16);
    IHS_ReadUInt32LE(raw+12+hs, &ms); assert(ms == (size_t)size-hs-16);
    CMsgRemoteClientBroadcastHeader *h = cmsg_remote_client_broadcast_header__unpack(NULL, hs, raw+12);
    assert(h && h->client_id == 1);
    if (h->msg_type == k_ERemoteClientBroadcastMsgDiscovery) {
        CMsgRemoteClientBroadcastStatus status = CMSG_REMOTE_CLIENT_BROADCAST_STATUS__INIT;
        status.hostname = "Loopback host"; status.has_euniverse = true; status.euniverse = IHS_SteamUniversePublic;
        status.has_games_running = status.has_timestamp = true;
        status.timestamp = (uint32_t)time(NULL);
        CMsgRemoteClientBroadcastStatus__User user = CMSG_REMOTE_CLIENT_BROADCAST_STATUS__USER__INIT;
        user.has_steamid = true; user.steamid = UINT64_C(76561198000000001);
        CMsgRemoteClientBroadcastStatus__User *users[] = {&user};
        status.n_users = 1; status.users = users;
        control_reply(from, k_ERemoteClientBroadcastMsgStatus, &status.base);
        ++control_discoveries;
    } else if (h->msg_type == k_ERemoteDeviceStreamingRequest) {
        CMsgRemoteDeviceStreamingRequest *m = cmsg_remote_device_streaming_request__unpack(NULL, ms, raw+16+hs);
        assert(m && m->request_id && m->client_id == 7 && m->n_supported_transport &&
               m->supported_transport[0] == k_EStreamTransportUDP && !m->network_test);
        unsigned slot = atomic_load(&peer_ready)-1;
        assert(slot < 3 && (!launch_ids[slot] || launch_ids[slot] == m->request_id));
        launch_ids[slot] = m->request_id; ++control_requests;
        uint8_t key[32], secret[32] = {0}, encrypted_key[80]; size_t encrypted_size = sizeof(encrypted_key);
        uint8_t token[64]; size_t token_size = sizeof(token); uint64_t token_id;
        assert(m->has_device_token && m->device_token.len == 32 &&
               !IHS_CryptoSymmetricDecrypt(m->device_token.data, m->device_token.len, secret,
                    sizeof(secret), token, &token_size) && token_size == 8);
        IHS_ReadUInt64LE(token, &token_id); assert(token_id == 1); ++control_tokens;
        for (unsigned i = 0; i < 32; ++i) key[i] = (uint8_t)i;
        assert(!IHS_CryptoSymmetricEncrypt(key, sizeof(key), secret, sizeof(secret), encrypted_key, &encrypted_size));
        CMsgRemoteDeviceStreamingResponse response = CMSG_REMOTE_DEVICE_STREAMING_RESPONSE__INIT;
        response.request_id = m->request_id; response.result = k_ERemoteDeviceStreamingSuccess;
        response.has_port = response.has_transport = response.has_encrypted_session_key = true;
        response.port = endpoint.port; response.transport = k_EStreamTransportUDP;
#ifdef NSL_RECOVERY_CLOUD
        response.transport = k_EStreamTransportSDR;
        response.cert = "controlled-test-certificate";
        response.relay_server = "stun:fixture.invalid:3478";
#endif
        response.encrypted_session_key = (ProtobufCBinaryData){encrypted_size, encrypted_key};
        control_reply(from, k_ERemoteDeviceStreamingResponse, &response.base);
        cmsg_remote_device_streaming_request__free_unpacked(m, NULL);
    } else if (h->msg_type == k_ERemoteDeviceStreamingCancelRequest) ++control_cancels;
    cmsg_remote_client_broadcast_header__free_unpacked(h, NULL);
}
#ifndef NSL_RECOVERY_CLOUD
static void control_receive(void) {
    uint8_t raw[4096]; struct sockaddr_in from; socklen_t len = sizeof(from);
    ssize_t size = recvfrom(fixture_control_fd, raw, sizeof(raw), 0, (void *)&from, &len);
    assert(size >= 0);
    control_receive_bytes(raw, (size_t)size, &from);
}
#endif
#endif
static void *peer_thread(void *unused) {
    (void)unused;
    for (unsigned round = 1; round <= 3; ++round) {
        if (atomic_load(&abort_peer)) break;
        int fd = __real_socket(AF_INET, SOCK_DGRAM, 0); assert(fd >= 0);
        struct sockaddr_in local_address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        assert(!bind(fd, (void *)&local_address, sizeof(local_address)));
        socklen_t len = sizeof(local_address);
        assert(!getsockname(fd, (void *)&local_address, &len));
        endpoint = (IHS_SocketAddress){.port = ntohs(local_address.sin_port)};
        assert(IHS_IPAddressFromString(&endpoint.ip, "127.0.0.1"));
        atomic_store(&channels_ready, 0);
        atomic_store(&peer_ready, round);
        bool hello = false, auth = false, configured = false, started = false;
        bool media_sent = false, silence = false;
        uint8_t local = 0;
        struct sockaddr_in client = {0};
        uint64_t deadline = now_ms()+25000;
        while (atomic_load(&peer_done) < round && !atomic_load(&abort_peer)) {
            if (now_ms() >= deadline)
                fprintf(stderr, "peer timeout round=%u stop=%u stage=%u page=%u phase=%u connected=%d gate=%d\n",
                        round, atomic_load(&peer_stop), atomic_load(&trace_stage), atomic_load(&trace_page),
                        atomic_load(&trace_phase), atomic_load(&trace_connected), atomic_load(&gate));
            assert(now_ms() < deadline);
            if (started && !media_sent && atomic_load(&channels_ready) == ((1u<<3)|(1u<<4))) {
                media(fd, &client, local, 3, encoded_video, encoded_size, true);
                const uint8_t opus[] = {0xf0, 0xff, 0xfe};
                media(fd, &client, local, 4, opus, sizeof(opus), false);
                media_sent = true; atomic_store(&peer_media, round);
            }
            if (atomic_load(&peer_stop) == round && !silence) {
                assert(media_sent);
                if (round != 2) wire(fd, &client, 9, local, 0, 0, 0, NULL, 0);
                silence = true;
            }
            struct pollfd p[2] = {{.fd = fd, .events = POLLIN}};
            unsigned count = 1;
#if defined(NSL_RECOVERY_MANAGER) && !defined(NSL_RECOVERY_CLOUD)
            p[1] = (struct pollfd){.fd = fixture_control_fd, .events = POLLIN}; count = 2;
#endif
            int ready = poll(p, count, 1); assert(ready >= 0);
            if (!ready) continue;
#if defined(NSL_RECOVERY_MANAGER) && !defined(NSL_RECOVERY_CLOUD)
            if (p[1].revents & POLLIN) control_receive();
#endif
            if (!(p[0].revents & POLLIN)) continue;
            uint8_t raw[4096]; len = sizeof(client);
            ssize_t size = recvfrom(fd, raw, sizeof(raw), 0, (void *)&client, &len);
            assert(size >= 13);
            if (silence) continue;
            local = raw[2]; unsigned type = raw[0]&127;
            if (type == 1) wire(fd, &client, 2, local, 0, 0, 0, raw+9, 4);
            else if (type == 5 && raw[4] == 1) {
                uint16_t id = (uint16_t)(raw[7] | (unsigned)raw[8]<<8);
                wire(fd, &client, 7, local, 1, id, 0, raw+9, 4);
                if (raw[13] == 6 && !hello) {
                    const uint8_t server[] = {7, 10, 3, 8, 0xc0, 0x0b};
                    wire(fd, &client, 5, local, 1, 0, 0, server, sizeof(server)); hello = true;
                } else if (raw[13] == 1 && !auth) {
                    const uint8_t response[] = {2, 8, 0, 16, 1}, init[] = {8, 1, 16, 3, 24, 4};
                    wire(fd, &client, 5, local, 1, 1, 0, response, sizeof(response));
                    encrypted(fd, &client, local, 2, 3, init, sizeof(init), 0); auth = true;
                } else if (raw[13] == 4 && !configured) {
                    IHS_Buffer in = IHS_BUFFER_WRAP(raw+14, (size_t)size-18), plain = IHS_BUFFER_INIT(1024, 4096);
                    uint64_t seq;
                    assert(IHS_SessionFrameDecrypt(atomic_load(&launched), &in, &plain, 0, &seq) == IHS_SessionFrameDecryptOK);
                    CNegotiationSetConfigMsg *m = cnegotiation_set_config_msg__unpack(NULL, plain.size, IHS_BufferPointer(&plain));
                    assert(m && m->config); message(fd, &client, local, 3, 4, &m->base, 1);
                    cnegotiation_set_config_msg__free_unpacked(m, NULL); IHS_BufferClear(&plain, true);
                    configured = true;
                } else if (raw[13] == 5 && !started) {
                    assert(configured);
                    CStartVideoDataMsg v = CSTART_VIDEO_DATA_MSG__INIT;
                    v.channel = 3; v.has_codec = v.has_width = v.has_height = true;
                    v.codec = k_EStreamVideoCodecH264; v.width = 128; v.height = 72;
                    message(fd, &client, local, 4, 52, &v.base, 2);
                    CStartAudioDataMsg a = CSTART_AUDIO_DATA_MSG__INIT;
                    a.channel = 4; a.has_codec = a.has_frequency = a.has_channels = true;
                    a.codec = k_EStreamAudioCodecOpus; a.frequency = 48000; a.channels = 2;
                    message(fd, &client, local, 5, 50, &a.base, 3); started = true;
                }
            }
        }
        close(fd);
    }
    return NULL;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    assert(!setenv("SDL_AUDIODRIVER", "dummy", 1) && !setenv("SDL_VIDEODRIVER", "dummy", 1));
    assert(!setenv("SDL_RENDER_DRIVER", "software", 1));
    char directory[] = "/tmp/nsl-application-recovery-XXXXXX";
    assert(mkdtemp(directory) && !setenv("NSL_DATA_DIR", directory, 1));
    FILE *file = fopen(argv[1], "rb"); assert(file && !fseek(file, 0, SEEK_END));
    long size = ftell(file); assert(size > 0 && size < 16000); rewind(file);
    uint8_t *video = malloc((size_t)size); assert(video);
    assert(fread(video, 1, (size_t)size, file) == (size_t)size && !fclose(file));
    encoded_video = video; encoded_size = (size_t)size;
    sl_auth_store store = {.device_id = 1, .sound = false};
    strcpy(store.device_name, "application recovery fixture"); sl_host_registry_init(&store.registry);
    sl_host host = {.client_id = 7, .instance_id = 1}; strcpy(host.name, "Loopback host"); strcpy(host.address, "127.0.0.1");
#ifdef NSL_RECOVERY_CLOUD
    host.address[0] = 0; /* Cloud membership has no local reachability evidence. */
#endif
    sl_host *saved = sl_host_observe(&store.registry, &host, 0); assert(saved); saved->paired = true;
#ifdef NSL_RECOVERY_MANAGER
    saved->account = UINT64_C(76561198000000001);
#endif
    assert(sl_auth_save(&store, directory));
#ifdef NSL_RECOVERY_MANAGER
    /* Model a previously completed network test; this case exercises ordinary
     * request/handoff, not the separate automatic first-connect test owner. */
    sl_network_stats_average average = {0};
    assert(sl_network_stats_save(directory, &average, NULL, 0));
#ifndef NSL_RECOVERY_CLOUD
    fixture_control_fd = __real_socket(AF_INET, SOCK_DGRAM, 0); assert(fixture_control_fd >= 0);
    fixture_control_address = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(!bind(fixture_control_fd, (void *)&fixture_control_address, sizeof(fixture_control_address)));
    socklen_t length = sizeof(fixture_control_address);
    assert(!getsockname(fixture_control_fd, (void *)&fixture_control_address, &length));
#endif
#endif
    app_deadline = now_ms()+75000;
    pthread_t peer; assert(!pthread_create(&peer, NULL, peer_thread, NULL));
    char *args[] = {"nsteamlink", NULL};
    int result = sl_application_run(1, args);
    assert(!pthread_join(peer, NULL));
#if defined(NSL_RECOVERY_MANAGER) && !defined(NSL_RECOVERY_CLOUD)
    close(fixture_control_fd);
#endif
    atomic_store(&actor, NULL);
    free(video); sl_fixture_remove_tree(directory);
    printf("{\"application_exit\":%d,\"rounds\":[", result);
    for (unsigned i = 0; i < 3; ++i) {
        observation o = results[i];
        printf("%s{\"displayed\":%s,\"audio\":%s,\"stopped\":%s,\"unexpected\":%s,"
               "\"ui_error\":%s,\"ui_home\":%s,\"video_clean\":%s,\"hid_unbound\":%s,"
               "\"timed_out\":%s,\"host_stop\":%s,\"audio_closed\":%s,\"returned_home\":%s,"
               "\"callbacks\":%u,\"destroys\":%u,\"session_id\":%llu}",i?",":"",
               o.displayed?"true":"false",o.audio?"true":"false",o.stopped?"true":"false",
               o.unexpected?"true":"false",o.ui_error?"true":"false",o.ui_home?"true":"false",
               o.video_clean?"true":"false",o.hid_unbound?"true":"false",o.timed_out?"true":"false",
               o.host_stop?"true":"false",o.audio_closed?"true":"false",o.returned_home?"true":"false",
               o.callbacks,o.destroys,(unsigned long long)o.session_id);
    }
    printf("],\"root_retained\":%s,\"joins_clean\":%s,\"final_clean\":%s,\"audio_opens\":%u,\"audio_closes\":%u,"
           "\"overlay_closed_gate\":%s,\"overlay_restored_gate\":%s,\"peer_joined\":true,"
           "\"deferred_replacement\":%s,\"wrong_cleanup_owner\":%s,\"first_generation\":%llu,"
           "\"cleanup_generation\":%llu,\"replacement_generation\":%llu",
           root_retained?"true":"false",joins_clean?"true":"false",app_closed?"true":"false",
           atomic_load(&audio_opens),atomic_load(&audio_closes),overlay_closed_gate?"true":"false",
           overlay_restored_gate?"true":"false",deferred_replacement?"true":"false",
           wrong_cleanup_owner?"true":"false",(unsigned long long)first_generation,
           (unsigned long long)cleanup_generation,(unsigned long long)replacement_generation);
#ifdef NSL_RECOVERY_MANAGER
    printf(",\"control_discoveries\":%u,\"control_requests\":%u,\"control_cancels\":%u,\"control_tokens\":%u,"
           "\"manager_handoffs\":%u,\"manager_ticket_phases\":%u,\"launch_ids\":[%u,%u,%u]",
           control_discoveries, control_requests, control_cancels, control_tokens, atomic_load(&manager_handoffs),
           atomic_load(&manager_ticket_phases),launch_ids[0],launch_ids[1],launch_ids[2]);
#endif
#ifdef NSL_RECOVERY_CLOUD
    void cloud_fixture_projection(void);
    cloud_fixture_projection();
#endif
    printf("}\n");
    return 0;
}
