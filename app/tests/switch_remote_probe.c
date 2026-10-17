/* Private fixture. The default target accepts network-only modes; the separate
 * opt-in media target receives 30 encoded frames. RomFS is supplied explicitly.
 * Never redirect stdio, publish this NRO, or use the normal application store. */
#include "services/auth_store.h"
#include <switch.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int sl_network_probe_run(int, char **);
#ifndef NSL_PRIVATE_MEDIA_FIXTURE
#define NSL_PRIVATE_MEDIA_FIXTURE 0
#endif
#if NSL_PRIVATE_MEDIA_FIXTURE
#define FIXTURE_KIND "MEDIA"
#define FIXTURE_NRO "nsl-sns-media-private.nro"
#define FIXTURE_DIRECTORY "sdmc:/switch/nsl-sns-media-private-%s"
#define FIXTURE_STAGE "sdmc:/switch/nsl-sns-media.stage"
#else
#define FIXTURE_KIND "NETWORK"
#define FIXTURE_NRO "nsl-sns-network-private.nro"
#define FIXTURE_DIRECTORY "sdmc:/switch/nsl-sns-private-%s"
#define FIXTURE_STAGE "sdmc:/switch/nsl-sns-network.stage"
#endif
static int log_fd = -1;
static char transcript[65536];
static size_t logged, delivered;
static const char *stage_path = FIXTURE_STAGE;
static uint64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void wipe(void *p, size_t n) { volatile unsigned char *b = p; while (n--) *b++ = 0; }
static void send_pending(void) {
    if (log_fd < 0 || delivered == logged) return;
    ssize_t n = send(log_fd, transcript+delivered, logged-delivered, MSG_DONTWAIT);
    if (n > 0) delivered += (size_t)n;
}
int sl_live_printf(const char *format, ...) {
    char line[1024];
    va_list args; va_start(args, format);
    int n = vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    if (n > 0) {
        size_t size = (size_t)n < sizeof(line) ? (size_t)n : sizeof(line)-1;
        if (size <= sizeof(transcript)-logged) {
            memcpy(transcript+logged, line, size); logged += size;
        }
        send_pending();
    }
    return n;
}
static void save_stage(const char *name) {
    FILE *f = fopen(stage_path, "w");
    if (f) { fprintf(f, "%s\n", name); fclose(f); }
}
static void sdk_atexit_returned(void) { save_stage("sdk_atexit_returned"); }
static void previous_stage(const char *path, const char *label) {
    FILE *previous=fopen(path,"r");
    if (!previous) return;
    char line[96]={0};
    if (fgets(line,sizeof(line),previous)) {
        line[strcspn(line,"\r\n")]=0;
        sl_live_printf("%s=%s\n",label,line);
    }
    fclose(previous);
}
static unsigned char *read_file(const char *path, size_t limit, size_t *size) {
    *size = 0;
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    unsigned char *data = NULL;
    if (fseek(f, 0, SEEK_END)) goto end;
    long length = ftell(f);
    if (length < 0 || (size_t)length > limit || fseek(f, 0, SEEK_SET)) goto end;
    data = malloc((size_t)length+1);
    if (data && fread(data, 1, (size_t)length, f) == (size_t)length && fgetc(f) == EOF)
        *size = (size_t)length;
    else { free(data); data = NULL; }
end:
    fclose(f);
    return data;
}
static bool wait_fd(int fd, short events, uint64_t deadline) {
    while (now_ms() < deadline) {
        struct pollfd p = {.fd=fd,.events=events};
        int ready = poll(&p, 1, 100);
        if (ready > 0) return (p.revents & events) != 0;
        if (ready < 0 && errno != EINTR) break;
    }
    return false;
}
static bool transfer(int fd, void *bytes, size_t size, bool sending, uint64_t deadline) {
    unsigned char *p = bytes;
    while (size && now_ms() < deadline) {
        ssize_t n = sending ? send(fd, p, size, MSG_DONTWAIT) : recv(fd, p, size, MSG_DONTWAIT);
        if (n > 0) { p += n; size -= (size_t)n; continue; }
        if (!n || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) return false;
        if (!wait_fd(fd, sending ? POLLOUT : POLLIN, deadline)) return false;
    }
    return size == 0;
}
static void put32(unsigned char *p, uint32_t n) {
    p[0]=n; p[1]=n>>8; p[2]=n>>16; p[3]=n>>24;
}
static bool return_profile(const char *directory, const unsigned char key[32], uint16_t port) {
    char path[512]; size_t profile_size=0, error_size=0;
    snprintf(path, sizeof(path), "%s/profile.bin", directory);
    unsigned char *profile = read_file(path, 65536, &profile_size);
    snprintf(path, sizeof(path), "%s/sns-error.private", directory);
    unsigned char *error = read_file(path, 8192, &error_size);
    if (!profile || !profile_size) { free(profile); free(error); return false; }
    size_t plain_size = 8+profile_size+error_size, cipher_size = plain_size+16;
    unsigned char *plain = calloc(1, plain_size), *cipher = malloc(cipher_size);
    int fd = -1; bool ok = false;
    mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
    mbedtls_md_context_t hmac; mbedtls_md_init(&hmac);
    unsigned char header[8]={'N','S','P','1'}, nonce[12], ack[32], expected[32];
    if (!plain || !cipher) goto cleanup;
    put32(plain, profile_size); put32(plain+4, error_size);
    memcpy(plain+8, profile, profile_size);
    if (error_size) memcpy(plain+8+profile_size, error, error_size);
    put32(header+4, cipher_size); randomGet(nonce, sizeof(nonce));
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256) ||
        mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plain_size,
            nonce, sizeof(nonce), header, sizeof(header), plain, cipher, 16, cipher+plain_size)) goto cleanup;
    const mbedtls_md_info_t *sha = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!sha || mbedtls_md_setup(&hmac, sha, 1) || mbedtls_md_hmac_starts(&hmac, key, 32) ||
        mbedtls_md_hmac_update(&hmac, (const unsigned char *)"NSP1-ACK", 8) ||
        mbedtls_md_hmac_update(&hmac, header, sizeof(header)) ||
        mbedtls_md_hmac_update(&hmac, nonce, sizeof(nonce)) ||
        mbedtls_md_hmac_update(&hmac, cipher, cipher_size) || mbedtls_md_hmac_finish(&hmac, expected)) goto cleanup;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0 || fcntl(fd, F_SETFL, O_NONBLOCK)) goto cleanup;
    struct sockaddr_in peer = {.sin_family=AF_INET,.sin_port=htons(port),.sin_addr=__nxlink_host};
    uint64_t deadline = now_ms()+5000;
    int connected = connect(fd, (void *)&peer, sizeof(peer));
    if (connected && errno != EINPROGRESS) goto cleanup;
    if (connected && !wait_fd(fd, POLLOUT, deadline)) goto cleanup;
    int pending=0; socklen_t pending_size=sizeof(pending);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &pending, &pending_size) || pending) goto cleanup;
    if (!transfer(fd, header, sizeof(header), true, deadline) ||
        !transfer(fd, nonce, sizeof(nonce), true, deadline) ||
        !transfer(fd, cipher, cipher_size, true, deadline) ||
        !transfer(fd, ack, sizeof(ack), false, deadline)) goto cleanup;
    unsigned difference = 0;
    for (unsigned i=0; i<sizeof(ack); ++i) difference |= ack[i]^expected[i];
    ok = difference == 0;
cleanup:
    if (fd >= 0) close(fd);
    mbedtls_md_free(&hmac); mbedtls_gcm_free(&gcm);
    if (plain) { wipe(plain, plain_size); free(plain); }
    if (cipher) { wipe(cipher, cipher_size); free(cipher); }
    wipe(profile, profile_size); free(profile);
    if (error) { wipe(error, error_size); free(error); }
    return ok;
}
int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
#if NSL_PRIVATE_MEDIA_FIXTURE
    bool allowed = !strcmp(mode,"--sns-desktop") || !strcmp(mode,"--sdr-only-desktop") ||
        !strcmp(mode,"--sdr-fault-desktop") || !strcmp(mode,"--sdr-warm-fault-desktop") ||
        !strcmp(mode,"--sdr-pause-desktop");
#else
    bool allowed = !strcmp(mode,"--sns-test") || !strcmp(mode,"--sdr-only-test") ||
        !strcmp(mode,"--sdr-fault-test") || !strcmp(mode,"--sdr-close-test") ||
        !strcmp(mode,"--sdr-no-connection-test");
#endif
    char *end = NULL; unsigned long port = argc > 2 ? strtoul(argv[2], &end, 10) : 0;
    bool valid=allowed && port && port <= 65535 && end && !*end;
    bool sockets = R_SUCCEEDED(socketInitializeDefault()), romfs = false;
    if (!sockets) return 1;
    log_fd = nxlinkConnectToHost(false, false);
    if (log_fd >= 0) fcntl(log_fd, F_SETFL, O_NONBLOCK);
    previous_stage(stage_path,"PREVIOUS_EXIT_STAGE");
#if !NSL_PRIVATE_MEDIA_FIXTURE
    previous_stage("sdmc:/switch/nsl-sns-media.stage","PREVIOUS_MEDIA_EXIT_STAGE");
#endif
    atexit(sdk_atexit_returned);
    save_stage("started");
    int result=1; unsigned char key[32]={0}, digest[32];
    const char *phase="romfs";
    sl_auth_store embedded={0}, existing={0}; char directory[128]={0};
    if (!valid) { result=2; phase="arguments"; goto cleanup; }
    romfs = R_SUCCEEDED(romfsInit());
    if (!romfs) goto cleanup;
    phase="embedded_profile";
    /* auth_store appends /profile.bin; libnx RomFS rejects an empty path
     * component in romfs://profile.bin. */
    int loaded=sl_auth_load(&embedded,"romfs:");
    sl_live_printf("PRIVATE_EMBEDDED_PROFILE result=%d errno=%d store_size=%zu\n",
                   loaded,loaded ? errno : 0,sizeof(embedded));
    if (loaded != 0) goto cleanup;
    phase="readback_key";
    size_t key_size=0; unsigned char *key_file=read_file("romfs:/return.key",32,&key_size);
    if (!key_file || key_size != 32) { free(key_file); goto cleanup; }
    memcpy(key,key_file,32); wipe(key_file,32); free(key_file);
    const mbedtls_md_info_t *sha = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!sha || mbedtls_md(sha,(void *)&embedded.device_id,sizeof(embedded.device_id),digest)) goto cleanup;
    char suffix[17];
    for (unsigned i=0; i<8; ++i) snprintf(suffix+2*i,3,"%02x",digest[i]);
    snprintf(directory,sizeof(directory),FIXTURE_DIRECTORY,suffix);
    char profile_path[192]; snprintf(profile_path,sizeof(profile_path),"%s/profile.bin",directory);
    phase="private_store";
    FILE *present=fopen(profile_path,"rb");
    if (present) {
        fclose(present);
        if (sl_auth_load(&existing,directory) != 0 || existing.device_id != embedded.device_id) goto cleanup;
    } else if (!sl_auth_save(&embedded,directory)) goto cleanup;
    save_stage(NSL_PRIVATE_MEDIA_FIXTURE ? "media_test" : "network_test");
    char *arguments[]={(char *)"sns-network-fixture",(char *)mode,directory,NULL};
    sl_live_printf("SWITCH_SNS_" FIXTURE_KIND "_BEGIN mode=%s network_only=%d\n",mode,!NSL_PRIVATE_MEDIA_FIXTURE);
    phase=NSL_PRIVATE_MEDIA_FIXTURE ? "media_test" : "network_test";
    result=sl_network_probe_run(3,arguments);
    save_stage(NSL_PRIVATE_MEDIA_FIXTURE ? "media_destroyed" : "network_destroyed");
    bool returned=return_profile(directory,key,(uint16_t)port);
    sl_live_printf("PROFILE_READBACK_ACK=%d\n",returned);
    if (returned) {
        const char *files[]={"profile.bin","profile.tmp","profile.bak","sns-error.private"};
        for (unsigned i=0; i<sizeof(files)/sizeof(files[0]); ++i) {
            char path[256]; snprintf(path,sizeof(path),"%s/%s",directory,files[i]);
            if (unlink(path) && errno != ENOENT) result=1;
        }
        rmdir(directory);
    } else result=1; /* Preserve a possibly rotated identity for recovery. */
    sl_live_printf("SWITCH_SNS_" FIXTURE_KIND "_RESULT=%d\n",result);
cleanup:
    sl_live_printf("PRIVATE_FIXTURE_CLEANUP phase=%s result=%d\n",phase,result);
    wipe(key,sizeof(key)); wipe(&embedded,sizeof(embedded)); wipe(&existing,sizeof(existing));
    if (romfs) romfsExit();
    /* The upload itself contains the private RomFS. Remove only this probe's
     * exact file, after unmounting RomFS, and report what could be observed. */
    const char *uploaded=argc ? argv[0] : "";
    const char *base=strrchr(uploaded,'/'); base=base ? base+1 : uploaded;
    bool safe_name=!strcmp(base,FIXTURE_NRO) &&
        !strncmp(uploaded,"sdmc:/switch/",13) && !strstr(uploaded,"/../");
    bool removed=safe_name && (unlink(uploaded) == 0 || errno == ENOENT);
    sl_live_printf("PRIVATE_NRO_REMOVED=%d known_path=%d\n",removed,safe_name);
    uint64_t deadline=now_ms()+1000;
    while (delivered < logged && now_ms() < deadline) { send_pending(); usleep(1000); }
    if (log_fd >= 0) { int fd=log_fd; log_fd=-1; close(fd); }
    save_stage("log_closed");
    socketExit();
    save_stage("socket_exit_returned");
    return result;
}
