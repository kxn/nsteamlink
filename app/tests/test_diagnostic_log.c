#include "diagnostic_log.h"
#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static char root[] = "/tmp/nsl-log-test-XXXXXX";
static const char *data_root = root;
const char *sl_system_data_dir(void) {
    return data_root;
}
uint64_t sl_system_now(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
void sl_system_log(const char *message) {
    (void)message;
}
static unsigned port(void) {
    for (unsigned i = 0; i < 1000; ++i) {
        unsigned value = sl_log_http_port();
        if (value)
            return value;
        usleep(1000);
    }
    assert(0);
    return 0;
}
static size_t get(const char *request, char *reply, size_t capacity) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct timeval timeout = {.tv_sec = 3};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in addr = {.sin_family = AF_INET,
                               .sin_port = htons(port()),
                               .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(!connect(fd, (struct sockaddr *)&addr, sizeof(addr)));
    assert(send(fd, request, strlen(request), 0) == (ssize_t)strlen(request));
    size_t size = 0;
    ssize_t n;
    while ((n = recv(fd, reply + size, capacity - size - 1, 0)) > 0) {
        size += n;
        assert(size < capacity - 1);
    }
    assert(n == 0);
    reply[size] = 0;
    close(fd);
    return size;
}
static unsigned files(char names[][96], unsigned capacity) {
    char path[512];
    snprintf(path, sizeof(path), "%s/logs", root);
    DIR *dir = opendir(path);
    assert(dir);
    unsigned count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)))
        if (!strncmp(entry->d_name, "session-", 8)) {
            assert(count < capacity);
            snprintf(names[count++], 96, "%.95s", entry->d_name);
        }
    closedir(dir);
    return count;
}
int main(void) {
    alarm(18);
    assert(mkdtemp(root));
    char path[512], reply[65536], names[128][96];
    snprintf(path, sizeof(path), "%s/stream_diag.log", root);
    FILE *legacy = fopen(path, "w");
    assert(legacy);
    fputs("OLD FAILURE MUST SURVIVE\n", legacy);
    fclose(legacy);
    snprintf(path, sizeof(path), "%s/stream_diag_prev.log", root);
    legacy = fopen(path, "w");
    assert(legacy);
    for (unsigned i = 0; i < 153600; ++i)
        fputc('A' + i % 26, legacy);
    fclose(legacy);
    snprintf(path, sizeof(path), "%s/profile.bin", root);
    FILE *secret = fopen(path, "w");
    assert(secret);
    fputs("DO NOT SERVE", secret);
    fclose(secret);
    assert(sl_log_start());
    port();
    /* More than the test segment size: records must continue in fresh volumes. */
    for (unsigned i = 0; i < 240; ++i) {
        char line[180];
        snprintf(line, sizeof(line),
                 "marker=%03u abcdefghijklmnopqrstuvwxyz "
                 "012345678901234567890123456789012345678901234567890123456789",
                 i);
        /* The public producer intentionally drops rather than blocking on a
         * busy queue mutex. Retry rejected test markers; accepted records must
         * all survive segmentation and restart. */
        for (unsigned attempt = 0;; ++attempt) {
            unsigned before = sl_log_drop_count();
            sl_log(line);
            if (sl_log_drop_count() == before)
                break;
            assert(attempt < 1000);
            usleep(1000);
        }
        usleep(1000);
    }
    for (unsigned i = 0; i < 1000; ++i) {
        if (sl_log_copy_tail(reply, sizeof(reply), false) && strstr(reply, "marker=239"))
            break;
        assert(i < 999);
        usleep(1000);
    }
    get("GET /logs HTTP/1.1\r\nHost: local\r\n\r\n", reply, sizeof(reply));
    assert(strstr(reply, "200 Response") && strstr(reply, "stream_diag.log") &&
           strstr(reply, "session-") && !strstr(reply, "profile.bin"));
    get("GET /logs/stream_diag.log HTTP/1.1\r\nHost: local\r\nRange: bytes=0-10\r\n\r\n", reply,
        sizeof(reply));
    assert(strstr(reply, "206 OK") && strstr(reply, "Content-Range: bytes 0-10/25"));
    assert(!strcmp(strstr(reply, "\r\n\r\n") + 4, "OLD FAILURE"));
    get("GET /logs/../profile.bin HTTP/1.1\r\nHost: local\r\n\r\n", reply, sizeof(reply));
    assert(strstr(reply, "404 Response") && !strstr(reply, "DO NOT SERVE"));
    get("GET /logs/stream_diag.log HTTP/1.1\r\nHost: local\r\nRange: bytes=10-5\r\n\r\n", reply,
        sizeof(reply));
    assert(strstr(reply, "416 Response"));
    get("GET /logs/stream_diag_prev.log HTTP/1.1\r\nHost: local\r\nRange: "
        "bytes=32768-65535\r\n\r\n",
        reply, sizeof(reply));
    char *large_body = strstr(reply, "\r\n\r\n") + 4;
    assert(strlen(large_body) == 32768);
    for (unsigned i = 0; i < 32768; ++i)
        assert(large_body[i] == (char)('A' + (32768 + i) % 26));
    unsigned before = files(names, 128);
    assert(before >= 2);
    sl_log_finish();
    assert(!sl_log_http_port());
    /* More archives than one manifest page must all remain downloadable. */
    for (unsigned i = 0; i < 70; ++i) {
        snprintf(path, sizeof(path), "%s/logs/session-99999999999999999999-%09u-00000.log", root,
                 i);
        FILE *empty = fopen(path, "w");
        assert(empty);
        fclose(empty);
    }
    /* A second complete logger lifetime must retain both all segments and the
     * old three-file format, and reopen its service after joining the first. */
    assert(sl_log_start());
    port();
    get("GET /logs HTTP/1.1\r\nHost: local\r\n\r\n", reply, sizeof(reply));
    for (unsigned i = 0; i < before; ++i)
        assert(strstr(reply, names[i]));
    unsigned listed = 0, pages = 0;
    char cursor[96] = {0};
    do {
        char request[256];
        snprintf(request, sizeof(request), "GET /logs%s%s HTTP/1.1\r\nHost: local\r\n\r\n",
                 cursor[0] ? "?after=" : "", cursor);
        get(request, reply, sizeof(reply));
        const char *entry = reply;
        while ((entry = strstr(entry, "\"name\":\""))) {
            ++listed;
            ++entry;
        }
        const char *next = strstr(reply, "\"next_after\":\"");
        assert(next);
        next += strlen("\"next_after\":\"");
        const char *end = strchr(next, '"');
        assert(end && end - next < (ptrdiff_t)sizeof(cursor));
        memcpy(cursor, next, end - next);
        cursor[end - next] = 0;
        assert(++pages < 5);
    } while (cursor[0]);
    assert(pages == 2 && listed == files(names, 128) + 2);
    get("GET /logs/stream_diag.log HTTP/1.1\r\nHost: local\r\n\r\n", reply, sizeof(reply));
    assert(!strcmp(strstr(reply, "\r\n\r\n") + 4, "OLD FAILURE MUST SURVIVE\n"));
    sl_log_finish();
    /* Unwritable storage must be visible through the running service. */
    char failed_root[512];
    snprintf(failed_root, sizeof(failed_root), "%s/profile.bin", root);
    data_root = failed_root; /* Existing regular file, so archive creation fails. */
    assert(sl_log_start());
    port();
    get("GET /logs HTTP/1.1\r\nHost: local\r\n\r\n", reply, sizeof(reply));
    assert(strstr(reply, "\"storage_errno\":") && !strstr(reply, "\"storage_errno\":0"));
    assert(!strstr(reply, "DO NOT SERVE"));
    sl_log_finish();
    data_root = root;
    unsigned after = files(names, 128);
    assert(after > before);
    char all[65536] = {0};
    size_t used = 0;
    for (unsigned i = 0; i < after; ++i) {
        snprintf(path, sizeof(path), "%s/logs/%.95s", root, names[i]);
        FILE *f = fopen(path, "r");
        assert(f);
        used += fread(all + used, 1, sizeof(all) - used - 1, f);
        fclose(f);
        assert(!unlink(path));
    }
    for (unsigned i = 0; i < 240; ++i) {
        char marker[20];
        snprintf(marker, sizeof(marker), "marker=%03u ", i);
        assert(strstr(all, marker));
    }
    snprintf(path, sizeof(path), "%s/logs", root);
    assert(!rmdir(path));
    snprintf(path, sizeof(path), "%s/stream_diag.log", root);
    assert(!unlink(path));
    snprintf(path, sizeof(path), "%s/stream_diag_prev.log", root);
    assert(!unlink(path));
    snprintf(path, sizeof(path), "%s/profile.bin", root);
    assert(!unlink(path));
    assert(!rmdir(root));
    puts("persistent log segmentation, restart, HTTP snapshots/ranges and path isolation passed");
}
