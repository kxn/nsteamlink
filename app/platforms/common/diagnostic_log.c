#include "diagnostic_log.h"
#include "build_identity.h"
#include "platform/system.h"
#include <stdio.h>
#include <string.h>

#if NSL_DIAGNOSTICS
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef NSL_DIAGNOSTIC_PORT
#define NSL_DIAGNOSTIC_PORT 28773
#endif
#ifndef NSL_DIAGNOSTIC_SEGMENT_BYTES
#define NSL_DIAGNOSTIC_SEGMENT_BYTES (4U * 1024U * 1024U)
#endif
#define PAGE_SIZE 64
#define NAME_SIZE 96
#define TAIL_SIZE 3500

static pthread_mutex_t lock;
static pthread_t worker;
static atomic_bool ready, stopping;
static atomic_uint dropped, http_port;
static bool started;
static char queue[128][224], tail[TAIL_SIZE + 1], previous_tail[TAIL_SIZE + 1];
static unsigned head, consumed;
static size_t tail_size;

/* One owner: the existing log worker owns all files and HTTP sockets. */
typedef struct log_store {
    char root[512], directory[544], run[64], active[NAME_SIZE];
    unsigned part;
    FILE *file;
    size_t written;
    uint64_t accept_after;
    int storage_error, listen_error;
} log_store;
typedef struct http_client {
    int fd;
    char request[2048], output[16384];
    char active_snapshot[NAME_SIZE];
    size_t received, size, sent;
    FILE *file;
    uint64_t remaining, deadline, offset;
    bool responding;
} http_client;
typedef struct log_entry {
    char name[NAME_SIZE];
    uint64_t size;
} log_entry;

void sl_log(const char *message) {
    if (!atomic_load(&ready))
        return;
    if (pthread_mutex_trylock(&lock)) {
        atomic_fetch_add(&dropped, 1);
        return;
    }
    if (head - consumed < 128)
        snprintf(queue[head++ % 128], sizeof(queue[0]), "%.220s", message);
    else
        atomic_fetch_add(&dropped, 1);
    pthread_mutex_unlock(&lock);
}
unsigned sl_log_drop_count(void) {
    return atomic_load(&dropped);
}
uint16_t sl_log_http_port(void) {
    return atomic_load(&http_port);
}
bool sl_log_copy_tail(char *out, size_t capacity, bool previous) {
    if (!capacity || !atomic_load(&ready) || pthread_mutex_trylock(&lock))
        return false;
    snprintf(out, capacity, "OK %s", previous ? previous_tail : tail);
    pthread_mutex_unlock(&lock);
    return true;
}

static bool valid_name(const char *name) {
    size_t n = strlen(name);
    if (n < 12 || n >= NAME_SIZE || strncmp(name, "session-", 8) || strcmp(name + n - 4, ".log"))
        return false;
    for (size_t i = 8; i < n - 4; ++i)
        if ((name[i] < '0' || name[i] > '9') && name[i] != '-' && name[i] != 'p')
            return false;
    return true;
}
static bool log_path(const log_store *store, const char *name, char *path, size_t capacity) {
    const char *legacy[] = {"stream_diag.log", "stream_diag_prev.log", "stream_diag_older.log"};
    for (unsigned i = 0; i < 3; ++i)
        if (!strcmp(name, legacy[i]))
            return snprintf(path, capacity, "%s/%s", store->root, name) < (int)capacity;
    return valid_name(name) &&
           snprintf(path, capacity, "%s/%s", store->directory, name) < (int)capacity;
}
static bool open_segment(log_store *store) {
    if (store->file)
        fclose(store->file);
    store->file = NULL;
    store->written = 0;
    for (unsigned tries = 0; tries < 1024; ++tries) {
        char path[672];
        snprintf(store->active, sizeof(store->active), "%s-%05u.log", store->run, store->part++);
        if (!log_path(store, store->active, path, sizeof(path)))
            break;
        int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
        if (fd < 0) {
            if (errno == EEXIST)
                continue;
            break;
        }
        store->file = fdopen(fd, "w+");
        if (!store->file) {
            int saved = errno;
            close(fd);
            errno = saved;
            break;
        }
        int n = fprintf(store->file, "diagnostic version=%s commit=%s unix_time=%lld part=%u\n",
                        NSL_APP_VERSION, NSL_GIT_COMMIT, (long long)time(NULL), store->part - 1);
        if (n > 0 && !fflush(store->file)) {
            store->written = n;
            store->storage_error = 0;
            return true;
        }
        break;
    }
    store->storage_error = errno ? errno : EIO;
    if (store->file)
        fclose(store->file);
    store->file = NULL;
    store->active[0] = 0;
    return false;
}
static void write_line(log_store *store, const char *message) {
    char line[272];
    int n = snprintf(line, sizeof(line), "%llu %s\n", (unsigned long long)sl_system_now(), message);
    if (!store->file || n <= 0 || n >= (int)sizeof(line))
        return;
    if (store->written + (size_t)n > NSL_DIAGNOSTIC_SEGMENT_BYTES && !open_segment(store))
        return;
    if (fwrite(line, 1, n, store->file) != (size_t)n || fflush(store->file)) {
        store->storage_error = errno ? errno : EIO;
        fclose(store->file);
        store->file = NULL;
        store->active[0] = 0;
    } else
        store->written += n;
}
static void load_previous(log_store *store) {
    char newest[NAME_SIZE] = {0}, path[672];
    DIR *dir = opendir(store->directory);
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)))
            if (valid_name(entry->d_name) && strcmp(entry->d_name, newest) > 0)
                snprintf(newest, sizeof(newest), "%.95s", entry->d_name);
        closedir(dir);
    }
    if (!log_path(store, newest[0] ? newest : "stream_diag.log", path, sizeof(path)))
        return;
    FILE *f = fopen(path, "r");
    if (!f)
        return;
    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    fseek(f, length > TAIL_SIZE ? length - TAIL_SIZE : 0, SEEK_SET);
    char text[TAIL_SIZE + 1];
    size_t n = fread(text, 1, TAIL_SIZE, f);
    fclose(f);
    text[n] = 0;
    pthread_mutex_lock(&lock);
    memcpy(previous_tail, text, n + 1);
    pthread_mutex_unlock(&lock);
}
static void client_close(http_client *client) {
    if (!client)
        return;
    if (client->file)
        fclose(client->file);
    if (client->fd >= 0)
        close(client->fd);
    memset(client, 0, sizeof(*client));
    client->fd = -1;
}
static void response(http_client *client, int code, const char *type, const char *body) {
    size_t n = strlen(body);
    int header = snprintf(client->output, sizeof(client->output),
                          "HTTP/1.1 %d Response\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
                          "Connection: close\r\nCache-Control: no-store\r\n"
                          "X-Content-Type-Options: nosniff\r\n\r\n",
                          code, type, n);
    if (header < 0 || (size_t)header + n > sizeof(client->output)) {
        client_close(client);
        return;
    }
    memcpy(client->output + header, body, n);
    client->size = header + n;
    client->responding = true;
}
static void insert_entry(log_entry *entries, unsigned *count, bool *more, const char *name,
                         uint64_t size, const char *after) {
    if (strcmp(name, after) <= 0)
        return;
    unsigned pos = 0;
    while (pos < *count && strcmp(entries[pos].name, name) < 0)
        ++pos;
    if (pos < *count && !strcmp(entries[pos].name, name))
        return;
    if (*count == PAGE_SIZE) {
        *more = true;
        if (pos == PAGE_SIZE)
            return;
    } else
        ++*count;
    memmove(entries + pos + 1, entries + pos, (*count - pos - 1) * sizeof(*entries));
    snprintf(entries[pos].name, NAME_SIZE, "%s", name);
    entries[pos].size = size;
}
static int snapshot_stat(log_store *store, const char *name, const char *path, struct stat *st) {
    /* libnx stat(path) opens a second read handle, which Horizon rejects for
     * a file already open for writing. The worker owns the existing handle. */
    if (store->file && !strcmp(name, store->active))
        return fstat(fileno(store->file), st);
    return stat(path, st);
}
static void index_response(log_store *store, http_client *client, const char *after) {
    struct index_page {
        log_entry entries[PAGE_SIZE];
        char body[12288];
    };
    struct index_page *page = calloc(1, sizeof(*page));
    if (!page) {
        response(client, 500, "text/plain", "Cannot allocate log index\n");
        return;
    }
    log_entry *entries = page->entries;
    unsigned count = 0;
    bool more = false;
    char path[672];
    DIR *dir = opendir(store->directory);
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir))) {
            struct stat st;
            if (valid_name(entry->d_name) && log_path(store, entry->d_name, path, sizeof(path)) &&
                !snapshot_stat(store, entry->d_name, path, &st) && S_ISREG(st.st_mode))
                insert_entry(entries, &count, &more, entry->d_name, st.st_size, after);
        }
        closedir(dir);
    }
    const char *legacy[] = {"stream_diag.log", "stream_diag_prev.log", "stream_diag_older.log"};
    for (unsigned i = 0; i < 3; ++i) {
        struct stat st;
        if (log_path(store, legacy[i], path, sizeof(path)) && !stat(path, &st) &&
            S_ISREG(st.st_mode))
            insert_entry(entries, &count, &more, legacy[i], st.st_size, after);
    }
    /* Names are restricted ASCII, including the active name, so need no JSON escaping. */
    char *body = page->body;
    size_t used = snprintf(body, sizeof(page->body),
                           "{\"version\":\"%s\",\"commit\":\"%s\",\"active\":\"%s\","
                           "\"storage_errno\":%d,\"log_dropped\":%u,\"files\":[",
                           NSL_APP_VERSION, NSL_GIT_COMMIT, store->active, store->storage_error,
                           sl_log_drop_count());
    for (unsigned i = 0; i < count; ++i)
        used += snprintf(body + used, sizeof(page->body) - used,
                         "%s{\"name\":\"%s\",\"bytes\":%llu,\"active\":%s}", i ? "," : "",
                         entries[i].name, (unsigned long long)entries[i].size,
                         !strcmp(entries[i].name, store->active) ? "true" : "false");
    snprintf(body + used, sizeof(page->body) - used, "],\"next_after\":\"%s\"}\n",
             more && count ? entries[count - 1].name : "");
    response(client, 200, "application/json", body);
    free(page);
}
static void request(log_store *store, http_client *client) {
    char method[16], target[256], protocol[16];
    if (sscanf(client->request, "%15s %255s %15s", method, target, protocol) != 3 ||
        strcmp(protocol, "HTTP/1.1") || strcmp(method, "GET")) {
        response(client, 400, "text/plain", "GET required\n");
        return;
    }
    if (!strcmp(target, "/") || !strcmp(target, "/logs")) {
        index_response(store, client, "");
        return;
    }
    if (!strncmp(target, "/logs?after=", 12)) {
        const char *after = target + 12;
        char path[672];
        if (log_path(store, after, path, sizeof(path)))
            index_response(store, client, after);
        else
            response(client, 400, "text/plain", "Invalid cursor\n");
        return;
    }
    char path[672];
    struct stat st;
    if (strncmp(target, "/logs/", 6) || !log_path(store, target + 6, path, sizeof(path)) ||
        snapshot_stat(store, target + 6, path, &st) || !S_ISREG(st.st_mode) || st.st_size < 0) {
        response(client, 404, "text/plain", "Log not found\n");
        return;
    }
    uint64_t first = 0, last = st.st_size ? (uint64_t)st.st_size - 1 : 0;
    bool ranged = false;
    for (char *line = strstr(client->request, "\r\n"); line && line[2];
         line = strstr(line + 2, "\r\n")) {
        if (strncasecmp(line + 2, "Range:", 6))
            continue;
        char trailing;
        if (ranged ||
            sscanf(line + 8, " bytes=%" SCNu64 "-%" SCNu64 "%c", &first, &last, &trailing) != 3 ||
            trailing != '\r' || !st.st_size || first > last || last >= (uint64_t)st.st_size) {
            response(client, 416, "text/plain", "Invalid range\n");
            return;
        }
        ranged = true;
    }
    bool active = store->file && !strcmp(target + 6, store->active);
    if (!active)
        client->file = fopen(path, "rb");
    if (first > LONG_MAX ||
        (!active && (!client->file || fseek(client->file, (long)first, SEEK_SET)))) {
        if (client->file)
            fclose(client->file);
        client->file = NULL;
        response(client, 500, "text/plain", "Cannot read log\n");
        return;
    }
    if (active)
        snprintf(client->active_snapshot, sizeof(client->active_snapshot), "%s", store->active);
    client->offset = first;
    client->remaining = st.st_size ? last - first + 1 : 0;
    char range[128] = {0};
    if (ranged)
        snprintf(range, sizeof(range), "Content-Range: bytes %llu-%llu/%llu\r\n",
                 (unsigned long long)first, (unsigned long long)last,
                 (unsigned long long)st.st_size);
    client->size =
        snprintf(client->output, sizeof(client->output),
                 "HTTP/1.1 %d OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
                 "Content-Length: %llu\r\n%sAccept-Ranges: bytes\r\nConnection: close\r\n"
                 "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n",
                 ranged ? 206 : 200, (unsigned long long)client->remaining, range);
    client->responding = true;
}
static size_t snapshot_read(log_store *store, http_client *client, size_t count) {
    if (!client->active_snapshot[0])
        return fread(client->output, 1, count, client->file);
    if (store->file && !strcmp(client->active_snapshot, store->active)) {
        /* The same worker serializes writes and bounded snapshot reads. Keep
         * the writer's append position, and never close its borrowed FILE. */
        fpos_t position;
        if (fgetpos(store->file, &position))
            return 0;
        size_t n = 0;
        if (client->offset <= LONG_MAX && !fseek(store->file, (long)client->offset, SEEK_SET))
            n = fread(client->output, 1, count, store->file);
        clearerr(store->file);
        if (fsetpos(store->file, &position)) {
            store->storage_error = errno ? errno : EIO;
            fclose(store->file);
            store->file = NULL;
            return 0;
        }
        client->offset += n;
        return n;
    }
    /* Rotation closed the writer for this snapshot; it is now a regular
     * immutable archive. Open it lazily and continue at the captured offset. */
    char path[672];
    if (!log_path(store, client->active_snapshot, path, sizeof(path)))
        return 0;
    client->file = fopen(path, "rb");
    if (!client->file || client->offset > LONG_MAX ||
        fseek(client->file, (long)client->offset, SEEK_SET))
        return 0;
    client->active_snapshot[0] = 0;
    return fread(client->output, 1, count, client->file);
}
static int listen_start(log_store *store) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        store->listen_error = errno;
        return -1;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    /* Diagnostics must not consume the stream's socket-buffer budget. */
    int rx = 4096, tx = 16384;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rx, sizeof(rx));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &tx, sizeof(tx));
    struct sockaddr_in addr = {.sin_family = AF_INET,
                               .sin_port = htons(NSL_DIAGNOSTIC_PORT),
                               .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (fcntl(fd, F_SETFL, O_NONBLOCK) || bind(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
        listen(fd, 4)) {
        store->listen_error = errno;
        close(fd);
        return -1;
    }
    socklen_t length = sizeof(addr);
    if (!getsockname(fd, (struct sockaddr *)&addr, &length))
        atomic_store(&http_port, ntohs(addr.sin_port));
    return fd;
}
static void http_step(int listener, log_store *store, http_client *client) {
    uint64_t now = sl_system_now();
    if (client->fd < 0 && listener >= 0 && now >= store->accept_after) {
        store->accept_after = now + 200;
        /* libnx 4.12.0 bsdAccept requires a non-NULL address length, even
         * when the nonblocking listener has no connection to accept. */
        struct sockaddr_storage peer;
        socklen_t peer_length = sizeof(peer);
        int fd = accept(listener, (struct sockaddr *)&peer, &peer_length);
        if (fd >= 0) {
            int rx = 4096, tx = 16384;
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rx, sizeof(rx));
            setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &tx, sizeof(tx));
            if (fcntl(fd, F_SETFL, O_NONBLOCK))
                close(fd);
            else {
                client->fd = fd;
                client->deadline = now + 10000;
            }
        }
    }
    if (client->fd < 0)
        return;
    if (now >= client->deadline) {
        client_close(client);
        return;
    }
    if (!client->responding) {
        ssize_t n = recv(client->fd, client->request + client->received,
                         sizeof(client->request) - client->received - 1, MSG_DONTWAIT);
        if (n > 0) {
            client->received += n;
            client->request[client->received] = 0;
            client->deadline = now + 10000;
            if (strstr(client->request, "\r\n\r\n"))
                request(store, client);
            else if (client->received == sizeof(client->request) - 1)
                client_close(client);
        } else if (!n || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
            client_close(client);
    }
    if (client->fd < 0 || !client->responding)
        return;
    if (client->sent == client->size) {
        if (!client->remaining) {
            client_close(client);
            return;
        }
        size_t count = client->remaining < 4096 ? client->remaining : 4096;
        client->size = snapshot_read(store, client, count);
        client->sent = 0;
        if (client->size != count) {
            client_close(client);
            return;
        }
        client->remaining -= count;
    }
    int flags = MSG_DONTWAIT;
#ifdef MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#endif
    ssize_t n = send(client->fd, client->output + client->sent, client->size - client->sent, flags);
    if (n > 0) {
        client->sent += n;
        client->deadline = now + 10000;
    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
        client_close(client);
}
static void *log_main(void *unused) {
    (void)unused;
    log_store store = {0};
    snprintf(store.root, sizeof(store.root), "%s", sl_system_data_dir());
    snprintf(store.directory, sizeof(store.directory), "%s/logs", store.root);
    mkdir(store.root, 0700);
    mkdir(store.directory, 0700);
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    snprintf(store.run, sizeof(store.run), "session-%020llu-%09u", (unsigned long long)now.tv_sec,
             (unsigned)now.tv_nsec);
    load_previous(&store);
    open_segment(&store);
    /* Keep buffers off libnx's pthread stack. One owner frees them after close. */
    http_client *client = calloc(1, sizeof(*client));
    if (client)
        client->fd = -1;
    else
        store.listen_error = ENOMEM;
    int listener = client ? listen_start(&store) : -1;
    char lifecycle[160];
    snprintf(lifecycle, sizeof(lifecycle),
             "diagnostic_service port=%u listen_errno=%d storage_errno=%d", sl_log_http_port(),
             store.listen_error, store.storage_error);
    write_line(&store, lifecycle);
    for (;;) {
        char message[224] = {0};
        pthread_mutex_lock(&lock);
        if (consumed != head)
            memcpy(message, queue[consumed++ % 128], sizeof(message));
        bool empty = consumed == head;
        if (message[0]) {
            size_t len = strlen(message);
            if (tail_size + len + 1 > TAIL_SIZE) {
                size_t trim = tail_size + len + 1 - TAIL_SIZE;
                memmove(tail, tail + trim, tail_size - trim);
                tail_size -= trim;
            }
            memcpy(tail + tail_size, message, len);
            tail_size += len;
            tail[tail_size++] = '\n';
            tail[tail_size] = 0;
        }
        pthread_mutex_unlock(&lock);
        if (message[0]) {
            sl_system_log(message);
            write_line(&store, message);
        }
        if (atomic_load(&stopping) && empty)
            break;
        if (client)
            http_step(listener, &store, client);
        if (!message[0])
            usleep(20000);
    }
    client_close(client);
    free(client);
    if (listener >= 0)
        close(listener);
    atomic_store(&http_port, 0);
    snprintf(lifecycle, sizeof(lifecycle), "diagnostic_end log_dropped=%u storage_errno=%d",
             sl_log_drop_count(), store.storage_error);
    write_line(&store, lifecycle);
    if (store.file)
        fclose(store.file);
    return NULL;
}
bool sl_log_start(void) {
    if (started)
        return true;
    if (pthread_mutex_init(&lock, NULL))
        return false;
    head = consumed = 0;
    tail_size = 0;
    tail[0] = previous_tail[0] = 0;
    atomic_store(&dropped, 0);
    atomic_store(&http_port, 0);
    atomic_store(&stopping, false);
    atomic_store(&ready, true);
    started = pthread_create(&worker, NULL, log_main, NULL) == 0;
    if (!started) {
        atomic_store(&ready, false);
        pthread_mutex_destroy(&lock);
    }
    return started;
}
void sl_log_finish(void) {
    if (!started)
        return;
    /* Application/session/media producers must already have stopped/joined. */
    atomic_store(&ready, false);
    atomic_store(&stopping, true);
    pthread_join(worker, NULL);
    started = false;
    pthread_mutex_destroy(&lock);
}
#else
bool sl_log_start(void) {
    return true;
}
void sl_log(const char *message) {
    (void)message;
}
void sl_log_finish(void) {
}
unsigned sl_log_drop_count(void) {
    return 0;
}
uint16_t sl_log_http_port(void) {
    return 0;
}
bool sl_log_copy_tail(char *out, size_t capacity, bool previous) {
    (void)out;
    (void)capacity;
    (void)previous;
    return false;
}
#endif
