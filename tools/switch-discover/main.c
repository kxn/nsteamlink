// M2 探针：在 Switch 上跑 IHSlib 主机发现，验证交叉编译产物在真机上可用。
// 输出双通道：本机屏幕（libnx console）+ nxlink 网络（开发机终端）。
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <switch.h> /* 聚合头，已含 runtime/nxlink.h */

#include <ihslib/client.h>
#include <ihslib/common.h>
#include <ihslib/net.h>

/* IHSlib 内部件（探针专用直连诊断，正式客户端会做正式抽象） */
#include "client_pri.h"
#include "discovery.pb-c.h"
#include "pb_utils.h"

static int cons_fd = -1;
static bool nxlink_active = false;
static volatile int host_count = 0;

/* 回调线程 → 主线程 的日志队列：libnx console 单写者（主线程） */
#define LOGQ_LEN 16
#define LOGQ_MSG 160
static char logq[LOGQ_LEN][LOGQ_MSG];
static int logq_head = 0, logq_tail = 0;
static pthread_mutex_t logq_lock = PTHREAD_MUTEX_INITIALIZER;

/* 仅主线程调用：console（+ nxlink 网络若激活）。 */
static void logline(const char *fmt, ...) {
    char buf[LOGQ_MSG];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (cons_fd >= 0) {
        dprintf(cons_fd, "%s\n", buf);
    }
    if (nxlink_active) {
        fputs(buf, stdout);
        fputc('\n', stdout);
        fflush(stdout);
    }
}

/* IHSlib 回调线程调用：只入队，不碰任何 IO。主循环里 drain。 */
static void logline_net(const char *fmt, ...) {
    pthread_mutex_lock(&logq_lock);
    char *slot = logq[logq_head];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(slot, LOGQ_MSG, fmt, ap);
    va_end(ap);
    logq_head = (logq_head + 1) % LOGQ_LEN;
    if (logq_head == logq_tail) logq_tail = (logq_tail + 1) % LOGQ_LEN; /* 满则丢最旧 */
    pthread_mutex_unlock(&logq_lock);
}

/* 仅主线程调用：把队列中的回调日志打到屏幕/网络。 */
static void logq_drain(void) {
    for (;;) {
        pthread_mutex_lock(&logq_lock);
        if (logq_head == logq_tail) {
            pthread_mutex_unlock(&logq_lock);
            return;
        }
        char local[LOGQ_MSG];
        strncpy(local, logq[logq_tail], LOGQ_MSG);
        logq_tail = (logq_tail + 1) % LOGQ_LEN;
        pthread_mutex_unlock(&logq_lock);
        if (cons_fd >= 0) {
            dprintf(cons_fd, "%s\n", local);
        }
        if (nxlink_active) {
            fputs(local, stdout);
            fputc('\n', stdout);
            fflush(stdout);
        }
    }
}

static void ihs_log(IHS_LogLevel level, const char *tag, const char *message) {
    logline_net("[IHS:%d][%s] %s", (int) level, tag, message);
}

static void on_discovered(IHS_Client *client, const IHS_HostInfo *host, void *context) {
    (void) client;
    (void) context;
    char *ip = IHS_IPAddressToString(&host->address.ip);
    logline_net(">>> 发现主机: %s (%s) gamesRunning=%d", host->hostname, ip ? ip : "?", (int) host->gamesRunning);
    free(ip);
    host_count++;
}

int main(int argc, char **argv) {
    (void) argc;
    (void) argv;

    consoleInit(NULL);
    cons_fd = dup(1);
    appletRequestToAcquireSleepLock(); /* 运行期间禁止休眠（applet 模式失败也无妨） */

    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    PadState pad;
    padInitializeDefault(&pad);

    if (R_FAILED(socketInitializeDefault())) {
        logline("socketInitialize 失败");
        consoleExit(NULL);
        return 1;
    }
    nxlink_active = (nxlinkStdio() >= 0); /* nxlink -s 启动时把 stdout 转发回开发机 */

    logline("nsteamlink M2 主机发现探针");
    logline("网络就绪，开始发现（30 秒，按 PLUS 退出）");

    IHS_Init(); /* 必须：创建任何 IHS 客户端前做全局初始化（plume main.c 同款顺序） */

    uint8_t secret[32] = {0};
    IHS_ClientConfig config = {
        .deviceId = 0x53574E5357590053ULL,
        .secretKey = secret,
        .deviceName = "nsteamlink-switch",
    };
    IHS_Client *client = IHS_ClientCreate(&config);
    logline("步骤1: IHS_ClientCreate -> %p", (void *) client);
    if (client == NULL) {
        socketExit();
        consoleExit(NULL);
        return 1;
    }
    IHS_ClientSetLogFunction(client, ihs_log);
    static const IHS_ClientDiscoveryCallbacks callbacks = {
        .discovered = on_discovered,
    };
    IHS_ClientSetDiscoveryCallbacks(client, &callbacks, NULL);
    logline("步骤2: 回调注册完成");

    bool started = IHS_ClientStartDiscovery(client, 500);
    logline("步骤3: StartDiscovery -> %d", (int) started);

    /* 诊断 A：裸 socket 广播能力（区分 libnx 发送失败 vs 路由器丢弃） */
    {
        int dfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (dfd >= 0) {
            int on = 1;
            setsockopt(dfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof on);
            struct sockaddr_in dst;
            memset(&dst, 0, sizeof dst);
            dst.sin_family = AF_INET;
            dst.sin_port = htons(27036);
            dst.sin_addr.s_addr = htonl(INADDR_BROADCAST);
            ssize_t r1 = sendto(dfd, "T", 1, 0, (struct sockaddr *) &dst, sizeof dst);
            logline("诊断: sendto(255.255.255.255) ret=%d errno=%d", (int) r1, r1 < 0 ? errno : 0);
            dst.sin_addr.s_addr = inet_addr("10.10.10.255");
            ssize_t r2 = sendto(dfd, "T", 1, 0, (struct sockaddr *) &dst, sizeof dst);
            logline("诊断: sendto(10.10.10.255)  ret=%d errno=%d", (int) r2, r2 < 0 ? errno : 0);
            close(dfd);
        } else {
            logline("诊断: 诊断 socket 创建失败 errno=%d", errno);
        }
    }

    /* 诊断 B：向 kxn-pc 单播真正的发现请求（绕过广播，kickoff §7.4 路线） */
    static const IHS_SocketAddress kxn_pc = {
        .ip = {.v4 = {IHS_IPAddressFamilyIPv4, {10, 10, 10, 166}}},
        .port = 27036,
    };
    uint32_t unicast_seq = 0;

    logline("步骤4: 进入主循环");
    consoleUpdate(NULL);

    for (int i = 0; i < 60 * 30; i++) {
        if (i == 0) {
            logline("步骤5: 循环第 0 帧");
        }
        if (i % 120 == 0) { /* 每 2 秒向 kxn-pc 重发一次单播发现 */
            CMsgRemoteClientBroadcastDiscovery msg = CMSG_REMOTE_CLIENT_BROADCAST_DISCOVERY__INIT;
            PROTOBUF_C_SET_VALUE(msg, seq_num, ++unicast_seq);
            bool sent = IHS_ClientSend(client, kxn_pc, k_ERemoteClientBroadcastMsgDiscovery,
                                       (ProtobufCMessage *) &msg);
            if (i == 0) {
                logline("单播发现请求已发往 10.10.10.166:27036 (ret=%d)", (int) sent);
            }
        }
        padUpdate(&pad);
        if (padGetButtonsDown(&pad) & HidNpadButton_Plus) {
            logline("用户按了 PLUS，退出");
            break;
        }
        if (i == 60 * 15) {
            logline("... 15 秒，继续等");
        }
        logq_drain();
        consoleUpdate(NULL);
        svcSleepThread(16 * 1000 * 1000);
    }

    if (host_count == 0) {
        logline("RESULT: 未发现主机（检查 Windows 侧 Steam 是否在运行）");
    } else {
        logline("RESULT: 共发现 %d 台主机 —— M2 发现链路验证成功", host_count);
    }

    logq_drain();
    IHS_ClientStop(client);
    IHS_ClientThreadedJoin(client);
    IHS_ClientStopDiscovery(client);
    IHS_ClientDestroy(client);

    logline("3 秒后退出");
    for (int i = 0; i < 180; i++) {
        logq_drain();
        consoleUpdate(NULL);
        svcSleepThread(16 * 1000 * 1000);
    }

    socketExit();
    appletReleaseSleepLock();
    consoleExit(NULL);
    return 0;
}
