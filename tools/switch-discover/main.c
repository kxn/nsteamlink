// M2 探针：在 Switch 上跑 IHSlib 主机发现，验证交叉编译产物在真机上可用。
// 输出双通道：本机屏幕（libnx console）+ nxlink 网络（开发机终端）。
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <switch.h> /* 聚合头，已含 runtime/nxlink.h */

#include <ihslib/client.h>
#include <ihslib/common.h>
#include <ihslib/net.h>

static int cons_fd = -1;
static volatile int host_count = 0;

/* 仅主线程调用：console + 网络双通道。libnx console 非线程安全。 */
static void logline(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (cons_fd >= 0) {
        dprintf(cons_fd, "%s\n", buf);
    }
    fputs(buf, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

/* IHSlib 回调线程调用：只 write() 到网络 fd，绕开 stdio 锁与 console 驱动。 */
static void logline_net(const char *fmt, ...) {
    char buf[600];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf - 1, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int) sizeof buf - 2) n = sizeof buf - 2;
    buf[n] = '\n';
    buf[n + 1] = '\0';
    if (write(STDOUT_FILENO, buf, n + 1) < 0) { /* 忽略 */ }
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
    nxlinkStdio(); /* nxlink -s 启动时把 stdout 转发回开发机；普通启动时无副作用 */

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

    logline("步骤4: 进入主循环");
    consoleUpdate(NULL);

    for (int i = 0; i < 60 * 30; i++) {
        if (i == 0) {
            logline("步骤5: 循环第 0 帧");
        }
        padUpdate(&pad);
        if (padGetButtonsDown(&pad) & HidNpadButton_Plus) {
            logline("用户按了 PLUS，退出");
            break;
        }
        if (i == 60 * 15) {
            logline("... 15 秒，继续等");
        }
        consoleUpdate(NULL);
        svcSleepThread(16 * 1000 * 1000);
    }

    if (host_count == 0) {
        logline("RESULT: 未发现主机（检查 Windows 侧 Steam 是否在运行）");
    } else {
        logline("RESULT: 共发现 %d 台主机 —— M2 发现链路验证成功", host_count);
    }

    IHS_ClientStop(client);
    IHS_ClientThreadedJoin(client);
    IHS_ClientStopDiscovery(client);
    IHS_ClientDestroy(client);

    logline("3 秒后退出");
    for (int i = 0; i < 180; i++) {
        consoleUpdate(NULL);
        svcSleepThread(16 * 1000 * 1000);
    }

    socketExit();
    appletReleaseSleepLock();
    consoleExit(NULL);
    return 0;
}
