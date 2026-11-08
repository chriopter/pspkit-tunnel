/* The platform layer on the console: sceNetInet under the protocol code. The
   radio belongs to the application (pspkit-https brings it up); this only
   opens sockets on it. Three traps, the same pspkit-https documents: the BSD
   wrappers report failure as a negative size_t, sceNetInetSelect hangs, and
   the option names for non-blocking sockets are not in the headers.

   Waiting is therefore a short sleep, a connect is retried until it answers
   EISCONN, and every socket is non-blocking by the numbers the firmware
   uses, since one blocking recv would stop the whole tunnel. */

#include <pspkernel.h>
#include <pspiofilemgr.h>
#include <psprtc.h>
#include <pspnet.h>
#include <pspnet_apctl.h>
#include <pspnet_inet.h>
#include <pspnet_resolver.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>

#include "psp/plat_psp.h"
#include "ts/plat.h"

/* Not in the headers: the firmware's own numbers for the socket level and
   the non-blocking flag. */
#define PSP_SOL_SOCKET 0xffff
#define PSP_SO_NONBLOCK 0x1009

#define CONNECT_TIMEOUT_MS 10000

static char g_dir[192] = "ms0:/PSP/TUNNEL";
static void (*g_log)(const char *text);

void plat_psp_set_dir(const char *dir) { snprintf(g_dir, sizeof(g_dir), "%s", dir); }
void plat_psp_set_log(void (*line)(const char *text)) { g_log = line; }

/* Counted from the first call, not from the console's epoch: the tick is an
   absolute microsecond count, and the milliseconds of it overflow a signed
   32-bit difference -- which is how every timer in the client is compared. */
uint32_t plat_ms(void) {
    static u64 base;
    u64 tick = 0;
    sceRtcGetCurrentTick(&tick);
    if (!base) base = tick;
    return (uint32_t)((tick - base) / 1000);
}

uint64_t plat_unix_ms(void) {
    /* The console's clock, wrong on a console whose battery has died, which
       WireGuard tolerates: its timestamps only have to rise. */
    return (uint64_t)time(NULL) * 1000;
}

/* tunnel.c's: a wait on the tunnel's own thread lets the lock go. */
static void (*g_wait)(unsigned ms);
void plat_psp_set_wait(void (*wait)(unsigned ms)) { g_wait = wait; }

void plat_sleep_ms(unsigned ms) {
    if (g_wait) g_wait(ms);
    else sceKernelDelayThread(ms * 1000);
}

/* wolfSSL's DRBG, seeded the way every TLS session of the application is:
   from pspkit-https's entropy pool. There is no weaker fallback -- a key
   from a predictable source would be worse than no tunnel -- so a failure
   is reported and plat_random_ok says so before any key is made. */
static WC_RNG g_rng;
static int g_rng_ready = -1;

int plat_random_ok(void) {
    if (g_rng_ready < 0) g_rng_ready = wc_InitRng(&g_rng) == 0;
    return g_rng_ready;
}

void plat_random(void *out, size_t len) {
    if (!plat_random_ok() || wc_RNG_GenerateBlock(&g_rng, out, (word32)len) != 0) {
        plat_log("tunnel: no randomness");
        memset(out, 0, len);
    }
}

void plat_log(const char *fmt, ...) {
    char line[160];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (g_log) g_log(line);
}

static void state_path(char *out, size_t max, const char *name) {
    snprintf(out, max, "%s/%s", g_dir, name);
}

int plat_load(const char *name, void *buf, size_t max) {
    char path[256];
    state_path(path, sizeof(path), name);
    int fd = sceIoOpen(path, PSP_O_RDONLY, 0777);
    if (fd < 0) return -1;
    int n = sceIoRead(fd, buf, (SceSize)max);
    sceIoClose(fd);
    return n;
}

/* The directory and every one above it: a test's ms0:/PSP/TUNNELTEST/hw/00
   has none of them yet. */
static void make_dirs(const char *dir) {
    char p[192];
    snprintf(p, sizeof(p), "%s", dir);
    for (char *c = strchr(p, '/'); c; c = strchr(c + 1, '/')) {
        if (c > p && c[-1] == ':') continue;            /* ms0:/ */
        *c = '\0';
        sceIoMkdir(p, 0777);
        *c = '/';
    }
    sceIoMkdir(p, 0777);
}

int plat_save(const char *name, const void *buf, size_t len) {
    char path[256], tmp[260];
    make_dirs(g_dir);
    state_path(path, sizeof(path), name);
    snprintf(tmp, sizeof(tmp), "%s.new", path);
    int fd = sceIoOpen(tmp, PSP_O_WRONLY | PSP_O_CREAT | PSP_O_TRUNC, 0777);
    if (fd < 0) return -1;
    int n = sceIoWrite(fd, buf, (SceSize)len);
    sceIoClose(fd);
    if (n != (int)len) { sceIoRemove(tmp); return -1; }
    sceIoRemove(path);
    return sceIoRename(tmp, path) < 0 ? -1 : 0;
}

int plat_remove(const char *name) {
    char path[256];
    state_path(path, sizeof(path), name);
    return sceIoRemove(path) < 0 && plat_exists(name) ? -1 : 0;
}

int plat_exists(const char *name) {
    char path[256];
    SceIoStat st;
    state_path(path, sizeof(path), name);
    return sceIoGetstat(path, &st) >= 0;
}

/* ------------------------------------------------------------------- net */

int plat_resolve(const char *host, uint32_t *ip) {
    struct in_addr addr;
    if (inet_aton(host, &addr)) {                  /* a literal needs no resolver */
        *ip = ntohl(addr.s_addr);
        return 0;
    }
    char buf[1024];
    int rid = -1;
    if (sceNetResolverCreate(&rid, buf, sizeof(buf)) < 0) return -1;
    int rc = sceNetResolverStartNtoA(rid, host, &addr, 2 * 1000 * 1000, 5);
    sceNetResolverDelete(rid);
    if (rc < 0) return -1;
    *ip = ntohl(addr.s_addr);
    return 0;
}

uint32_t plat_local_ip(void) {
    union SceNetApctlInfo info;
    if (sceNetApctlGetInfo(PSP_NET_APCTL_INFO_IP, &info) < 0) return 0;
    struct in_addr addr;
    if (!inet_aton(info.ip, &addr)) return 0;
    return ntohl(addr.s_addr);
}

/* A socket that stayed blocking would hold the whole tunnel in one recv,
   so one that cannot be made non-blocking is not used at all. */
static int set_nonblocking(int fd) {
    int one = 1;
    return sceNetInetSetsockopt(fd, PSP_SOL_SOCKET, PSP_SO_NONBLOCK, &one, sizeof(one)) < 0 ? -1 : 0;
}

int plat_tcp_connect(uint32_t ip, uint16_t port) {
    int fd = sceNetInetSocket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (set_nonblocking(fd) < 0) { sceNetInetClose(fd); return -1; }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(ip);
    uint32_t start = plat_ms();
    if (sceNetInetConnect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        int e = sceNetInetGetErrno();
        if (e != EINPROGRESS && e != EALREADY && e != EWOULDBLOCK) {
            sceNetInetClose(fd);
            return -1;
        }
        /* With no SO_ERROR and no usable select, asking again is how the
           stack is made to say whether the connection stands. */
        for (;;) {
            plat_sleep_ms(20);
            if (sceNetInetConnect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) break;
            e = sceNetInetGetErrno();
            if (e == EISCONN) break;
            if (e != EINPROGRESS && e != EALREADY && e != EWOULDBLOCK) {
                sceNetInetClose(fd);
                return -1;
            }
            if (plat_ms() - start > CONNECT_TIMEOUT_MS) {
                sceNetInetClose(fd);
                return -1;
            }
        }
    }
    return fd;
}

/* The wrappers are declared as returning size_t and report failure as a
   negative value, so every call goes through this cast. */
int plat_tcp_send(int fd, const void *buf, size_t len) {
    int n = (int)sceNetInetSend(fd, buf, len, 0);
    if (n >= 0) return n;
    int e = sceNetInetGetErrno();
    return e == EAGAIN || e == EWOULDBLOCK || e == EINTR ? PLAT_AGAIN : PLAT_ERR;
}

int plat_tcp_recv(int fd, void *buf, size_t len) {
    int n = (int)sceNetInetRecv(fd, buf, len, 0);
    if (n >= 0) return n;
    int e = sceNetInetGetErrno();
    return e == EAGAIN || e == EWOULDBLOCK || e == EINTR ? PLAT_AGAIN : PLAT_ERR;
}

void plat_tcp_close(int fd) { sceNetInetClose(fd); }

int plat_udp_open(uint16_t port, uint16_t *bound) {
    int fd = sceNetInetSocket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    if (set_nonblocking(fd) < 0) { sceNetInetClose(fd); return -1; }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (sceNetInetBind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        sceNetInetClose(fd);
        return -1;
    }
    /* getsockname is in the same family of wrappers as the rest and is only
       needed when the port was left to the stack. */
    *bound = port;
    if (!port) {
        socklen_t len = sizeof(sa);
        if (sceNetInetGetsockname(fd, (struct sockaddr *)&sa, &len) == 0)
            *bound = ntohs(sa.sin_port);
    }
    return fd;
}

int plat_udp_send(int fd, uint32_t ip, uint16_t port, const void *buf, size_t len) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(ip);
    int n = (int)sceNetInetSendto(fd, buf, len, 0, (struct sockaddr *)&sa, sizeof(sa));
    if (n >= 0) return n;
    int e = sceNetInetGetErrno();
    return e == EAGAIN || e == EWOULDBLOCK || e == EINTR ? PLAT_AGAIN : PLAT_ERR;
}

int plat_udp_recv(int fd, void *buf, size_t len, uint32_t *ip, uint16_t *port) {
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    memset(&sa, 0, sizeof(sa));
    int n = (int)sceNetInetRecvfrom(fd, buf, len, 0, (struct sockaddr *)&sa, &sl);
    if (n >= 0) {
        *ip = ntohl(sa.sin_addr.s_addr);
        *port = ntohs(sa.sin_port);
        return n;
    }
    int e = sceNetInetGetErrno();
    return e == EAGAIN || e == EWOULDBLOCK || e == EINTR ? 0 : PLAT_ERR;
}

void plat_udp_close(int fd) { sceNetInetClose(fd); }
