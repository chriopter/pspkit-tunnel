/* The platform layer on Linux: the same contract plat_psp.c keeps, over BSD
   sockets, so the protocol code can be run and debugged on the desk. */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "ts/plat.h"

const char *plat_state_dir = ".";

uint32_t plat_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint32_t)(t.tv_sec * 1000 + t.tv_nsec / 1000000);
}

uint64_t plat_unix_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}

void plat_sleep_ms(unsigned ms) { usleep(ms * 1000); }

void plat_random(void *out, size_t len) {
    uint8_t *p = out;
    while (len) {
        ssize_t n = getrandom(p, len, 0);
        if (n <= 0) continue;
        p += n;
        len -= (size_t)n;
    }
}

void plat_log(const char *fmt, ...) {
    static uint32_t t0;
    if (!t0) t0 = plat_ms();
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[%7.3f] ", (plat_ms() - t0) / 1000.0);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static void path(char *out, size_t max, const char *name) {
    snprintf(out, max, "%s/%s", plat_state_dir, name);
}

int plat_load(const char *name, void *buf, size_t max) {
    char p[512];
    path(p, sizeof(p), name);
    FILE *f = fopen(p, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, max, f);
    fclose(f);
    return (int)n;
}

int plat_save(const char *name, const void *buf, size_t len) {
    char p[512];
    path(p, sizeof(p), name);
    FILE *f = fopen(p, "wb");
    if (!f) return -1;
    size_t n = fwrite(buf, 1, len, f);
    return fclose(f) == 0 && n == len ? 0 : -1;
}

int plat_resolve(const char *host, uint32_t *ip) {
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM }, *res;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) return -1;
    *ip = ntohl(((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr);
    freeaddrinfo(res);
    return 0;
}

/* Which address the host would use to reach the internet: a connected UDP
   socket knows without a packet being sent. */
uint32_t plat_local_ip(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(9) };
    sa.sin_addr.s_addr = htonl(0xc0000201);             /* 192.0.2.1, TEST-NET */
    uint32_t ip = 0;
    if (fd >= 0 && connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
        socklen_t len = sizeof(sa);
        if (getsockname(fd, (struct sockaddr *)&sa, &len) == 0) ip = ntohl(sa.sin_addr.s_addr);
    }
    if (fd >= 0) close(fd);
    return ip;
}

static void nonblocking(int fd) { fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK); }

int plat_tcp_connect(uint32_t ip, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    nonblocking(fd);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) };
    sa.sin_addr.s_addr = htonl(ip);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    int err = 0;
    socklen_t len = sizeof(err);
    if (poll(&pfd, 1, 10000) != 1 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err) {
        close(fd);
        return -1;
    }
    return fd;
}

static int result(ssize_t n) {
    if (n >= 0) return (int)n;
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? PLAT_AGAIN : PLAT_ERR;
}

int plat_tcp_send(int fd, const void *buf, size_t len) { return result(send(fd, buf, len, MSG_NOSIGNAL)); }
int plat_tcp_recv(int fd, void *buf, size_t len) { return result(recv(fd, buf, len, 0)); }
void plat_tcp_close(int fd) { close(fd); }

int plat_udp_open(uint16_t port, uint16_t *bound) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) };
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    socklen_t len = sizeof(sa);
    getsockname(fd, (struct sockaddr *)&sa, &len);
    *bound = ntohs(sa.sin_port);
    nonblocking(fd);
    return fd;
}

int plat_udp_send(int fd, uint32_t ip, uint16_t port, const void *buf, size_t len) {
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) };
    sa.sin_addr.s_addr = htonl(ip);
    return result(sendto(fd, buf, len, 0, (struct sockaddr *)&sa, sizeof(sa)));
}

int plat_udp_recv(int fd, void *buf, size_t len, uint32_t *ip, uint16_t *port) {
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    ssize_t n = recvfrom(fd, buf, len, 0, (struct sockaddr *)&sa, &sl);
    if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : PLAT_ERR;
    *ip = ntohl(sa.sin_addr.s_addr);
    *port = ntohs(sa.sin_port);
    return (int)n;
}

void plat_udp_close(int fd) { close(fd); }

/* The system's roots, as anything else on the desk trusts them; under
   dev/testnet the throwaway CA its testca.h carries, and nothing else. */
int plat_trust(void *wolfssl_ctx) {
#ifdef TUNNEL_TEST_CA_PEM
    return wolfSSL_CTX_load_verify_buffer(wolfssl_ctx, (const unsigned char *)TUNNEL_TEST_CA_PEM,
                                          (long)sizeof(TUNNEL_TEST_CA_PEM) - 1,
                                          WOLFSSL_FILETYPE_PEM) == WOLFSSL_SUCCESS;
#else
    static const char *const bundles[] = {
        "/etc/ssl/certs/ca-certificates.crt",   /* Debian, Arch */
        "/etc/pki/tls/certs/ca-bundle.crt",     /* Fedora */
    };
    for (size_t i = 0; i < sizeof(bundles) / sizeof(bundles[0]); i++)
        if (wolfSSL_CTX_load_verify_locations(wolfssl_ctx, bundles[i], NULL) == WOLFSSL_SUCCESS)
            return 1;
    plat_log("tls: no system roots found");
    return 0;
#endif
}
