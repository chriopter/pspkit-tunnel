/* GET through the tunnel, for measuring it: http:// straight over the
   tunnel's TCP, https:// with wolfSSL on top of that -- the PSP's case,
   where a source's own TLS runs inside WireGuard inside DERP's TLS. Blocks,
   pumping node_step while it waits, and reports bytes and time. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "ts/node.h"
#include "ts/plat.h"
#include "ts/tcp.h"

struct fetch_result {
    int status;
    long long body;
    uint32_t connect_ms, tls_ms, first_byte_ms, total_ms;
};

static struct node *g_n;
static uint32_t g_deadline;

static int pump(void) {
    node_step(g_n);
    if ((int32_t)(plat_ms() - g_deadline) > 0) return -1;
    return 0;
}

static int io_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    int r = tcp_tunnel_recv(*(int *)ctx, buf, (size_t)sz);
    if (r == PLAT_AGAIN) return WOLFSSL_CBIO_ERR_WANT_READ;
    if (r == 0) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    if (r < 0) return WOLFSSL_CBIO_ERR_GENERAL;
    return r;
}

static int io_send(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    int r = tcp_tunnel_send(*(int *)ctx, buf, (size_t)sz);
    if (r == PLAT_AGAIN) return WOLFSSL_CBIO_ERR_WANT_WRITE;
    if (r < 0) return WOLFSSL_CBIO_ERR_GENERAL;
    return r;
}

static int verify_ignoring_dates(int preverify, WOLFSSL_X509_STORE_CTX *store) {
    if (preverify) return 1;
    if (store->error == ASN_BEFORE_DATE_E || store->error == ASN_AFTER_DATE_E) return 1;
    plat_log("fetch: certificate error %d at depth %d", store->error, store->error_depth);
    return 0;
}

static void base64(char *out, const char *in) {
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t n = strlen(in), o = 0;
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = (unsigned char)in[i] << 16;
        if (i + 1 < n) v |= (unsigned char)in[i + 1] << 8;
        if (i + 2 < n) v |= (unsigned char)in[i + 2];
        out[o++] = t[v >> 18 & 63];
        out[o++] = t[v >> 12 & 63];
        out[o++] = i + 1 < n ? t[v >> 6 & 63] : '=';
        out[o++] = i + 2 < n ? t[v & 63] : '=';
    }
    out[o] = '\0';
}

/* Moves everything through either TLS or the bare handle. */
static int xsend(WOLFSSL *ssl, int h, const char *p, int len) {
    int off = 0;
    while (off < len) {
        int r = ssl ? wolfSSL_write(ssl, p + off, len - off) : tcp_tunnel_send(h, p + off, (size_t)(len - off));
        if (r > 0) { off += r; continue; }
        if (ssl ? wolfSSL_get_error(ssl, r) != WOLFSSL_ERROR_WANT_WRITE && wolfSSL_get_error(ssl, r) != WOLFSSL_ERROR_WANT_READ
                : r != PLAT_AGAIN) return -1;
        if (pump() < 0) return -1;
    }
    return 0;
}

static int xrecv(WOLFSSL *ssl, int h, char *p, int len) {
    for (;;) {
        int r = ssl ? wolfSSL_read(ssl, p, len) : tcp_tunnel_recv(h, p, (size_t)len);
        if (r > 0) return r;
        if (ssl) {
            int e = wolfSSL_get_error(ssl, r);
            if (e == WOLFSSL_ERROR_ZERO_RETURN || e == SOCKET_PEER_CLOSED_E) return 0;
            if (e != WOLFSSL_ERROR_WANT_READ && e != WOLFSSL_ERROR_WANT_WRITE) return -1;
        } else {
            if (r == 0) return 0;
            if (r != PLAT_AGAIN) return -1;
        }
        if (pump() < 0) return -1;
    }
}

int fetch(struct node *n, const char *url, const char *basic, unsigned timeout_s, struct fetch_result *res) {
    char host[128], path[512] = "/";
    int tls;
    unsigned port;
    memset(res, 0, sizeof(*res));
    g_n = n;
    g_deadline = plat_ms() + timeout_s * 1000;
    if (!strncmp(url, "https://", 8)) { tls = 1; port = 443; url += 8; }
    else if (!strncmp(url, "http://", 7)) { tls = 0; port = 80; url += 7; }
    else return -1;
    size_t hl = strcspn(url, ":/");
    if (!hl || hl >= sizeof(host)) return -1;
    memcpy(host, url, hl);
    host[hl] = '\0';
    url += hl;
    if (*url == ':') port = (unsigned)strtoul(url + 1, (char **)&url, 10);
    if (*url == '/') snprintf(path, sizeof(path), "%s", url);

    uint32_t ip;
    if (node_resolve(n, host, &ip) < 0) { plat_log("fetch: %s is not in the tailnet", host); return -1; }
    uint32_t t0 = plat_ms();
    int h = tcp_tunnel_open(ip, (uint16_t)port);
    if (h < 0) return -1;
    int rc = -1;
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    for (;;) {
        int r = tcp_tunnel_ready(h);
        if (r == 1) break;
        if (r == PLAT_ERR || pump() < 0) { plat_log("fetch: no connection to %s:%u", host, port); goto out; }
    }
    res->connect_ms = plat_ms() - t0;
    if (tls) {
        uint32_t t1 = plat_ms();
        ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
        plat_trust(ctx);
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, verify_ignoring_dates);
        wolfSSL_CTX_SetIORecv(ctx, io_recv);
        wolfSSL_CTX_SetIOSend(ctx, io_send);
        ssl = wolfSSL_new(ctx);
        wolfSSL_SetIOReadCtx(ssl, &h);
        wolfSSL_SetIOWriteCtx(ssl, &h);
        wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host, (unsigned short)strlen(host));
        wolfSSL_check_domain_name(ssl, host);
        for (;;) {
            int r = wolfSSL_connect(ssl);
            if (r == WOLFSSL_SUCCESS) break;
            int e = wolfSSL_get_error(ssl, r);
            if (e != WOLFSSL_ERROR_WANT_READ && e != WOLFSSL_ERROR_WANT_WRITE) {
                char msg[80];
                plat_log("fetch: tls with %s failed: %s", host, wolfSSL_ERR_error_string((unsigned long)e, msg));
                goto out;
            }
            if (pump() < 0) { plat_log("fetch: tls with %s timed out", host); goto out; }
        }
        res->tls_ms = plat_ms() - t1;
    }
    char req[1024], auth[300] = "";
    if (basic && *basic) {
        char b64[200];
        base64(b64, basic);
        snprintf(auth, sizeof(auth), "Authorization: Basic %s\r\n", b64);
    }
    int rl = snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: %s\r\n%sUser-Agent: pspkit-tunnel-test\r\n"
                      "Connection: close\r\n\r\n", path, host, auth);
    if (xsend(ssl, h, req, rl) < 0) goto out;
    static char buf[16384];
    char head[4096];
    int hlen = 0, in_body = 0;
    long long total = 0;
    for (;;) {
        int r = xrecv(ssl, h, buf, sizeof(buf));
        if (r < 0) { plat_log("fetch: read failed after %lld bytes", res->body); goto out; }
        if (r == 0) break;
        if (!res->first_byte_ms) res->first_byte_ms = plat_ms() - t0;
        total += r;
        if (in_body) { res->body += r; continue; }
        int take = r < (int)sizeof(head) - 1 - hlen ? r : (int)sizeof(head) - 1 - hlen;
        memcpy(head + hlen, buf, (size_t)take);
        hlen += take;
        head[hlen] = '\0';
        char *end = strstr(head, "\r\n\r\n");
        if (end) {
            in_body = 1;
            sscanf(head, "HTTP/1.%*d %d", &res->status);
            res->body = total - (end + 4 - head);
        }
    }
    res->total_ms = plat_ms() - t0;
    rc = 0;
out:
    if (ssl) wolfSSL_free(ssl);
    if (ctx) wolfSSL_CTX_free(ctx);
    tcp_tunnel_close(h);
    return rc;
}
