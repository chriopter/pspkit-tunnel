#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "network/ca_certs.h"
#include "ts/conn.h"
#include "ts/plat.h"

#define HANDSHAKE_TIMEOUT_MS 20000
#define WRITE_TIMEOUT_MS 20000

struct conn {
    int fd;
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
};

/* The same IO callbacks as network/https.c, over the platform's sockets: a
   socket with nothing to give answers WANT_READ and the caller decides how
   long to keep asking, since retrying inside the callback never ends. */
static int io_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    int n = plat_tcp_recv(*(int *)ctx, buf, (size_t)sz);
    if (n > 0) return n;
    if (n == 0) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return n == PLAT_AGAIN ? WOLFSSL_CBIO_ERR_WANT_READ : WOLFSSL_CBIO_ERR_GENERAL;
}

static int io_send(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    int n = plat_tcp_send(*(int *)ctx, buf, (size_t)sz);
    if (n >= 0) return n;
    return n == PLAT_AGAIN ? WOLFSSL_CBIO_ERR_WANT_WRITE : WOLFSSL_CBIO_ERR_CONN_RST;
}

/* The console's clock is not to be trusted -- it is user-set and falls back
   to 2000 with a flat battery -- so a certificate's dates are the one check
   waived, as in network/https.c. Issuer, signature and name still count. */
/* A DERP server sends, after its real chain, a self-signed certificate
   named derpkey<its key in hex> -- how Go clients learn the key early. No
   one issued it and nothing has to: it is passed over, and only it. The
   chain in front of it is checked as any other. */
static int is_derp_meta(WOLFSSL_X509 *cert, int depth) {
    char cn[96];
    if (!cert || depth == 0) return 0;
    if (wolfSSL_X509_NAME_get_text_by_NID(wolfSSL_X509_get_subject_name(cert), NID_commonName,
                                          cn, sizeof(cn)) != 7 + 64) return 0;
    if (strncmp(cn, "derpkey", 7)) return 0;
    for (int i = 7; i < 7 + 64; i++)
        if (!((cn[i] >= '0' && cn[i] <= '9') || (cn[i] >= 'a' && cn[i] <= 'f'))) return 0;
    return wolfSSL_X509_NAME_cmp(wolfSSL_X509_get_subject_name(cert),
                                 wolfSSL_X509_get_issuer_name(cert)) == 0;
}

static int verify_ignoring_dates(int preverify, WOLFSSL_X509_STORE_CTX *store) {
    if (preverify) return 1;
    if (store->error == ASN_BEFORE_DATE_E || store->error == ASN_AFTER_DATE_E) return 1;
    WOLFSSL_X509 *cert = wolfSSL_X509_STORE_CTX_get_current_cert(store);
    if ((store->error == ASN_NO_SIGNER_E || store->error == ASN_SELF_SIGNED_E) &&
        is_derp_meta(cert, store->error_depth))
        return 1;
    char sub[96] = "?", iss[96] = "?";
    if (cert) {
        wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_subject_name(cert), sub, sizeof(sub));
        wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(cert), iss, sizeof(iss));
    }
    plat_log("tls: certificate error %d at depth %d: %s from %s", store->error, store->error_depth, sub, iss);
    return 0;
}

/* One context for every connection of the run: the roots are parsed once,
   which on a PSP is most of a handshake's cost. Only the tunnel's own
   thread opens connections, so nothing else touches it. */
static WOLFSSL_CTX *shared_ctx(void) {
    static WOLFSSL_CTX *ctx;
    if (ctx) return ctx;
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) return NULL;
    WOLFSSL_CTX *x = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!x) return NULL;
    wolfSSL_CTX_set_cipher_list(x, "TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES128-GCM-SHA256");
    if (wolfSSL_CTX_load_verify_buffer(x, (const unsigned char *)PSPDX_CA_PEM,
                                       (long)sizeof(PSPDX_CA_PEM) - 1,
                                       WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        plat_log("tls: CA bundle rejected");
        wolfSSL_CTX_free(x);
        return NULL;
    }
    wolfSSL_CTX_set_verify(x, WOLFSSL_VERIFY_PEER, verify_ignoring_dates);
    wolfSSL_CTX_SetIORecv(x, io_recv);
    wolfSSL_CTX_SetIOSend(x, io_send);
    ctx = x;
    return ctx;
}

static int tls_up(conn *c, const char *host) {
    c->ctx = shared_ctx();
    if (!c->ctx) return -1;
    c->ssl = wolfSSL_new(c->ctx);
    if (!c->ssl) return -1;
    wolfSSL_SetIOReadCtx(c->ssl, &c->fd);
    wolfSSL_SetIOWriteCtx(c->ssl, &c->fd);
    wolfSSL_UseSNI(c->ssl, WOLFSSL_SNI_HOST_NAME, host, (unsigned short)strlen(host));
    if (wolfSSL_check_domain_name(c->ssl, host) != WOLFSSL_SUCCESS) return -1;
    wolfSSL_UseKeyShare(c->ssl, WOLFSSL_ECC_X25519);

    uint32_t start = plat_ms();
    int rc;
    while ((rc = wolfSSL_connect(c->ssl)) != WOLFSSL_SUCCESS) {
        int e = wolfSSL_get_error(c->ssl, rc);
        if (e != WOLFSSL_ERROR_WANT_READ && e != WOLFSSL_ERROR_WANT_WRITE) {
            char msg[80];
            wolfSSL_ERR_error_string((unsigned long)e, msg);
            plat_log("tls: handshake with %s failed: %s", host, msg);
            return -1;
        }
        if (plat_ms() - start > HANDSHAKE_TIMEOUT_MS) {
            plat_log("tls: handshake with %s timed out", host);
            return -1;
        }
        plat_sleep_ms(1);
    }
    plat_log("tls: %s %s in %u ms", host, wolfSSL_get_cipher(c->ssl),
             (unsigned)(plat_ms() - start));
    return 0;
}

conn *conn_open(const char *host, uint16_t port, int tls) {
    uint32_t ip;
    if (plat_resolve(host, &ip) < 0) {
        plat_log("dns: %s did not resolve", host);
        return NULL;
    }
    conn *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->fd = plat_tcp_connect(ip, port);
    if (c->fd < 0) {
        plat_log("tcp: %s:%u refused or timed out", host, port);
        free(c);
        return NULL;
    }
    if (tls && tls_up(c, host) < 0) {
        conn_close(c);
        return NULL;
    }
    return c;
}

int conn_read(conn *c, void *buf, size_t len) {
    if (!c->ssl) {
        int n = plat_tcp_recv(c->fd, buf, len);
        if (n > 0) return n;
        return n == PLAT_AGAIN ? 0 : -1;
    }
    int rc = wolfSSL_read(c->ssl, buf, (int)len);
    if (rc > 0) return rc;
    int e = wolfSSL_get_error(c->ssl, rc);
    if (e == WOLFSSL_ERROR_WANT_READ || e == WOLFSSL_ERROR_WANT_WRITE) return 0;
    plat_log("tls: read error %d", e);
    return -1;
}

int conn_write(conn *c, const void *buf, size_t len) {
    const uint8_t *p = buf;
    uint32_t start = plat_ms();
    while (len > 0) {
        int n;
        if (c->ssl) {
            n = wolfSSL_write(c->ssl, p, (int)len);
            if (n <= 0) {
                int e = wolfSSL_get_error(c->ssl, n);
                if (e != WOLFSSL_ERROR_WANT_READ && e != WOLFSSL_ERROR_WANT_WRITE) return -1;
                n = 0;
            }
        } else {
            n = plat_tcp_send(c->fd, p, len);
            if (n == PLAT_ERR) return -1;
            if (n < 0) n = 0;
        }
        if (n > 0) {
            p += n;
            len -= (size_t)n;
            start = plat_ms();
            continue;
        }
        if (plat_ms() - start > WRITE_TIMEOUT_MS) return -1;
        plat_sleep_ms(1);
    }
    return 0;
}

void conn_close(conn *c) {
    if (!c) return;
    if (c->ssl) wolfSSL_free(c->ssl);
    if (c->fd >= 0) plat_tcp_close(c->fd);
    free(c);
}

int conn_read_head(conn *c, char *head, size_t head_max, unsigned timeout_ms) {
    size_t have = 0;
    uint32_t start = plat_ms();
    /* A byte at a time until the blank line, so that nothing past the head
       is taken off the stream: what follows a 101 is the next protocol's,
       and a TLS read that swallowed it would hide it from the caller. */
    for (;;) {
        if (have + 1 >= head_max) { plat_log("http: head too long"); return -1; }
        int n = conn_read(c, head + have, 1);
        if (n < 0) { plat_log("http: closed after %u bytes of head", (unsigned)have); return -1; }
        if (n == 0) {
            if (plat_ms() - start > timeout_ms) {
                plat_log("http: head timed out after %u bytes", (unsigned)have);
                return -1;
            }
            plat_sleep_ms(1);
            continue;
        }
        have++;
        if (have >= 4 && memcmp(head + have - 4, "\r\n\r\n", 4) == 0) break;
    }
    head[have] = '\0';
    int status = -1;
    if (sscanf(head, "HTTP/%*d.%*d %d", &status) != 1) {
        plat_log("http: no status in %.32s", head);
        return -1;
    }
    return status;
}
