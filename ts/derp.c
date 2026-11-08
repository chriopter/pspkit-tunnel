/*
 * DERP: Tailscale's relays, for every peer we cannot reach directly -- and
 * from behind a home router's NAT, before disco has found a way through,
 * that is every peer. One TLS connection per region we talk to:
 *
 *   GET /derp, Upgrade: DERP; 101; then frames, a type byte and a
 *   big-endian length. The server opens with its key, we answer with ours
 *   and a NaCl box of JSON sealed to it, and after that it is packets:
 *   SendPacket carries a destination node key and a datagram, RecvPacket a
 *   source key and one.
 *
 * A peer is reached through its home region, and reaches us through ours;
 * the home connection says so with NotePreferred. The others are opened
 * when a packet has to go there and closed when they fall quiet.
 *
 * Reference: tailscale.com/derp/derp.go, derp_client.go, derphttp.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ts/crypto.h"
#include "ts/node.h"
#include "ts/plat.h"

enum {
    FRAME_SERVER_KEY = 0x01, FRAME_CLIENT_INFO = 0x02, FRAME_SERVER_INFO = 0x03,
    FRAME_SEND_PACKET = 0x04, FRAME_RECV_PACKET = 0x05, FRAME_KEEP_ALIVE = 0x06,
    FRAME_NOTE_PREFERRED = 0x07, FRAME_PEER_GONE = 0x08, FRAME_PING = 0x12,
    FRAME_PONG = 0x13, FRAME_HEALTH = 0x14, FRAME_RESTARTING = 0x15,
};

#define MAGIC "DERP\xf0\x9f\x94\x91"
#define FRAME_MAX (64 * 1024 + 64)
#define IDLE_CLOSE_MS 60000
#define RETRY_MS 5000
#define SILENCE_MS 130000        /* the server keeps alive every 60 s */

struct derp_conn {
    int region;
    conn *c;
    uint8_t server_key[32];
    uint8_t *in;
    size_t in_len;
    uint32_t last_rx, last_tx;
    int sending;                /* a frame half written, its writer waiting */
    int broken;                 /* a write failed part-way: closed by derp_poll */
};

static uint32_t g_retry_at;

static void write_header(uint8_t *h, uint8_t type, uint32_t len) {
    h[0] = type;
    h[1] = (uint8_t)(len >> 24); h[2] = (uint8_t)(len >> 16);
    h[3] = (uint8_t)(len >> 8);  h[4] = (uint8_t)len;
}

/* One frame, one write: header and both parts in a single TLS record
   rather than three. A frame another thread is still writing -- its writer
   waiting for room, with the tunnel's lock let go -- is not interleaved
   with: this one is dropped, as a full link drops, and what it carried is
   sent again by whoever needs it to arrive. */
static int send_frame(struct derp_conn *d, uint8_t type, const void *a, size_t alen,
                      const void *b, size_t blen) {
    if (d->broken) return -1;
    if (d->sending) return 0;
    uint8_t stack[5 + 32 + MTU + 64], *f = stack;
    size_t len = 5 + alen + blen;
    if (len > sizeof(stack) && !(f = malloc(len))) return 0;
    write_header(f, type, (uint32_t)(alen + blen));
    if (alen) memcpy(f + 5, a, alen);
    if (blen) memcpy(f + 5 + alen, b, blen);
    d->sending = 1;
    int rc = conn_write(d->c, f, len);
    d->sending = 0;
    if (f != stack) free(f);
    if (rc < 0) {
        /* Part of a frame may be out, or wolfSSL may hold a record it was
           not allowed to finish: nothing more can follow on this one. */
        d->broken = 1;
        return -1;
    }
    d->last_tx = plat_ms();
    return 0;
}

static void derp_close(struct node *n, int slot) {
    struct derp_conn *d = n->derp[slot];
    if (!d) return;
    conn_close(d->c);
    free(d->in);
    free(d);
    n->derp[slot] = NULL;
}

void derp_stop(struct node *n) {
    for (int i = 0; i < MAX_DERP_CONNS; i++) derp_close(n, i);
    g_retry_at = 0;
}

/* Reads until one whole frame is buffered or the timeout passes: only the
   greeting waits like this, everything after it is read as it comes. */
static int read_frame_blocking(struct derp_conn *d, unsigned timeout_ms) {
    uint32_t start = plat_ms();
    for (;;) {
        if (d->in_len >= 5) {
            uint32_t len = (uint32_t)d->in[1] << 24 | (uint32_t)d->in[2] << 16 |
                           (uint32_t)d->in[3] << 8 | d->in[4];
            if (len > FRAME_MAX - 5) return -1;
            if (d->in_len >= 5 + len) return 0;
        }
        int got = conn_read(d->c, d->in + d->in_len, FRAME_MAX - d->in_len);
        if (got < 0) return -1;
        if (got == 0) {
            if (plat_ms() - start > timeout_ms) return -1;
            plat_sleep_ms(2);
            continue;
        }
        d->in_len += (size_t)got;
    }
}

static struct derp_conn *derp_open(struct node *n, int region) {
    const struct region *r = region_by_id(n, region);
    if (!r) return NULL;
    int slot = -1;
    for (int i = 0; i < MAX_DERP_CONNS; i++)
        if (!n->derp[i]) { slot = i; break; }
    /* Full: nothing is evicted here, since this can run from inside a
       receive on the very connection that would go; the idle ones close
       themselves within a minute. */
    if (slot < 0) {
        plat_log("derp: no room for region %d", region);
        return NULL;
    }

    struct derp_conn *d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    d->region = region;
    d->in = malloc(FRAME_MAX);
    plat_log("derp: connecting to region %d (%s:%u)", region, r->host, r->port);
    d->c = d->in ? conn_open(r->host, r->port, 1) : NULL;
    if (!d->c) goto fail;

    char req[256], head[1024];
    int len = snprintf(req, sizeof(req),
                       "GET /derp HTTP/1.1\r\nHost: %s\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n",
                       r->host);
    int status = conn_write(d->c, req, (size_t)len) < 0 ? -1
               : conn_read_head(d->c, head, sizeof(head), 10000);
    if (status != 101) {
        plat_log("derp: region %d answered %d", region, status);
        goto fail;
    }
    if (read_frame_blocking(d, 10000) < 0 || d->in[0] != FRAME_SERVER_KEY ||
        memcmp(d->in + 5, MAGIC, 8) != 0) {
        plat_log("derp: region %d sent no greeting", region);
        goto fail;
    }
    memcpy(d->server_key, d->in + 13, 32);
    uint32_t glen = (uint32_t)d->in[1] << 24 | (uint32_t)d->in[2] << 16 |
                    (uint32_t)d->in[3] << 8 | d->in[4];
    memmove(d->in, d->in + 5 + glen, d->in_len - 5 - glen);
    d->in_len -= 5 + glen;

    /* Our key, a nonce, and {"version":2,"CanAckPings":true} sealed to the
       server: the box proves we hold the node key we claim. */
    static const char info[] = "{\"version\":2,\"CanAckPings\":true}";
    uint8_t msg[32 + BOX_NONCE_LEN + TAG_LEN + sizeof(info)];
    memcpy(msg, n->node_pub, 32);
    random_bytes(msg + 32, BOX_NONCE_LEN);
    box_seal(msg + 32 + BOX_NONCE_LEN, info, sizeof(info) - 1, msg + 32, d->server_key, n->node_priv);
    if (send_frame(d, FRAME_CLIENT_INFO, msg, sizeof(msg) - 1, NULL, 0) < 0) goto fail;
    if (region == n->home_region) {
        uint8_t yes = 1;
        if (send_frame(d, FRAME_NOTE_PREFERRED, &yes, 1, NULL, 0) < 0) goto fail;
    }
    d->last_rx = d->last_tx = plat_ms();
    n->derp[slot] = d;
    plat_log("derp: region %d up", region);
    return d;

fail:
    if (d->c) conn_close(d->c);
    free(d->in);
    free(d);
    return NULL;
}

static struct derp_conn *derp_for(struct node *n, int region, int open) {
    for (int i = 0; i < MAX_DERP_CONNS; i++)
        if (n->derp[i] && n->derp[i]->region == region) return n->derp[i];
    return open ? derp_open(n, region) : NULL;
}

/* A region not connected yet is connected by derp_poll, on the tunnel's own
   thread, not here: this can run on any thread that sends, and opening a
   connection takes seconds. The packet is lost meanwhile. */
int derp_send(struct node *n, int region, const uint8_t dst[32], const void *pkt, int len) {
    if (!region) region = n->home_region;
    struct derp_conn *d = derp_for(n, region, 0);
    if (!d) {
        n->derp_wanted = region;
        return -1;
    }
    return send_frame(d, FRAME_SEND_PACKET, dst, 32, pkt, (size_t)len);
}

static int handle_frame(struct node *n, struct derp_conn *d, uint8_t type, uint8_t *p, uint32_t len) {
    switch (type) {
    case FRAME_RECV_PACKET: {
        if (len < 32) return 0;
        struct path via = { d->region, { 0, 0 } };
        magic_recv(n, p, &via, p + 32, (int)len - 32);
        return 0;
    }
    case FRAME_PING:
        if (len == 8) return send_frame(d, FRAME_PONG, p, 8, NULL, 0);
        return 0;
    case FRAME_HEALTH:
        if (len) plat_log("derp: region %d says: %.*s", d->region, (int)(len > 60 ? 60 : len), p);
        return 0;
    case FRAME_RESTARTING:
        plat_log("derp: region %d is restarting", d->region);
        return -1;
    default:
        return 0;           /* ServerInfo, KeepAlive, PeerGone, PeerPresent */
    }
}

void derp_poll(struct node *n) {
    uint32_t now = plat_ms();
    if (n->home_region && !derp_for(n, n->home_region, 0) && (int32_t)(now - g_retry_at) >= 0) {
        if (!derp_open(n, n->home_region)) g_retry_at = plat_ms() + RETRY_MS;
    }
    /* A peer's region somebody wanted to send to. */
    int wanted = n->derp_wanted;
    n->derp_wanted = 0;
    if (wanted && !derp_for(n, wanted, 0)) derp_open(n, wanted);
    for (int i = 0; i < MAX_DERP_CONNS; i++) {
        struct derp_conn *d = n->derp[i];
        if (!d) continue;
        /* Fresh: opening one above took time, and a timestamp from before
           that would read as a connection that has been silent for weeks. */
        now = plat_ms();
        int dead = 0;
        const char *why = "";
        for (;;) {
            int got = conn_read(d->c, d->in + d->in_len, FRAME_MAX - d->in_len);
            if (got < 0) { dead = 1; why = "read failed"; break; }
            if (got == 0) break;
            d->in_len += (size_t)got;
            d->last_rx = now;
            /* Every whole frame in the buffer, then what is left of the
               last one moved to the front once -- not after each frame,
               which during a download is a hundred frames a read. */
            size_t off = 0;
            while (d->in_len - off >= 5) {
                uint8_t *f = d->in + off;
                uint32_t len = (uint32_t)f[1] << 24 | (uint32_t)f[2] << 16 | (uint32_t)f[3] << 8 | f[4];
                if (len > FRAME_MAX - 5) { dead = 1; why = "frame too long"; break; }
                if (d->in_len - off < 5 + len) break;
                /* The frame's handler may have opened or dropped connections;
                   this one is still ours, since nothing closes a peer's
                   connection from inside a receive. */
                if (handle_frame(n, d, f[0], f + 5, len) < 0) { dead = 1; why = "frame refused"; break; }
                off += 5 + len;
            }
            if (off) {
                memmove(d->in, d->in + off, d->in_len - off);
                d->in_len -= off;
            }
            if (dead) break;
        }
        if (!dead && (int32_t)(now - d->last_rx) > SILENCE_MS) { dead = 1; why = "silent"; }
        if (!dead && d->broken) { dead = 1; why = "write failed"; }
        if (!dead && d->region != n->home_region && (int32_t)(now - d->last_tx) > IDLE_CLOSE_MS) {
            plat_log("derp: region %d idle, closing", d->region);
            derp_close(n, i);
            continue;
        }
        if (dead) {
            plat_log("derp: region %d lost (%s)", d->region, why);
            derp_close(n, i);
            g_retry_at = now + RETRY_MS;
        }
    }
}

int derp_connected(struct node *n) {
    return n->home_region && derp_for(n, n->home_region, 0) != NULL;
}
