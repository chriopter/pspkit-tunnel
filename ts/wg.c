/*
 * WireGuard, as the whitepaper has it and wireguard-go speaks it: the
 * Noise_IKpsk2 handshake with an all-zero preshared key, then transport
 * packets under ChaCha20-Poly1305 with a 64-bit little-endian counter.
 * Tailscale adds nothing on the wire; a node's WireGuard key is its node
 * key, and whether the datagrams go by UDP or DERP is magicsock's business.
 *
 * Timers are the whitepaper's, cut to what a node that mostly answers
 * needs: rekey after two minutes, give a session up after three, retry a
 * handshake every five seconds for ninety, and keep a session warm with an
 * empty packet when we have been sent something and said nothing back.
 * Cookies (the under-load DoS defence) are neither sent nor answered.
 */

#include <string.h>

#include "ts/crypto.h"
#include "ts/node.h"
#include "ts/plat.h"

#define REKEY_AFTER_MS 120000
#define REJECT_AFTER_MS 180000
#define REKEY_TIMEOUT_MS 5000
#define REKEY_ATTEMPT_MS 90000
#define KEEPALIVE_MS 10000

enum { MSG_INIT = 1, MSG_RESP = 2, MSG_COOKIE = 3, MSG_DATA = 4 };
#define INIT_LEN 148
#define RESP_LEN 92
#define DATA_HEADER 16

static uint8_t g_ck0[32], g_h0[32];

static void setup(void) {
    static int done;
    if (done) return;
    static const char construction[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    static const char identifier[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
    blake2s(g_ck0, 32, NULL, 0, construction, strlen(construction));
    blake2s_ctx c;
    blake2s_init(&c, 32, NULL, 0);
    blake2s_update(&c, g_ck0, 32);
    blake2s_update(&c, identifier, strlen(identifier));
    blake2s_final(&c, g_h0);
    done = 1;
}

static void mix_hash(uint8_t h[32], const void *data, size_t len) {
    blake2s_ctx c;
    blake2s_init(&c, 32, NULL, 0);
    blake2s_update(&c, h, 32);
    blake2s_update(&c, data, len);
    blake2s_final(&c, h);
}

static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void nonce_le(uint8_t out[12], uint64_t n) {
    memset(out, 0, 4);
    for (int i = 0; i < 8; i++) out[4 + i] = (uint8_t)(n >> (8 * i));
}

/* mac1: a 16-byte keyed BLAKE2s over the message so far, keyed with the
   hash of "mac1----" and the receiver's static key. */
static void mac1(uint8_t out[16], const uint8_t receiver[32], const uint8_t *msg, size_t len) {
    uint8_t key[32];
    blake2s_ctx c;
    blake2s_init(&c, 32, NULL, 0);
    blake2s_update(&c, "mac1----", 8);
    blake2s_update(&c, receiver, 32);
    blake2s_final(&c, key);
    blake2s(out, 16, key, 32, msg, len);
}

static int mac1_ok(struct node *n, const uint8_t *msg, size_t len) {
    uint8_t m[16], diff = 0;
    mac1(m, n->node_pub, msg, len - 32);
    for (int i = 0; i < 16; i++) diff |= m[i] ^ msg[len - 32 + i];
    return diff == 0;
}

/* TAI64N: seconds past 1970 plus 2^62, then nanoseconds, both big-endian. */
static void tai64n(uint8_t out[12]) {
    uint64_t ms = plat_unix_ms();
    uint64_t s = 0x400000000000000aULL + ms / 1000;
    uint32_t ns = (uint32_t)(ms % 1000) * 1000000u;
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(s >> (56 - 8 * i));
    for (int i = 0; i < 4; i++) out[8 + i] = (uint8_t)(ns >> (24 - 8 * i));
}

static uint32_t new_index(void) {
    uint32_t i;
    random_bytes(&i, sizeof(i));
    return i;
}

static const char *peer_name(const struct peer *p) { return p->name[0] ? p->name : "peer"; }

/* ------------------------------------------------------------ handshake */

static void send_initiation(struct node *n, struct peer *p) {
    struct wg_peer *w = &p->wg;
    uint8_t msg[INIT_LEN], ck[32], h[32], k[32], dh[32], eph_pub[32], ts[12];
    uint8_t zero[12] = { 0 };
    setup();
    memcpy(ck, g_ck0, 32);
    memcpy(h, g_h0, 32);
    mix_hash(h, p->node_key, 32);

    w->hs_index = new_index();
    x25519_keygen(w->hs_eph_priv, eph_pub);
    msg[0] = MSG_INIT; msg[1] = msg[2] = msg[3] = 0;
    put32(msg + 4, w->hs_index);
    memcpy(msg + 8, eph_pub, 32);
    hkdf(ck, NULL, NULL, ck, eph_pub, 32);
    mix_hash(h, eph_pub, 32);

    x25519(dh, w->hs_eph_priv, p->node_key);
    hkdf(ck, k, NULL, ck, dh, 32);
    aead_seal(msg + 40, k, zero, n->node_pub, 32, h, 32);
    mix_hash(h, msg + 40, 48);

    x25519(dh, n->node_priv, p->node_key);
    hkdf(ck, k, NULL, ck, dh, 32);
    tai64n(ts);
    aead_seal(msg + 88, k, zero, ts, 12, h, 32);
    mix_hash(h, msg + 88, 28);

    mac1(msg + 116, p->node_key, msg, 116);
    memset(msg + 132, 0, 16);                        /* mac2: no cookie */
    memcpy(w->hs_hash, h, 32);
    memcpy(w->hs_ck, ck, 32);
    w->hs_sent = plat_ms();
    if (!w->hs_pending) w->hs_started = w->hs_sent;
    w->hs_pending = 1;
    magic_send(n, p, msg, sizeof(msg));
}

static void install(struct wg_keypair *kp, const uint8_t ck[32], int initiator,
                    uint32_t local, uint32_t remote) {
    memset(kp, 0, sizeof(*kp));
    if (initiator) hkdf(kp->send_key, kp->recv_key, NULL, ck, NULL, 0);
    else hkdf(kp->recv_key, kp->send_key, NULL, ck, NULL, 0);
    kp->local_index = local;
    kp->remote_index = remote;
    kp->initiator = initiator;
    kp->confirmed = initiator;
    kp->created = plat_ms();
    kp->valid = 1;
}

static int send_data(struct node *n, struct peer *p, struct wg_keypair *kp,
                     const uint8_t *ip, int len);
static int queue_take(struct node *n, struct peer *p, struct wg_keypair *kp);

/* An initiation from somebody: who it is comes out of the message itself,
   so it is decrypted before any peer is looked at. */
static void recv_initiation(struct node *n, const uint8_t *msg) {
    uint8_t ck[32], h[32], k[32], dh[32], peer_key[32], ts[12];
    uint8_t zero[12] = { 0 };
    if (!mac1_ok(n, msg, INIT_LEN)) return;
    setup();
    memcpy(ck, g_ck0, 32);
    memcpy(h, g_h0, 32);
    mix_hash(h, n->node_pub, 32);

    const uint8_t *eph_i = msg + 8;
    hkdf(ck, NULL, NULL, ck, eph_i, 32);
    mix_hash(h, eph_i, 32);
    if (x25519(dh, n->node_priv, eph_i) < 0) return;
    hkdf(ck, k, NULL, ck, dh, 32);
    if (aead_open(peer_key, k, zero, msg + 40, 48, h, 32) < 0) return;
    mix_hash(h, msg + 40, 48);

    struct peer *p = peer_by_key(n, peer_key);
    if (!p) {
        plat_log("wg: initiation from a key not in the netmap");
        return;
    }
    if (x25519(dh, n->node_priv, peer_key) < 0) return;
    hkdf(ck, k, NULL, ck, dh, 32);
    if (aead_open(ts, k, zero, msg + 88, 28, h, 32) < 0) return;
    mix_hash(h, msg + 88, 28);
    if (memcmp(ts, p->wg.last_timestamp, 12) <= 0) {
        plat_log("wg: replayed initiation from %s", peer_name(p));
        return;
    }
    memcpy(p->wg.last_timestamp, ts, 12);

    /* The response. */
    uint8_t resp[RESP_LEN], eph_priv[32], eph_pub[32], tau[32], psk[32] = { 0 };
    uint32_t local = new_index();
    x25519_keygen(eph_priv, eph_pub);
    resp[0] = MSG_RESP; resp[1] = resp[2] = resp[3] = 0;
    put32(resp + 4, local);
    memcpy(resp + 8, msg + 4, 4);                    /* their index, as they sent it */
    memcpy(resp + 12, eph_pub, 32);
    hkdf(ck, NULL, NULL, ck, eph_pub, 32);
    mix_hash(h, eph_pub, 32);
    x25519(dh, eph_priv, eph_i);
    hkdf(ck, NULL, NULL, ck, dh, 32);
    x25519(dh, eph_priv, peer_key);
    hkdf(ck, NULL, NULL, ck, dh, 32);
    hkdf(ck, tau, k, ck, psk, 32);
    mix_hash(h, tau, 32);
    aead_seal(resp + 44, k, zero, NULL, 0, h, 32);
    mix_hash(h, resp + 44, 16);
    mac1(resp + 60, peer_key, resp, 60);
    memset(resp + 76, 0, 16);

    install(&p->wg.next, ck, 0, local, get32(msg + 4));
    plat_log("wg: handshake from %s answered", peer_name(p));
    magic_send(n, p, resp, sizeof(resp));
    p->wg.last_sent = plat_ms();
}

static void recv_response(struct node *n, const uint8_t *msg) {
    uint32_t receiver = get32(msg + 8);
    struct peer *p = NULL;
    for (int i = 0; i < n->peer_count; i++)
        if (n->peers[i].wg.hs_pending && n->peers[i].wg.hs_index == receiver) p = &n->peers[i];
    if (!p || !mac1_ok(n, msg, RESP_LEN)) return;
    struct wg_peer *w = &p->wg;
    uint8_t ck[32], h[32], k[32], dh[32], tau[32], psk[32] = { 0 }, zero[12] = { 0 };
    memcpy(ck, w->hs_ck, 32);
    memcpy(h, w->hs_hash, 32);
    const uint8_t *eph_r = msg + 12;
    hkdf(ck, NULL, NULL, ck, eph_r, 32);
    mix_hash(h, eph_r, 32);
    if (x25519(dh, w->hs_eph_priv, eph_r) < 0) return;
    hkdf(ck, NULL, NULL, ck, dh, 32);
    if (x25519(dh, n->node_priv, eph_r) < 0) return;
    hkdf(ck, NULL, NULL, ck, dh, 32);
    hkdf(ck, tau, k, ck, psk, 32);
    mix_hash(h, tau, 32);
    if (aead_open(NULL, k, zero, msg + 44, 16, h, 32) < 0) {
        plat_log("wg: response from %s did not authenticate", peer_name(p));
        return;
    }
    w->hs_pending = 0;
    w->previous = w->current;
    install(&w->current, ck, 1, w->hs_index, get32(msg + 4));
    plat_log("wg: session with %s up", peer_name(p));
    /* What was waiting, or an empty keepalive if nothing was: either way
       the responder learns the session is real and may start sending. */
    if (!queue_take(n, p, &w->current)) send_data(n, p, &w->current, NULL, 0);
}

/* ----------------------------------------------------------------- queue */

/* What waits for a handshake to finish, for every peer together: the
   first moments of a session are when several connections open at once,
   and a SYN dropped here costs a whole retransmission timeout. Sixteen
   packets, the oldest given up first; matched by node key, since the peer
   table can be rewritten while they wait. */
#define QUEUE_MAX 16
static struct { uint8_t key[32]; int len; uint8_t pkt[MTU]; } g_queue[QUEUE_MAX];
static int g_queued;

static void queue_add(struct peer *p, const uint8_t *ip, int len) {
    if (g_queued == QUEUE_MAX) {
        memmove(&g_queue[0], &g_queue[1], sizeof(g_queue[0]) * (QUEUE_MAX - 1));
        g_queued--;
    }
    memcpy(g_queue[g_queued].key, p->node_key, 32);
    memcpy(g_queue[g_queued].pkt, ip, (size_t)len);
    g_queue[g_queued].len = len;
    g_queued++;
}

/* Sends what waits for p over kp, or drops it when kp is NULL; how many.
   The packets come out of the queue first and are sent after, from a copy:
   a send can wait with the tunnel's lock let go, and another thread may
   queue meanwhile. */
static int queue_take(struct node *n, struct peer *p, struct wg_keypair *kp) {
    static uint8_t mine_pkt[QUEUE_MAX][MTU];   /* the tunnel's thread only */
    int mine_len[QUEUE_MAX], mine = 0, keep = 0;
    for (int i = 0; i < g_queued; i++) {
        if (memcmp(g_queue[i].key, p->node_key, 32)) {
            if (keep != i) g_queue[keep] = g_queue[i];
            keep++;
            continue;
        }
        memcpy(mine_pkt[mine], g_queue[i].pkt, (size_t)g_queue[i].len);
        mine_len[mine++] = g_queue[i].len;
    }
    g_queued = keep;
    if (!kp) return 0;
    for (int i = 0; i < mine; i++) send_data(n, p, kp, mine_pkt[i], mine_len[i]);
    return mine;
}

void wg_reset(void) { g_queued = 0; }

/* ------------------------------------------------------------- transport */

static int send_data(struct node *n, struct peer *p, struct wg_keypair *kp,
                     const uint8_t *ip, int len) {
    uint8_t pkt[DATA_HEADER + MTU + 16 + TAG_LEN], plain[MTU + 16], nonce[12];
    if (len > MTU) return -1;
    int padded = (len + 15) & ~15;
    if (padded > MTU) padded = MTU;
    memset(plain, 0, (size_t)padded);
    if (len) memcpy(plain, ip, (size_t)len);
    pkt[0] = MSG_DATA; pkt[1] = pkt[2] = pkt[3] = 0;
    put32(pkt + 4, kp->remote_index);
    uint64_t c = kp->send_counter++;
    for (int i = 0; i < 8; i++) pkt[8 + i] = (uint8_t)(c >> (8 * i));
    nonce_le(nonce, c);
    aead_seal(pkt + DATA_HEADER, kp->send_key, nonce, plain, (size_t)padded, NULL, 0);
    p->wg.last_sent = plat_ms();
    return magic_send(n, p, pkt, DATA_HEADER + padded + TAG_LEN);
}

/* The sliding window of RFC 6479, at the size of one word: a counter may
   arrive up to 63 behind the newest and still count once. */
static int replay_ok(struct wg_keypair *kp, uint64_t c) {
    if (c > kp->recv_max || (kp->recv_max == 0 && kp->recv_window == 0)) {
        uint64_t shift = c - kp->recv_max;
        kp->recv_window = shift >= 64 ? 0 : kp->recv_window << shift;
        kp->recv_window |= 1;
        kp->recv_max = c;
        return 1;
    }
    uint64_t back = kp->recv_max - c;
    if (back >= 64 || (kp->recv_window & (1ULL << back))) return 0;
    kp->recv_window |= 1ULL << back;
    return 1;
}

static void recv_data(struct node *n, uint8_t *msg, int len) {
    uint32_t idx = get32(msg + 4);
    struct peer *p = NULL;
    struct wg_keypair *kp = NULL;
    for (int i = 0; i < n->peer_count && !kp; i++) {
        struct wg_peer *w = &n->peers[i].wg;
        struct wg_keypair *slots[3] = { &w->current, &w->next, &w->previous };
        for (int s = 0; s < 3; s++) {
            if (slots[s]->valid && slots[s]->local_index == idx) {
                kp = slots[s];
                p = &n->peers[i];
                break;
            }
        }
    }
    if (!kp || len < DATA_HEADER + TAG_LEN) return;
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) c |= (uint64_t)msg[8 + i] << (8 * i);
    uint8_t nonce[12], plain[MTU + 16];
    int plen = len - DATA_HEADER - TAG_LEN;
    if (plen > (int)sizeof(plain)) return;
    nonce_le(nonce, c);
    if (aead_open(plain, kp->recv_key, nonce, msg + DATA_HEADER, (size_t)(len - DATA_HEADER), NULL, 0) < 0)
        return;
    if (!replay_ok(kp, c)) return;
    struct wg_peer *w = &p->wg;
    if (kp == &w->next) {
        /* The initiator's first packet under the session we answered. */
        w->previous = w->current;
        w->current = w->next;
        w->current.confirmed = 1;
        memset(&w->next, 0, sizeof(w->next));
        kp = &w->current;
        plat_log("wg: session with %s up", peer_name(p));
        queue_take(n, p, kp);
    }
    w->last_recv = plat_ms();
    if (plen == 0) return;                           /* keepalive */
    w->last_data_recv = w->last_recv;
    net_input(n, p, plain, plen);
}

void wg_recv(struct node *n, struct peer *from, const struct path *via, uint8_t *pkt, int len) {
    (void)from; (void)via;
    if (len < 4) return;
    switch (pkt[0]) {
    case MSG_INIT: if (len == INIT_LEN) recv_initiation(n, pkt); break;
    case MSG_RESP: if (len == RESP_LEN) recv_response(n, pkt); break;
    case MSG_DATA: recv_data(n, pkt, len); break;
    case MSG_COOKIE: plat_log("wg: cookie reply ignored (peer under load)"); break;
    }
}

static int usable(const struct wg_keypair *kp) {
    return kp->valid && kp->confirmed && plat_ms() - kp->created < REJECT_AFTER_MS;
}

int wg_send_ip(struct node *n, struct peer *p, const uint8_t *ip, int len) {
    struct wg_peer *w = &p->wg;
    uint32_t now = plat_ms();
    if (usable(&w->current)) {
        int rc = send_data(n, p, &w->current, ip, len);
        if (w->current.initiator && now - w->current.created > REKEY_AFTER_MS && !w->hs_pending)
            send_initiation(n, p);
        return rc;
    }
    if (len > MTU) return -1;
    queue_add(p, ip, len);
    if (!w->hs_pending || now - w->hs_sent > REKEY_TIMEOUT_MS) send_initiation(n, p);
    return 0;
}

void wg_tick(struct node *n) {
    uint32_t now = plat_ms();
    for (int i = 0; i < n->peer_count; i++) {
        struct peer *p = &n->peers[i];
        struct wg_peer *w = &p->wg;
        if (w->hs_pending && now - w->hs_sent > REKEY_TIMEOUT_MS) {
            if (now - w->hs_started > REKEY_ATTEMPT_MS) {
                plat_log("wg: %s never answered", peer_name(p));
                w->hs_pending = 0;
                queue_take(n, p, NULL);
            } else {
                send_initiation(n, p);
            }
        }
        if (usable(&w->current) && w->last_data_recv &&
            w->last_data_recv > w->last_sent && now - w->last_data_recv > KEEPALIVE_MS) {
            send_data(n, p, &w->current, NULL, 0);
        }
        if (w->previous.valid && now - w->previous.created > REJECT_AFTER_MS) w->previous.valid = 0;
        if (w->next.valid && now - w->next.created > REJECT_AFTER_MS) w->next.valid = 0;
    }
}
