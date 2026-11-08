/*
 * Disco: how two nodes find out whether they can talk without a relay. Each
 * run has a disco key; a disco message is "TS" and a speech balloon, the
 * sender's disco key, a nonce, and a NaCl box sealed to the receiver's disco
 * key. Inside: a type byte, a version byte, the body.
 *
 *   ping         twelve bytes of transaction id and the sender's node key
 *   pong         the id back, and the address the ping came from
 *   call-me-maybe  the sender's endpoints: ping me there, I am pinging you
 *
 * A pong to a ping we sent over UDP proves that path, and WireGuard then
 * goes direct until it stops being proven. Pings that arrive are always
 * answered by the way they came -- that is what tailscale ping measures.
 *
 * Reference: tailscale.com/disco/disco.go, wgengine/magicsock/endpoint.go.
 */

#include <string.h>

#include "ts/crypto.h"
#include "ts/node.h"
#include "ts/plat.h"

#define MAGIC "TS\xf0\x9f\x92\xac"
#define MAGIC_LEN 6
#define HEADER (MAGIC_LEN + 32 + BOX_NONCE_LEN)

enum { PING = 1, PONG = 2, CALL_ME_MAYBE = 3 };

#define PING_INTERVAL_MS 5000
#define TRUST_MS 15000
#define ACTIVE_MS 45000

static void send_to(struct node *n, struct peer *p, const struct path *via,
                    const uint8_t *msg, size_t len) {
    uint8_t pkt[HEADER + TAG_LEN + 128];
    if (len > 128) return;
    memcpy(pkt, MAGIC, MAGIC_LEN);
    memcpy(pkt + MAGIC_LEN, n->disco_pub, 32);
    random_bytes(pkt + MAGIC_LEN + 32, BOX_NONCE_LEN);
    box_seal(pkt + HEADER, msg, len, pkt + MAGIC_LEN + 32, p->disco_key, n->disco_priv);
    int total = (int)(HEADER + TAG_LEN + len);
    if (via->region) derp_send(n, via->region, p->node_key, pkt, total);
    else if (n->udp >= 0) plat_udp_send(n->udp, via->ep.ip, via->ep.port, pkt, (size_t)total);
}

static void put_addr(uint8_t *out, uint32_t ip, uint16_t port) {
    /* Sixteen bytes of IPv6, the IPv4 mapped into it, then the port. */
    memset(out, 0, 10);
    out[10] = out[11] = 0xff;
    out[12] = (uint8_t)(ip >> 24); out[13] = (uint8_t)(ip >> 16);
    out[14] = (uint8_t)(ip >> 8);  out[15] = (uint8_t)ip;
    out[16] = (uint8_t)(port >> 8); out[17] = (uint8_t)port;
}

static void ping(struct node *n, struct peer *p, const struct endpoint *ep) {
    uint8_t msg[2 + 12 + 32];
    msg[0] = PING;
    msg[1] = 0;
    random_bytes(p->ping_txid, 12);
    memcpy(msg + 2, p->ping_txid, 12);
    memcpy(msg + 14, n->node_pub, 32);
    p->ping_to = *ep;
    p->last_disco_ping = plat_ms();
    struct path via = { 0, *ep };
    send_to(n, p, &via, msg, sizeof(msg));
}

static void ping_endpoints(struct node *n, struct peer *p) {
    /* One transaction at a time, so each round tries the endpoints in turn:
       a pong names the one that answered. */
    if (!p->endpoint_count || n->udp < 0) return;
    if (plat_ms() < p->direct_until) {               /* a heartbeat on the path in use */
        ping(n, p, &p->direct);
        return;
    }
    static unsigned turn;
    ping(n, p, &p->endpoints[turn++ % (unsigned)p->endpoint_count]);
}

void disco_recv(struct node *n, const struct path *via, const uint8_t *pkt, int len) {
    if (len < HEADER + TAG_LEN + 2) return;
    struct peer *p = peer_by_disco(n, pkt + MAGIC_LEN);
    if (!p) return;
    uint8_t msg[256];
    int mlen = box_open(msg, pkt + HEADER, (size_t)(len - HEADER), pkt + MAGIC_LEN + 32,
                        p->disco_key, n->disco_priv);
    if (mlen < 2) return;

    switch (msg[0]) {
    case PING: {
        if (mlen < 2 + 12) return;
        uint8_t pong[2 + 12 + 18];
        pong[0] = PONG;
        pong[1] = 0;
        memcpy(pong + 2, msg + 2, 12);
        if (via->region) put_addr(pong + 14, DERP_MAGIC_IP, (uint16_t)via->region);
        else put_addr(pong + 14, via->ep.ip, via->ep.port);
        send_to(n, p, via, pong, sizeof(pong));
        /* A ping over UDP means they can reach us there; whether we can
           reach them is what our own ping back will tell. */
        if (!via->region && plat_ms() - p->last_disco_ping > 1000) ping(n, p, &via->ep);
        break;
    }
    case PONG:
        if (mlen < 2 + 12 + 18 || memcmp(msg + 2, p->ping_txid, 12) != 0 || via->region) return;
        if (via->ep.ip != p->ping_to.ip || via->ep.port != p->ping_to.port) return;
        if (plat_ms() >= p->direct_until) {
            char ip[16];
            ip_string(ip, via->ep.ip);
            plat_log("disco: direct path to %s via %s:%u, %u ms", p->name, ip, via->ep.port,
                     (unsigned)(plat_ms() - p->last_disco_ping));
        }
        p->direct = via->ep;
        p->direct_until = plat_ms() + TRUST_MS;
        break;
    case CALL_ME_MAYBE:
        /* Their endpoints, fresher than the netmap's: take them and start. */
        if ((mlen - 2) % 18 == 0 && mlen > 2) {
            p->endpoint_count = 0;
            for (int o = 2; o + 18 <= mlen && p->endpoint_count < MAX_ENDPOINTS; o += 18) {
                static const uint8_t v4[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
                if (memcmp(msg + o, v4, 12) != 0) continue;
                struct endpoint *e = &p->endpoints[p->endpoint_count++];
                e->ip = (uint32_t)msg[o + 12] << 24 | (uint32_t)msg[o + 13] << 16 |
                        (uint32_t)msg[o + 14] << 8 | msg[o + 15];
                e->port = (uint16_t)(msg[o + 16] << 8 | msg[o + 17]);
            }
        }
        for (int i = 0; i < p->endpoint_count; i++) ping(n, p, &p->endpoints[i]);
        break;
    }
}

void disco_tick(struct node *n) {
    uint32_t now = plat_ms();
    for (int i = 0; i < n->peer_count; i++) {
        struct peer *p = &n->peers[i];
        if (!p->has_disco || !p->endpoint_count) continue;
        /* Only peers there is traffic with: a node that pinged everybody in
           a large tailnet every five seconds would be a nuisance. */
        uint32_t last = p->wg.last_recv > p->wg.last_sent ? p->wg.last_recv : p->wg.last_sent;
        if (!last || now - last > ACTIVE_MS) continue;
        if (now - p->last_disco_ping > PING_INTERVAL_MS) ping_endpoints(n, p);
    }
}
