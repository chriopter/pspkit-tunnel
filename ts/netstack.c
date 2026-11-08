/*
 * The part of an IP stack a node cannot do without: it answers ICMP echo
 * (ping from any peer, and tailscale ping --icmp) and TSMP echo (tailscale
 * ping --tsmp, which is Tailscale's own protocol 99 and a single packet),
 * and it can ping a peer itself. TCP goes on to lwIP (tcp.c); UDP has no
 * use here yet. IPv6 is dropped, since the tailnet gives every node an IPv4
 * address too.
 */

#include <string.h>

#include "ts/node.h"
#include "ts/plat.h"
#include "ts/tcp.h"

#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_TSMP 99
#define ECHO_ID 0x5053                           /* "PS" */

static uint16_t be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static uint16_t checksum(const uint8_t *p, int len) {
    uint32_t sum = 0;
    for (int i = 0; i + 1 < len; i += 2) sum += be16(p + i);
    if (len & 1) sum += (uint32_t)p[len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static void ip_header(uint8_t *ip, int total, uint8_t proto, uint32_t src, uint32_t dst) {
    memset(ip, 0, 20);
    ip[0] = 0x45;
    put16(ip + 2, (uint16_t)total);
    ip[8] = 64;
    ip[9] = proto;
    put32(ip + 12, src);
    put32(ip + 16, dst);
    put16(ip + 10, checksum(ip, 20));
}

static void icmp(struct node *n, struct peer *from, uint8_t *ip, int ihl, int len) {
    uint8_t *m = ip + ihl;
    int mlen = len - ihl;
    if (mlen < 8 || checksum(m, mlen) != 0) return;
    if (m[0] == 8) {                                 /* echo request */
        uint8_t reply[MTU];
        if (len > MTU) return;
        memcpy(reply + 20, m, (size_t)mlen);
        reply[20] = 0;
        put16(reply + 22, 0);
        put16(reply + 22, checksum(reply + 20, mlen));
        ip_header(reply, 20 + mlen, PROTO_ICMP, n->ip, be32(ip + 12));
        wg_send_ip(n, from, reply, 20 + mlen);
    } else if (m[0] == 0 && be16(m + 4) == ECHO_ID && be16(m + 6) == from->echo_seq) {
        from->echo_rtt = (int)(plat_ms() - from->echo_sent);
        plat_log("ping: %s answered in %d ms", from->name, from->echo_rtt);
    }
}

static void tsmp(struct node *n, struct peer *from, const uint8_t *ip, int ihl, int len) {
    const uint8_t *m = ip + ihl;
    if (len - ihl < 9 || m[0] != 'p') return;
    uint8_t reply[20 + 11];
    reply[20] = 'o';
    memcpy(reply + 21, m + 1, 8);
    put16(reply + 29, 0);                            /* no PeerAPI here */
    ip_header(reply, sizeof(reply), PROTO_TSMP, n->ip, be32(ip + 12));
    wg_send_ip(n, from, reply, sizeof(reply));
}

void net_input(struct node *n, struct peer *from, uint8_t *ip, int len) {
    if (len < 20 || (ip[0] >> 4) != 4) return;
    int ihl = (ip[0] & 15) * 4, total = be16(ip + 2);
    if (ihl < 20 || total < ihl || total > len) return;
    if (be32(ip + 16) != n->ip) return;
    /* The source has to be the peer the packet came from: WireGuard's
       allowed-IPs check, for a node that allows each peer its own address. */
    if (be32(ip + 12) != from->ip) return;
    switch (ip[9]) {
    case PROTO_ICMP: icmp(n, from, ip, ihl, total); break;
    case PROTO_TSMP: tsmp(n, from, ip, ihl, total); break;
    case PROTO_TCP: tcp_tunnel_input(ip, total); break;
    }
}

int net_ping(struct node *n, struct peer *p) {
    if (!p->ip || !n->ip) return -1;
    uint8_t pkt[20 + 8 + 16];
    uint8_t *m = pkt + 20;
    memset(m, 0, 8);
    m[0] = 8;
    put16(m + 4, ECHO_ID);
    put16(m + 6, ++p->echo_seq);
    memcpy(m + 8, "pspdx tailscale", 16);
    put16(m + 2, checksum(m, 24));
    ip_header(pkt, sizeof(pkt), PROTO_ICMP, n->ip, p->ip);
    p->echo_sent = plat_ms();
    p->echo_rtt = -1;
    return wg_send_ip(n, p, pkt, sizeof(pkt));
}
