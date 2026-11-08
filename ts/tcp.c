/*
 * TCP through the tunnel. lwIP runs without an OS, driven from node_step:
 * one netif whose output is WireGuard to the peer that owns the destination
 * address, and whose input is what netstack hands over with protocol 6.
 * On top, a handful of non-blocking handles that read like plat.h's sockets,
 * which is what an HTTPS client wants to sit on.
 *
 * Received data stays in lwIP's pbufs until it is read, and the window is
 * only opened (tcp_recved) as it is: a slow reader slows the sender instead
 * of filling memory.
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "lwip/init.h"
#include "lwip/ip4.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"

#include "ts/node.h"
#include "ts/plat.h"
#include "ts/tcp.h"

/* What has arrived and not been read, as lwIP handed it over: a ring of
   chains, not one chain -- a pbuf counts its total in sixteen bits, and a
   window of 128 KiB unread would wrap it. */
#define RX_SLOTS 192

struct handle {
    int used;
    int gen;                    /* the handle handed out: slot + gen * TCP_TUNNEL_MAX */
    struct tcp_pcb *pcb;
    struct pbuf *rx[RX_SLOTS];
    int rx_head, rx_count;
    int connected;
    int eof;                    /* the far side closed in order */
    int failed;
};

static struct node *g_node;
static struct netif g_netif;
static struct handle g_h[TCP_TUNNEL_MAX];
static uint32_t g_ip;
/* Inside lwIP: a wait below this -- a DERP write with no room -- must not
   let the tunnel's lock go, or another thread could change the very pcb
   lwIP is in the middle of. */
static int g_depth;
int tcp_tunnel_in_lwip(void) { return g_depth > 0; }

/* ---------------------------------------------------------------- platform */

u32_t sys_now(void) { return plat_ms(); }

unsigned lwip_port_rand(void) {
    unsigned r;
    plat_random(&r, sizeof(r));
    return r;
}

void lwip_port_log(const char *fmt, ...) {
    char line[160];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    size_t len = strlen(line);
    while (len && line[len - 1] == '\n') line[--len] = '\0';
    plat_log("lwip: %s", line);
}

/* -------------------------------------------------------------------- netif */

static err_t netif_out(struct netif *nif, struct pbuf *p, const ip4_addr_t *dst) {
    (void)nif;
    uint8_t pkt[MTU];
    if (p->tot_len > sizeof(pkt)) return ERR_BUF;
    struct peer *peer = peer_by_ip(g_node, lwip_ntohl(ip4_addr_get_u32(dst)));
    if (!peer) return ERR_RTE;
    pbuf_copy_partial(p, pkt, p->tot_len, 0);
    /* A packet WireGuard cannot send yet is TCP's to send again; lwIP's
       retransmission is the queue. */
    wg_send_ip(g_node, peer, pkt, p->tot_len);
    return ERR_OK;
}

static err_t netif_setup(struct netif *nif) {
    nif->name[0] = 't';
    nif->name[1] = 's';
    nif->mtu = MTU;
    nif->output = netif_out;
    nif->flags = 0;
    return ERR_OK;
}

void tcp_tunnel_init(struct node *n) {
    static int ready;
    g_node = n;
    g_ip = 0;
    if (ready) return;                      /* lwIP and its netif live for the program */
    ready = 1;
    lwip_init();
    ip4_addr_t any;
    ip4_addr_set_zero(&any);
    netif_add(&g_netif, &any, &any, &any, NULL, netif_setup, ip4_input);
    netif_set_default(&g_netif);
    netif_set_link_up(&g_netif);
    netif_set_up(&g_netif);
}

void tcp_tunnel_poll(void) {
    if (!g_node) return;
    if (g_node->ip != g_ip) {
        /* The tailnet address arrives with the first map, and may change. */
        ip4_addr_t a, mask, gw;
        g_ip = g_node->ip;
        ip4_addr_set_u32(&a, lwip_htonl(g_ip));
        IP4_ADDR(&mask, 255, 255, 255, 255);
        ip4_addr_set_zero(&gw);
        netif_set_addr(&g_netif, &a, &mask, &gw);
    }
    g_depth++;
    sys_check_timeouts();
    g_depth--;
}

void tcp_tunnel_input(const uint8_t *ip, int len) {
    if (!g_node || len <= 0) return;
    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_POOL);
    if (!p) return;                         /* full: the sender will send it again */
    pbuf_take(p, ip, (u16_t)len);
    g_depth++;
    if (g_netif.input(p, &g_netif) != ERR_OK) pbuf_free(p);
    g_depth--;
}

/* ----------------------------------------------------------------- handles */

/* A handle names its slot and which opening of the slot it was, so one
   kept past a close -- by a connection pool, across a restart -- finds
   nothing rather than whatever uses the slot now. */
static int g_gen;

static struct handle *get(int h) {
    if (h < 0) return NULL;
    struct handle *c = &g_h[h % TCP_TUNNEL_MAX];
    return c->used && c->gen == h / TCP_TUNNEL_MAX ? c : NULL;
}

static err_t on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    struct handle *c = arg;
    (void)pcb;
    if (!c) { if (p) pbuf_free(p); return ERR_OK; }
    if (!p) { c->eof = 1; return ERR_OK; }
    if (err != ERR_OK) { pbuf_free(p); return err; }
    /* No slot: lwIP keeps the data and offers it again on its next timer. */
    if (c->rx_count == RX_SLOTS) return ERR_MEM;
    c->rx[(c->rx_head + c->rx_count++) % RX_SLOTS] = p;
    return ERR_OK;
}

static err_t on_connected(void *arg, struct tcp_pcb *pcb, err_t err) {
    struct handle *c = arg;
    (void)pcb;
    if (c) c->connected = err == ERR_OK;
    return ERR_OK;
}

/* lwIP has freed the pcb by the time this runs: a reset, or a connection
   that never answered. */
static void on_err(void *arg, err_t err) {
    struct handle *c = arg;
    if (!c) return;
    c->pcb = NULL;
    c->failed = 1;
    plat_log("tcp: connection failed (%d)", err);
}

int tcp_tunnel_open(uint32_t ip, uint16_t port) {
    if (!g_node || !g_node->ip || !peer_by_ip(g_node, ip)) return PLAT_ERR;
    int h;
    for (h = 0; h < TCP_TUNNEL_MAX && g_h[h].used; h++) {}
    if (h == TCP_TUNNEL_MAX) return PLAT_ERR;
    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (!pcb) return PLAT_ERR;
    struct handle *c = &g_h[h];
    memset(c, 0, sizeof(*c));
    c->used = 1;
    g_gen = g_gen % (1 << 20) + 1;
    c->gen = g_gen;
    c->pcb = pcb;
    tcp_arg(pcb, c);
    tcp_recv(pcb, on_recv);
    tcp_err(pcb, on_err);
    tcp_nagle_disable(pcb);
    ip_addr_t dst;
    ip_addr_set_ip4_u32(&dst, lwip_htonl(ip));
    g_depth++;
    err_t e = tcp_connect(pcb, &dst, port, on_connected);
    g_depth--;
    if (e != ERR_OK) {
        tcp_abort(pcb);
        c->used = 0;
        return PLAT_ERR;
    }
    return h + c->gen * TCP_TUNNEL_MAX;
}

int tcp_tunnel_ready(int h) {
    struct handle *c = get(h);
    if (!c || c->failed) return PLAT_ERR;
    return c->connected ? 1 : PLAT_AGAIN;
}

int tcp_tunnel_send(int h, const void *buf, size_t len) {
    struct handle *c = get(h);
    if (!c || c->failed || !c->pcb) return PLAT_ERR;
    if (!c->connected) return PLAT_AGAIN;
    size_t room = tcp_sndbuf(c->pcb);
    if (len > room) len = room;
    if (len > 0xffff) len = 0xffff;
    if (!len) return PLAT_AGAIN;
    g_depth++;
    err_t e = tcp_write(c->pcb, buf, (u16_t)len, TCP_WRITE_FLAG_COPY);
    if (e == ERR_OK) tcp_output(c->pcb);
    g_depth--;
    if (e == ERR_MEM) return PLAT_AGAIN;
    if (e != ERR_OK) return PLAT_ERR;
    return (int)len;
}

int tcp_tunnel_recv(int h, void *buf, size_t len) {
    struct handle *c = get(h);
    if (!c) return PLAT_ERR;
    if (!c->rx_count) {
        if (c->eof) return 0;
        return c->failed ? PLAT_ERR : PLAT_AGAIN;
    }
    if (len > 0xffff) len = 0xffff;         /* tcp_recved counts in sixteen bits */
    size_t done = 0;
    while (done < len && c->rx_count) {
        struct pbuf *p = c->rx[c->rx_head];
        u16_t take = (u16_t)(len - done < p->tot_len ? len - done : p->tot_len);
        pbuf_copy_partial(p, (uint8_t *)buf + done, take, 0);
        done += take;
        p = pbuf_free_header(p, take);
        if (p) c->rx[c->rx_head] = p;
        else { c->rx_head = (c->rx_head + 1) % RX_SLOTS; c->rx_count--; }
    }
    g_depth++;
    if (c->pcb) tcp_recved(c->pcb, (u16_t)done);
    g_depth--;
    return (int)done;
}

static void close_slot(struct handle *c) {
    g_depth++;
    if (c->pcb) {
        tcp_arg(c->pcb, NULL);
        tcp_recv(c->pcb, NULL);
        tcp_err(c->pcb, NULL);
        if (tcp_close(c->pcb) != ERR_OK) tcp_abort(c->pcb);
    }
    while (c->rx_count) {
        pbuf_free(c->rx[c->rx_head]);
        c->rx_head = (c->rx_head + 1) % RX_SLOTS;
        c->rx_count--;
    }
    g_depth--;
    memset(c, 0, sizeof(*c));
}

void tcp_tunnel_close(int h) {
    struct handle *c = get(h);
    if (c) close_slot(c);
}

void tcp_tunnel_close_all(void) {
    for (int i = 0; i < TCP_TUNNEL_MAX; i++)
        if (g_h[i].used) close_slot(&g_h[i]);
}
