#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "ts/crypto.h"
#include "ts/node.h"
#include "ts/tcp.h"
#include "ts/plat.h"

#define KEY_FILE "tunnel.key"
#define CONTROL_RETRY_MS 10000
#define WG_PORT 41641

struct peer *peer_by_key(struct node *n, const uint8_t key[32]) {
    for (int i = 0; i < n->peer_count; i++)
        if (memcmp(n->peers[i].node_key, key, 32) == 0) return &n->peers[i];
    return NULL;
}

struct peer *peer_by_disco(struct node *n, const uint8_t key[32]) {
    for (int i = 0; i < n->peer_count; i++)
        if (n->peers[i].has_disco && memcmp(n->peers[i].disco_key, key, 32) == 0) return &n->peers[i];
    return NULL;
}

struct peer *peer_by_id(struct node *n, int64_t id) {
    for (int i = 0; i < n->peer_count; i++)
        if (n->peers[i].id == id) return &n->peers[i];
    return NULL;
}

struct peer *peer_by_ip(struct node *n, uint32_t ip) {
    for (int i = 0; i < n->peer_count; i++)
        if (n->peers[i].ip == ip) return &n->peers[i];
    return NULL;
}

/* A name in the tailnet to its address: the peer's short name, or the
   short name under the tailnet's MagicDNS suffix (jellyhop, jellyhop.foo.ts.net,
   with or without the final dot), or an address written out. */
int node_resolve(struct node *n, const char *host, uint32_t *ip) {
    unsigned a, b, c, d;
    char tail;
    if (sscanf(host, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) == 4 && a < 256 && b < 256 && c < 256 && d < 256) {
        *ip = a << 24 | b << 16 | c << 8 | d;
        return 0;
    }
    size_t len = strcspn(host, ".");
    const char *rest = host + len;
    if (*rest == '.') {
        rest++;
        size_t dl = strlen(n->suffix), rl = strlen(rest);
        if (rl && rest[rl - 1] == '.') rl--;
        while (dl && n->suffix[dl - 1] == '.') dl--;
        if (rl && (rl != dl || strncasecmp(rest, n->suffix, rl))) return -1;
    }
    for (int i = 0; i < n->peer_count; i++) {
        if (n->peers[i].ip && strlen(n->peers[i].name) == len && !strncasecmp(n->peers[i].name, host, len)) {
            *ip = n->peers[i].ip;
            return 0;
        }
    }
    return -1;
}

const struct region *region_by_id(struct node *n, int id) {
    for (int i = 0; i < n->region_count; i++)
        if (n->regions[i].id == id) return &n->regions[i];
    return NULL;
}

/* The machine and node keys outlive a run: they are what the control
   server knows this device by, and a new pair would be a new device. The
   file is the two private halves, 64 bytes, and nothing else. A pair is only
   written once control has taken it, so a file there means a device in the
   tailnet, and a refused key leaves nothing behind. */
static void load_keys(struct node *n) {
    uint8_t buf[64];
    if (plat_load(KEY_FILE, buf, sizeof(buf)) == (int)sizeof(buf)) {
        memcpy(n->machine_priv, buf, 32);
        memcpy(n->node_priv, buf + 32, 32);
        x25519_public(n->machine_pub, n->machine_priv);
        x25519_public(n->node_pub, n->node_priv);
        n->keys_saved = 1;
        memset(buf, 0, sizeof(buf));
        return;
    }
    x25519_keygen(n->machine_priv, n->machine_pub);
    x25519_keygen(n->node_priv, n->node_pub);
}

void node_save_keys(struct node *n) {
    uint8_t buf[64];
    if (n->keys_saved) return;
    memcpy(buf, n->machine_priv, 32);
    memcpy(buf + 32, n->node_priv, 32);
    if (plat_save(KEY_FILE, buf, sizeof(buf)) < 0) plat_log("node: could not save %s", KEY_FILE);
    else { n->keys_saved = 1; plat_log("node: keys kept in %s", KEY_FILE); }
    memset(buf, 0, sizeof(buf));
}

int node_init(struct node *n) {
    load_keys(n);
    x25519_keygen(n->disco_priv, n->disco_pub);
    n->udp = -1;
    if (!n->no_udp) {
        n->udp = plat_udp_open(WG_PORT, &n->udp_port);
        if (n->udp < 0) n->udp = plat_udp_open(0, &n->udp_port);
    }
    n->lan_ip = plat_local_ip();
    n->started = plat_ms();
    tcp_tunnel_init(n);
    char key[80];
    key_string(key, "nodekey:", n->node_pub);
    plat_log("node: %.24s... udp port %u", key, n->udp_port);
    return 0;
}

/* The home region, chosen without asking anyone: the one most peers call
   home, online ones counting double, so the packets to them need no hop
   between relays -- the rule the ESP32 ports use in place of Tailscale's
   latency measurement (netcheck). A region asked for wins; with no peers
   at all, the lowest-numbered. Once chosen it goes to control, which tells
   every peer where to find us. */
static void pick_home(struct node *n) {
    if (n->home_region || !n->region_count) return;
    int best = 0, best_votes = 0;
    for (int i = 0; i < n->region_count; i++) {
        int id = n->regions[i].id, votes = 0;
        if (id == n->prefer_region) { best = id; break; }
        for (int j = 0; j < n->peer_count; j++)
            if (n->peers[j].derp_region == id) votes += n->peers[j].online ? 2 : 1;
        if (!best || votes > best_votes || (votes == best_votes && id < best)) {
            best = id;
            best_votes = votes;
        }
    }
    n->home_region = best;
    const struct region *r = region_by_id(n, best);
    plat_log("node: home DERP region %d (%s)", best, r ? r->code : "?");
    control_update_endpoints(n);
}

void magic_recv(struct node *n, const uint8_t src_key[32], const struct path *via,
                uint8_t *pkt, int len) {
    if (len >= 6 + 32 + 24 && memcmp(pkt, "TS\xf0\x9f\x92\xac", 6) == 0) {
        disco_recv(n, via, pkt, len);
        return;
    }
    wg_recv(n, src_key ? peer_by_key(n, src_key) : NULL, via, pkt, len);
}

int magic_send(struct node *n, struct peer *p, const void *pkt, int len) {
    if (n->udp >= 0 && plat_ms() < p->direct_until)
        return plat_udp_send(n->udp, p->direct.ip, p->direct.port, pkt, (size_t)len) < 0 ? -1 : 0;
    return derp_send(n, p->derp_region, p->node_key, pkt, len);
}

static void udp_poll(struct node *n) {
    uint8_t buf[MTU + 128];
    for (int i = 0; i < 64 && n->udp >= 0; i++) {
        struct path via = { 0, { 0, 0 } };
        int len = plat_udp_recv(n->udp, buf, sizeof(buf), &via.ep.ip, &via.ep.port);
        if (len <= 0) break;
        magic_recv(n, NULL, &via, buf, len);
    }
}

void node_stop(struct node *n) {
    wg_reset();
    control_stop(n);
    derp_stop(n);
    if (n->udp >= 0) plat_udp_close(n->udp);
    n->udp = -1;
}

void node_step(struct node *n) {
    uint32_t now = plat_ms();
    if (!n->control && (int32_t)(now - n->control_retry) >= 0) {
        if (control_start(n) < 0) n->control_retry = plat_ms() + CONTROL_RETRY_MS;
    }
    control_poll(n);
    pick_home(n);
    derp_poll(n);
    udp_poll(n);
    disco_tick(n);
    wg_tick(n);
    tcp_tunnel_poll();
    if (n->control && n->ip) {
        char ip[16];
        ip_string(ip, n->ip);
        snprintf(n->status, sizeof(n->status), "%s, %d peers, derp %s", ip, n->peer_count,
                 derp_connected(n) ? "up" : "down");
    }
}
