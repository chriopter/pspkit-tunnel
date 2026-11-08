/* The client on the desk: the PSP's protocol code, a terminal instead of a
   screen. For working on the protocols against tools/tailscale/testnet (or
   a real tailnet) without an emulator in the loop.

     tailscale-host --server https://127.0.0.1:18443 --authkey KEY
                    [--hostname NAME] [--state DIR] [--derp REGION]
                    [--ping SECONDS] [--run SECONDS] [--ephemeral] */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "ts/node.h"
#include "ts/plat.h"

extern const char *plat_state_dir;

struct fetch_result {
    int status;
    long long body;
    uint32_t connect_ms, tls_ms, first_byte_ms, total_ms;
};
int fetch(struct node *n, const char *url, const char *basic, unsigned timeout_s, struct fetch_result *res);

/* http(s)://host[:port], nothing after it. */
int parse_server(struct node *n, const char *url) {
    const char *h;
    if (strncmp(url, "https://", 8) == 0) { n->control_tls = 1; n->control_port = 443; h = url + 8; }
    else if (strncmp(url, "http://", 7) == 0) { n->control_tls = 0; n->control_port = 80; h = url + 7; }
    else return -1;
    size_t len = strcspn(h, ":/");
    if (!len || len >= sizeof(n->control_host)) return -1;
    memcpy(n->control_host, h, len);
    n->control_host[len] = '\0';
    if (h[len] == ':') n->control_port = (uint16_t)atoi(h + len + 1);
    return 0;
}

static void print_peers(struct node *n) {
    for (int i = 0; i < n->peer_count; i++) {
        struct peer *p = &n->peers[i];
        char ip[16];
        ip_string(ip, p->ip);
        plat_log("  %-16s %-15s %s derp %d %s%s", p->name, ip, p->online ? "online " : "offline",
                 p->derp_region, p->direct_until > plat_ms() ? "direct" : "relayed",
                 p->wg.current.valid ? ", wg up" : "");
    }
}

int main(int argc, char **argv) {
    static struct node n;
    unsigned ping_every = 0, run_for = 0, times = 1;
    const char *get = NULL, *basic = getenv("TUNNEL_BASIC");
    snprintf(n.hostname, sizeof(n.hostname), "psp-host");
    n.interactive = 1;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(a, "--no-udp")) { n.no_udp = 1; continue; }
        if (!strcmp(a, "--ephemeral")) { n.ephemeral = 1; continue; }
        if (!v) { fprintf(stderr, "%s wants a value\n", a); return 2; }
        if (!strcmp(a, "--server")) { if (parse_server(&n, v) < 0) { fprintf(stderr, "bad url\n"); return 2; } }
        else if (!strcmp(a, "--authkey")) snprintf(n.auth_key, sizeof(n.auth_key), "%s", v);
        else if (!strcmp(a, "--hostname")) snprintf(n.hostname, sizeof(n.hostname), "%s", v);
        else if (!strcmp(a, "--state")) { plat_state_dir = v; mkdir(v, 0700); }
        else if (!strcmp(a, "--derp")) n.prefer_region = atoi(v);
        else if (!strcmp(a, "--ping")) ping_every = (unsigned)atoi(v) * 1000;
        else if (!strcmp(a, "--run")) run_for = (unsigned)atoi(v) * 1000;
        else if (!strcmp(a, "--get")) get = v;
        else if (!strcmp(a, "--times")) times = (unsigned)atoi(v);
        else { fprintf(stderr, "unknown option %s\n", a); return 2; }
        i++;
    }
    if (!n.control_host[0]) {
        fprintf(stderr, "usage: %s --server URL [--authkey KEY] [--hostname NAME] [--state DIR]"
                " [--derp REGION] [--ping S] [--run S] [--no-udp]\n", argv[0]);
        return 2;
    }
    node_init(&n);
    uint32_t start = plat_ms(), last_ping = start, last_print = start;
    int maps = 0;
    if (get) {
        /* Up first: an address, and the relay home. */
        while (!(n.ip && derp_connected(&n))) {
            node_step(&n);
            plat_sleep_ms(1);
            if (plat_ms() - start > 30000) { plat_log("fetch: tunnel not up in 30 s"); return 1; }
        }
        plat_log("tunnel up after %u ms", plat_ms() - start);
        int failed = 0;
        for (unsigned i = 0; i < times; i++) {
            struct fetch_result r;
            if (fetch(&n, get, basic, 120, &r) < 0) { failed++; plat_log("get %u: failed", i + 1); continue; }
            double s = r.total_ms / 1000.0;
            plat_log("get %u: %d, %lld bytes, connect %u ms, tls %u ms, first byte %u ms, %.2f s, %.0f KB/s",
                     i + 1, r.status, r.body, r.connect_ms, r.tls_ms, r.first_byte_ms, s,
                     s > 0 ? r.body / 1024.0 / s : 0);
            if (r.status != 200) failed++;
        }
        return failed ? 1 : 0;
    }
    for (;;) {
        node_step(&n);
        uint32_t now = plat_ms();
        if (n.map_count != maps) {
            maps = n.map_count;
            plat_log("status: %s", n.status);
            print_peers(&n);
        }
        if (ping_every && n.ip && now - last_ping >= ping_every) {
            last_ping = now;
            for (int i = 0; i < n.peer_count; i++)
                if (n.peers[i].online && n.peers[i].ip) net_ping(&n, &n.peers[i]);
        }
        if (now - last_print >= 30000) {
            last_print = now;
            plat_log("status: %s", n.status);
            print_peers(&n);
        }
        if (run_for && now - start >= run_for) break;
        plat_sleep_ms(2);
    }
    plat_log("status: %s", n.status);
    print_peers(&n);
    return 0;
}
