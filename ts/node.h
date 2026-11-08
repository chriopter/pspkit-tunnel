#ifndef TS_NODE_H
#define TS_NODE_H

/* One Tailscale node: its keys, what the control server says about it and
   its peers, and the state of every protocol running on its behalf. There is
   one of these per process and every module works on it; nothing below is
   thread-safe, because nothing below runs on more than one thread -- the
   whole client is one loop, node_step, called as often as the caller likes.

   Four protocols meet here, each in its own file:

     control.c   Noise IK to the coordination server, HTTP/2 inside it,
                 registration and the streaming map of the tailnet
     derp.c      the relays, TLS to each, a frame protocol inside
     disco.c     path discovery: pings and pongs sealed to disco keys
     wg.c        WireGuard to each peer, over DERP or UDP
     netstack.c  the few bits of IPv4 a node has to answer for itself */

#include <stdint.h>

#include "ts/conn.h"

#define MAX_PEERS 64
#define MAX_REGIONS 32
#define MAX_ENDPOINTS 8
#define MAX_DERP_CONNS 4
#define MTU 1280

/* The address magicsock stands in for a DERP region: 127.3.3.40, with the
   region in the port. A pong for a ping that came over DERP carries it. */
#define DERP_MAGIC_IP 0x7f030328u

struct endpoint {
    uint32_t ip;
    uint16_t port;
};

/* A WireGuard session in one direction pair: keys, indices, counters. */
struct wg_keypair {
    int valid;
    uint8_t send_key[32], recv_key[32];
    uint32_t local_index, remote_index;
    uint64_t send_counter;
    uint64_t recv_max;
    uint64_t recv_window;           /* bit i: recv_max - i has been seen */
    uint32_t created;
    int initiator;
    int confirmed;                  /* a responder may send only after the first packet */
};

struct wg_peer {
    /* Handshake in flight, as initiator. */
    uint32_t hs_index;
    uint8_t hs_eph_priv[32], hs_hash[32], hs_ck[32];
    uint32_t hs_sent, hs_started;
    int hs_pending;
    uint8_t last_timestamp[12];     /* TAI64N of the newest initiation seen */
    /* next is a session we answered as responder, held until the initiator
       proves it with a first packet; then it becomes current. */
    struct wg_keypair current, previous, next;
    uint32_t last_data_recv;
    uint32_t last_sent, last_recv;
};

struct peer {
    int64_t id;
    uint8_t node_key[32], disco_key[32];
    int has_disco;
    uint32_t ip;                    /* first IPv4 address, 0 if none */
    int derp_region;
    char name[64];
    int online;
    struct endpoint endpoints[MAX_ENDPOINTS];
    int endpoint_count;
    /* A direct UDP path, once a disco pong has come back over it. */
    struct endpoint direct;
    uint32_t direct_until;
    uint32_t last_disco_ping;
    uint8_t ping_txid[12];
    struct endpoint ping_to;
    struct wg_peer wg;
    /* ICMP echo sent from here, for the round trip. */
    uint32_t echo_sent;
    uint16_t echo_seq;
    int echo_rtt;
};

struct region {
    int id;
    char code[16];
    char host[128];
    uint16_t port;
    int insecure;
};

struct derp_conn;
struct control;

struct node {
    /* Configuration. */
    char control_host[128];
    uint16_t control_port;
    int control_tls;
    char auth_key[256];
    char hostname[64];
    int prefer_region;              /* 0: the lowest-numbered one */
    int no_udp;                     /* for testing the relay path on its own */
    int interactive;                /* wait for a login link to be opened */
    int ephemeral;                  /* control deletes the node soon after it goes offline */

    /* Keys. The machine key names this device to the control server, the
       node key is its WireGuard and DERP identity, the disco key is fresh
       every run as tailscaled's is. */
    uint8_t machine_priv[32], machine_pub[32];
    uint8_t node_priv[32], node_pub[32];
    uint8_t disco_priv[32], disco_pub[32];

    /* What control has told us. */
    int registered;
    int keys_saved;                 /* tunnel.key holds these keys */
    char auth_url[256];
    uint32_t ip;
    char domain[64];
    char suffix[96];                /* MagicDNS: example.ts.net., from the peers' names */
    int home_region;
    struct region regions[MAX_REGIONS];
    int region_count;
    struct peer peers[MAX_PEERS];
    int peer_count;
    int map_count;                  /* map responses seen, for the status line */

    struct control *control;
    struct derp_conn *derp[MAX_DERP_CONNS];
    int derp_wanted;                /* a region to connect to, asked for by a send */

    /* The UDP socket direct paths use. */
    int udp;
    uint16_t udp_port;
    uint32_t lan_ip;

    char status[96];
    uint32_t started;
    uint32_t control_retry;
};

/* The loop. */
int node_init(struct node *n);
void node_save_keys(struct node *n);
/* Closes every connection; the node can be initialised again after. */
void node_stop(struct node *n);
void node_step(struct node *n);

/* Looks up by node key, disco key, id or tailnet address. NULL if unknown. */
struct peer *peer_by_key(struct node *n, const uint8_t key[32]);
struct peer *peer_by_disco(struct node *n, const uint8_t key[32]);
struct peer *peer_by_id(struct node *n, int64_t id);
struct peer *peer_by_ip(struct node *n, uint32_t ip);
const struct region *region_by_id(struct node *n, int id);
int node_resolve(struct node *n, const char *host, uint32_t *ip);

/* control.c */
int control_start(struct node *n);
void control_poll(struct node *n);
void control_update_endpoints(struct node *n);
void control_stop(struct node *n);
int control_logout(struct node *n);

/* derp.c */
void derp_poll(struct node *n);
int derp_send(struct node *n, int region, const uint8_t dst[32], const void *pkt, int len);
int derp_connected(struct node *n);
void derp_stop(struct node *n);

/* How a packet from a peer reached us, so an answer can go back the same way. */
struct path {
    int region;                     /* DERP region, or 0 for UDP */
    struct endpoint ep;             /* UDP source when region is 0 */
};

/* magicsock, in node.c: whatever arrives over DERP or UDP, sorted into disco
   and WireGuard; and the way out to a peer, direct if a path is proven,
   relayed if not. */
void magic_recv(struct node *n, const uint8_t src_key[32], const struct path *via,
                uint8_t *pkt, int len);
int magic_send(struct node *n, struct peer *p, const void *pkt, int len);

/* disco.c */
void disco_recv(struct node *n, const struct path *via, const uint8_t *pkt, int len);
void disco_tick(struct node *n);

/* wg.c */
void wg_recv(struct node *n, struct peer *from, const struct path *via, uint8_t *pkt, int len);
int wg_send_ip(struct node *n, struct peer *p, const uint8_t *ip, int len);
void wg_tick(struct node *n);
/* Forgets what waits for handshakes, when the node stops. */
void wg_reset(void);

/* netstack.c */
void net_input(struct node *n, struct peer *from, uint8_t *ip, int len);
int net_ping(struct node *n, struct peer *p);

void key_string(char *out, const char *prefix, const uint8_t key[32]);
int key_parse(uint8_t key[32], const char *prefix, const char *s);
void ip_string(char *out, uint32_t ip);

#endif
