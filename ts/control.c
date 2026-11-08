/*
 * The coordination server: who we are, who else is in the tailnet, and how
 * to reach them. Everything here rides one TCP connection:
 *
 *   POST /ts2021, Upgrade: tailscale-control-protocol, the first Noise
 *   message in a header; 101, then the second, then Noise transport frames
 *   in both directions, and inside those plain HTTP/2 with the server on
 *   the other end of a Go http2.Server.
 *
 * Over HTTP/2 go two requests: /machine/register once, then /machine/map
 * with Stream set, whose response body never ends -- it is a sequence of
 * little-endian length-prefixed JSON MapResponses, the first with the whole
 * tailnet, the rest with what changed and keep-alives in between.
 *
 * The HTTP/2 here is the least that a Go server accepts: the preface, our
 * settings and an acknowledgement of its, window updates as the body is
 * read, pings answered. Header blocks from the server are not decoded past
 * the status: we set its header table to nothing, and a 200 then comes as
 * one static-table byte.
 *
 * Reference: tailscale.com/control/controlbase (the Noise framing),
 * control/controlhttp (the upgrade), control/controlclient (the requests).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

#include "ts/crypto.h"
#include "ts/node.h"
#include "ts/plat.h"

/* The capability version we claim. Headscale takes anything from 115 up,
   the control plane at Tailscale serves far older; 131 is a version whose
   map responses carry nothing this client would misread. */
#define CAPVER 131

#define NOISE_MAX_FRAME 4096
#define NOISE_MAX_PLAIN (NOISE_MAX_FRAME - 3 - TAG_LEN)
#define BODY_MAX (4 * 1024 * 1024)
/* The receive window we grant, per stream and for the connection. A full
   netmap for a small tailnet is tens of kilobytes; this lets the server send
   the first one without waiting on us, and window updates keep it open. */
#define WINDOW (1 << 20)
#define WATCHDOG_MS 150000

enum { H2_DATA = 0, H2_HEADERS = 1, H2_RST = 3, H2_SETTINGS = 4, H2_PING = 6,
       H2_GOAWAY = 7, H2_WINDOW = 8 };
enum { F_END_STREAM = 1, F_ACK = 1, F_END_HEADERS = 4, F_PADDED = 8 };

struct buf {
    uint8_t *p;
    size_t len, cap;
};

struct control {
    conn *c;
    uint8_t tx_key[32], rx_key[32];
    uint64_t tx_nonce, rx_nonce;
    struct buf raw;                 /* bytes off the wire, short of a whole frame */
    struct buf h2;                  /* decrypted HTTP/2, short of a whole frame */
    int early_checked;
    uint32_t next_stream;
    /* The one request in flight besides the map. */
    uint32_t req_stream;
    int req_status, req_done;
    struct buf body;
    uint32_t map_stream;
    struct buf map;
    size_t unacked_conn, unacked_map;
    uint32_t last_rx;
    int dead;
};

static int buf_add(struct buf *b, const void *p, size_t n) {
    if (b->len + n > b->cap) {
        size_t cap = b->cap ? b->cap : 4096;
        while (cap < b->len + n) cap *= 2;
        if (cap > BODY_MAX + 65536) return -1;
        uint8_t *np = realloc(b->p, cap);
        if (!np) return -1;
        b->p = np;
        b->cap = cap;
    }
    memcpy(b->p + b->len, p, n);
    b->len += n;
    return 0;
}

static void buf_drop(struct buf *b, size_t n) {
    memmove(b->p, b->p + n, b->len - n);
    b->len -= n;
}

static void buf_free(struct buf *b) {
    free(b->p);
    memset(b, 0, sizeof(*b));
}

static uint16_t be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t be24(const uint8_t *p) { return (uint32_t)p[0] << 16 | (uint32_t)p[1] << 8 | p[2]; }
static uint32_t be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

/* ---------------------------------------------------------------- noise */

static void mix_hash(uint8_t h[32], const void *data, size_t len) {
    blake2s_ctx ctx;
    blake2s_init(&ctx, 32, NULL, 0);
    blake2s_update(&ctx, h, 32);
    blake2s_update(&ctx, data, len);
    blake2s_final(&ctx, h);
}

/* Control's nonce is big-endian in the last eight bytes -- WireGuard's is
   little-endian. Both are Noise; they differ exactly here. */
static void nonce_be(uint8_t out[12], uint64_t n) {
    memset(out, 0, 4);
    for (int i = 0; i < 8; i++) out[4 + i] = (uint8_t)(n >> (56 - 8 * i));
}

struct handshake {
    uint8_t h[32], ck[32], eph_priv[32], eph_pub[32];
};

/* The initiation, 101 bytes: version, type 1, length 96, then e, the
   encrypted static key and an empty payload's tag. */
static void noise_initiation(struct node *n, const uint8_t server[32],
                             struct handshake *hs, uint8_t msg[101]) {
    static const char name[] = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
    uint8_t dh[32], k[32], zero[12] = { 0 };
    char prologue[48];
    blake2s(hs->h, 32, NULL, 0, name, strlen(name));
    memcpy(hs->ck, hs->h, 32);
    int plen = snprintf(prologue, sizeof(prologue), "Tailscale Control Protocol v%d", CAPVER);
    mix_hash(hs->h, prologue, (size_t)plen);
    mix_hash(hs->h, server, 32);

    msg[0] = CAPVER >> 8;
    msg[1] = CAPVER & 0xff;
    msg[2] = 1;
    msg[3] = 0;
    msg[4] = 96;
    x25519_keygen(hs->eph_priv, hs->eph_pub);
    memcpy(msg + 5, hs->eph_pub, 32);
    mix_hash(hs->h, hs->eph_pub, 32);

    x25519(dh, hs->eph_priv, server);                        /* es */
    hkdf(hs->ck, k, NULL, hs->ck, dh, 32);
    aead_seal(msg + 37, k, zero, n->machine_pub, 32, hs->h, 32);
    mix_hash(hs->h, msg + 37, 48);

    x25519(dh, n->machine_priv, server);                     /* ss */
    hkdf(hs->ck, k, NULL, hs->ck, dh, 32);
    aead_seal(msg + 85, k, zero, NULL, 0, hs->h, 32);
    mix_hash(hs->h, msg + 85, 16);
}

/* The response's 48 bytes: e and an empty payload's tag. */
static int noise_response(struct node *n, struct control *ct, struct handshake *hs,
                          const uint8_t resp[48]) {
    uint8_t dh[32], k[32], zero[12] = { 0 };
    mix_hash(hs->h, resp, 32);
    x25519(dh, hs->eph_priv, resp);                          /* ee */
    hkdf(hs->ck, k, NULL, hs->ck, dh, 32);
    x25519(dh, n->machine_priv, resp);                       /* se */
    hkdf(hs->ck, k, NULL, hs->ck, dh, 32);
    if (aead_open(NULL, k, zero, resp + 32, 16, hs->h, 32) < 0) return -1;
    hkdf(ct->tx_key, ct->rx_key, NULL, hs->ck, NULL, 0);
    ct->tx_nonce = ct->rx_nonce = 0;
    return 0;
}

/* Plaintext out as as many transport frames as it takes. */
static int noise_write(struct control *ct, const uint8_t *data, size_t len) {
    uint8_t frame[NOISE_MAX_FRAME], nonce[12];
    while (len > 0) {
        size_t n = len < NOISE_MAX_PLAIN ? len : NOISE_MAX_PLAIN;
        size_t clen = n + TAG_LEN;
        frame[0] = 4;
        frame[1] = (uint8_t)(clen >> 8);
        frame[2] = (uint8_t)clen;
        nonce_be(nonce, ct->tx_nonce++);
        aead_seal(frame + 3, ct->tx_key, nonce, data, n, NULL, 0);
        if (conn_write(ct->c, frame, 3 + clen) < 0) return -1;
        data += n;
        len -= n;
    }
    return 0;
}

/* --------------------------------------------------------------- http/2 */

static void h2_header(uint8_t *out, uint32_t len, uint8_t type, uint8_t flags, uint32_t stream) {
    out[0] = (uint8_t)(len >> 16); out[1] = (uint8_t)(len >> 8); out[2] = (uint8_t)len;
    out[3] = type;
    out[4] = flags;
    out[5] = (uint8_t)(stream >> 24); out[6] = (uint8_t)(stream >> 16);
    out[7] = (uint8_t)(stream >> 8);  out[8] = (uint8_t)stream;
}

static int h2_window(struct control *ct, uint32_t stream, uint32_t inc) {
    uint8_t f[13];
    h2_header(f, 4, H2_WINDOW, 0, stream);
    f[9] = (uint8_t)(inc >> 24); f[10] = (uint8_t)(inc >> 16);
    f[11] = (uint8_t)(inc >> 8); f[12] = (uint8_t)inc;
    return noise_write(ct, f, sizeof(f));
}

static int h2_start(struct control *ct) {
    static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    uint8_t out[64];
    size_t o = 0;
    memcpy(out, preface, 24);
    o = 24;
    /* HEADER_TABLE_SIZE 0, ENABLE_PUSH 0, INITIAL_WINDOW_SIZE. */
    static const uint8_t settings[] = {
        0, 1, 0, 0, 0, 0,
        0, 2, 0, 0, 0, 0,
        0, 4, (WINDOW >> 24) & 0xff, (WINDOW >> 16) & 0xff, (WINDOW >> 8) & 0xff, WINDOW & 0xff,
    };
    h2_header(out + o, sizeof(settings), H2_SETTINGS, 0, 0);
    o += 9;
    memcpy(out + o, settings, sizeof(settings));
    o += sizeof(settings);
    if (noise_write(ct, out, o) < 0) return -1;
    return h2_window(ct, 0, WINDOW - 65535);
}

/* A string literal: length, then the bytes. No Huffman; every value here is
   short enough for a one-byte length. */
static size_t hpack_string(uint8_t *out, const char *value) {
    size_t len = strlen(value);
    out[0] = (uint8_t)len;
    memcpy(out + 1, value, len);
    return 1 + len;
}

/* POST path with a JSON body, on a new stream. Returns the stream id. */
static uint32_t h2_post(struct node *n, struct control *ct, const char *path, const char *json) {
    uint32_t stream = ct->next_stream;
    ct->next_stream += 2;
    uint8_t hb[256];
    size_t o = 0;
    hb[o++] = 0x83;                                  /* :method POST */
    hb[o++] = 0x86;                                  /* :scheme http */
    /* Literals without indexing, the name from the static table. */
    hb[o++] = 0x04;                                  /* :path */
    o += hpack_string(hb + o, path);
    hb[o++] = 0x01;                                  /* :authority */
    o += hpack_string(hb + o, n->control_host);
    hb[o++] = 0x0f; hb[o++] = 0x10;                  /* content-type, index 31 */
    o += hpack_string(hb + o, "application/json");

    size_t jlen = strlen(json);
    uint8_t *f = malloc(9 + o + jlen + 9 * (jlen / 16384 + 1));
    if (!f) return 0;
    size_t fo = 0;
    h2_header(f, (uint32_t)o, H2_HEADERS, F_END_HEADERS, stream);
    memcpy(f + 9, hb, o);
    fo = 9 + o;
    size_t sent = 0;
    do {
        size_t chunk = jlen - sent > 16384 ? 16384 : jlen - sent;
        int last = sent + chunk == jlen;
        h2_header(f + fo, (uint32_t)chunk, H2_DATA, last ? F_END_STREAM : 0, stream);
        memcpy(f + fo + 9, json + sent, chunk);
        fo += 9 + chunk;
        sent += chunk;
    } while (sent < jlen);
    int rc = noise_write(ct, f, fo);
    free(f);
    return rc < 0 ? 0 : stream;
}

/* The status out of a header block encoded against an empty dynamic table:
   a size update or two, then :status from the static table if it is one of
   the seven there. Anything else is reported as unknown, which callers
   treat as failure -- the body usually says why. */
static int h2_status(const uint8_t *p, size_t len) {
    static const int statics[] = { 200, 204, 206, 304, 400, 404, 500 };
    size_t i = 0;
    while (i < len && (p[i] & 0xe0) == 0x20) i++;
    if (i < len && p[i] >= 0x88 && p[i] <= 0x8e) return statics[p[i] - 0x88];
    return -1;
}

static void handle_map_bytes(struct node *n, struct control *ct);

static int h2_frame(struct node *n, struct control *ct, uint8_t type, uint8_t flags,
                    uint32_t stream, const uint8_t *p, size_t len) {
    switch (type) {
    case H2_SETTINGS:
        if (!(flags & F_ACK)) {
            uint8_t ack[9];
            h2_header(ack, 0, H2_SETTINGS, F_ACK, 0);
            return noise_write(ct, ack, 9);
        }
        return 0;
    case H2_PING:
        if (!(flags & F_ACK) && len == 8) {
            uint8_t pong[17];
            h2_header(pong, 8, H2_PING, F_ACK, 0);
            memcpy(pong + 9, p, 8);
            return noise_write(ct, pong, 17);
        }
        return 0;
    case H2_GOAWAY:
        plat_log("control: server sent GOAWAY");
        ct->dead = 1;
        return 0;
    case H2_RST:
        plat_log("control: stream %u reset", (unsigned)stream);
        if (stream == ct->req_stream) ct->req_done = 1;
        if (stream == ct->map_stream) ct->dead = 1;
        return 0;
    case H2_HEADERS:
        if (stream == ct->req_stream) {
            ct->req_status = h2_status(p, len);
            if (flags & F_END_STREAM) ct->req_done = 1;
        } else if (stream == ct->map_stream) {
            int st = h2_status(p, len);
            if (st != 200) plat_log("control: map answered %d", st);
            if (flags & F_END_STREAM) ct->dead = 1;
        }
        return 0;
    case H2_DATA: {
        size_t full = len;
        if ((flags & F_PADDED) && len > 0) {
            size_t pad = p[0];
            if (pad + 1 > len) return -1;
            p++;
            len -= pad + 1;
        }
        ct->unacked_conn += full;
        if (stream == ct->req_stream) {
            if (buf_add(&ct->body, p, len) < 0) return -1;
            if (flags & F_END_STREAM) ct->req_done = 1;
        } else if (stream == ct->map_stream) {
            if (buf_add(&ct->map, p, len) < 0) return -1;
            ct->unacked_map += full;
            handle_map_bytes(n, ct);
            if (flags & F_END_STREAM) ct->dead = 1;
        }
        /* Give back what was read once a quarter of the window is spent. */
        if (ct->unacked_conn >= WINDOW / 4) {
            if (h2_window(ct, 0, (uint32_t)ct->unacked_conn) < 0) return -1;
            ct->unacked_conn = 0;
        }
        if (ct->unacked_map >= WINDOW / 4) {
            if (h2_window(ct, ct->map_stream, (uint32_t)ct->unacked_map) < 0) return -1;
            ct->unacked_map = 0;
        }
        return 0;
    }
    default:
        return 0;
    }
}

/* Everything readable off the socket, through Noise, into HTTP/2 frames. */
static int pump(struct node *n, struct control *ct) {
    uint8_t tmp[8192];
    for (;;) {
        int got = conn_read(ct->c, tmp, sizeof(tmp));
        if (got < 0) return -1;
        if (got == 0) break;
        if (buf_add(&ct->raw, tmp, (size_t)got) < 0) return -1;
        ct->last_rx = plat_ms();
    }
    while (ct->raw.len >= 3) {
        size_t clen = be16(ct->raw.p + 1);
        if (ct->raw.len < 3 + clen) break;
        if (ct->raw.p[0] != 4 || clen < TAG_LEN) {
            plat_log("control: unexpected noise frame type %d", ct->raw.p[0]);
            return -1;
        }
        uint8_t nonce[12], plain[NOISE_MAX_FRAME];
        nonce_be(nonce, ct->rx_nonce++);
        if (aead_open(plain, ct->rx_key, nonce, ct->raw.p + 3, clen, NULL, 0) < 0) {
            plat_log("control: noise frame failed to authenticate");
            return -1;
        }
        if (buf_add(&ct->h2, plain, clen - TAG_LEN) < 0) return -1;
        buf_drop(&ct->raw, 3 + clen);
    }
    /* Before the server's first HTTP/2 frame it may put the early payload:
       five magic bytes, a big-endian length and that much JSON, the same
       nine bytes a frame header would take. Nothing in it is needed. */
    if (!ct->early_checked && ct->h2.len >= 9) {
        if (memcmp(ct->h2.p, "\xff\xff\xffTS", 5) == 0) {
            size_t elen = be32(ct->h2.p + 5);
            if (ct->h2.len < 9 + elen) return 0;
            buf_drop(&ct->h2, 9 + elen);
        }
        ct->early_checked = 1;
    }
    if (!ct->early_checked) return 0;
    while (ct->h2.len >= 9) {
        uint32_t flen = be24(ct->h2.p);
        if (ct->h2.len < 9 + flen) break;
        uint8_t type = ct->h2.p[3], flags = ct->h2.p[4];
        uint32_t stream = be32(ct->h2.p + 5) & 0x7fffffff;
        if (h2_frame(n, ct, type, flags, stream, ct->h2.p + 9, flen) < 0) return -1;
        buf_drop(&ct->h2, 9 + flen);
    }
    return 0;
}

/* Waits for the request in flight to finish, pumping the connection --
   and so the map stream, if one is open -- meanwhile. */
static int wait_request(struct node *n, struct control *ct, unsigned timeout_ms) {
    uint32_t start = plat_ms();
    while (!ct->req_done) {
        if (pump(n, ct) < 0 || ct->dead) return -1;
        if (plat_ms() - start > timeout_ms) return -1;
        plat_sleep_ms(2);
    }
    return 0;
}

/* ------------------------------------------------------------- requests */

void key_string(char *out, const char *prefix, const uint8_t key[32]) {
    size_t pl = strlen(prefix);
    memcpy(out, prefix, pl);
    hex_encode(out + pl, key, 32);
}

int key_parse(uint8_t key[32], const char *prefix, const char *s) {
    size_t pl = strlen(prefix);
    if (!s || strncmp(s, prefix, pl) != 0 || strlen(s) != pl + 64) return -1;
    return hex_decode(key, 32, s + pl);
}

void ip_string(char *out, uint32_t ip) {
    /* The casts are for the PSP, where uint32_t is a long. */
    sprintf(out, "%u.%u.%u.%u", (unsigned)(ip >> 24), (unsigned)(ip >> 16) & 255,
            (unsigned)(ip >> 8) & 255, (unsigned)ip & 255);
}

static cJSON *hostinfo(struct node *n) {
    cJSON *h = cJSON_CreateObject();
    cJSON_AddStringToObject(h, "IPNVersion", "pspkit-tunnel");
    cJSON_AddStringToObject(h, "Hostname", n->hostname);
    cJSON_AddStringToObject(h, "OS", "linux");
    cJSON_AddStringToObject(h, "OSVersion", "PSP");
    cJSON_AddStringToObject(h, "GoArch", "mipsle");
    cJSON_AddStringToObject(h, "DeviceModel", "PlayStation Portable");
    if (n->home_region) {
        cJSON *ni = cJSON_AddObjectToObject(h, "NetInfo");
        cJSON_AddNumberToObject(ni, "PreferredDERP", n->home_region);
        cJSON_AddBoolToObject(ni, "WorkingUDP", n->udp >= 0);
    }
    return h;
}

static void add_keys(struct node *n, cJSON *req) {
    char key[80];
    cJSON_AddNumberToObject(req, "Version", CAPVER);
    key_string(key, "nodekey:", n->node_pub);
    cJSON_AddStringToObject(req, "NodeKey", key);
}

static char *print_and_free(cJSON *j) {
    char *s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    return s;
}

static cJSON *finish_json(struct control *ct) {
    buf_add(&ct->body, "", 1);
    cJSON *j = cJSON_Parse((char *)ct->body.p);
    if (!j) plat_log("control: unparseable reply (%d): %.60s", ct->req_status, ct->body.p);
    return j;
}

static int request(struct node *n, struct control *ct, const char *path, char *json,
                   unsigned timeout_ms) {
    ct->body.len = 0;
    ct->req_done = 0;
    ct->req_status = -1;
    ct->req_stream = h2_post(n, ct, path, json);
    free(json);
    if (!ct->req_stream) return -1;
    return wait_request(n, ct, timeout_ms);
}

/* Registration, and the interactive half when there is no key: the reply
   then carries an AuthURL, which somebody opens on another device, and a
   follow-up request that the server holds until they have. */
static int do_register(struct node *n, struct control *ct) {
    char followup[256] = "";
    for (int round = 0; round < 3; round++) {
        cJSON *req = cJSON_CreateObject();
        add_keys(n, req);
        if (n->auth_key[0] && !followup[0]) {
            cJSON *auth = cJSON_AddObjectToObject(req, "Auth");
            cJSON_AddStringToObject(auth, "AuthKey", n->auth_key);
        }
        if (followup[0]) cJSON_AddStringToObject(req, "Followup", followup);
        if (n->ephemeral) cJSON_AddBoolToObject(req, "Ephemeral", 1);
        cJSON_AddItemToObject(req, "Hostinfo", hostinfo(n));
        unsigned timeout = followup[0] ? 15 * 60 * 1000 : 30000;
        if (request(n, ct, "/machine/register", print_and_free(req), timeout) < 0) {
            plat_log("control: register got no answer");
            return -1;
        }
        cJSON *resp = finish_json(ct);
        if (!resp) return -1;
        const cJSON *err = cJSON_GetObjectItem(resp, "Error");
        const cJSON *authorized = cJSON_GetObjectItem(resp, "MachineAuthorized");
        const cJSON *url = cJSON_GetObjectItem(resp, "AuthURL");
        if (cJSON_IsString(err) && err->valuestring[0]) {
            plat_log("control: register refused: %s", err->valuestring);
            snprintf(n->status, sizeof(n->status), "refused: %.80s", err->valuestring);
            cJSON_Delete(resp);
            return -1;
        }
        if (cJSON_IsTrue(authorized)) {
            cJSON_Delete(resp);
            n->registered = 1;
            node_save_keys(n);
            n->auth_url[0] = '\0';
            return 0;
        }
        if (cJSON_IsString(url) && url->valuestring[0] && !n->interactive) {
            /* Nobody here to open a link: the key is what is missing. */
            snprintf(n->auth_url, sizeof(n->auth_url), "%s", url->valuestring);
            snprintf(n->status, sizeof(n->status), "not in the tailnet: needs an auth key");
            plat_log("control: not registered, and no auth key");
            cJSON_Delete(resp);
            return -1;
        }
        if (cJSON_IsString(url) && url->valuestring[0]) {
            snprintf(n->auth_url, sizeof(n->auth_url), "%s", url->valuestring);
            snprintf(followup, sizeof(followup), "%s", url->valuestring);
            plat_log("control: log in at %s", n->auth_url);
            snprintf(n->status, sizeof(n->status), "waiting for login");
        }
        cJSON_Delete(resp);
    }
    return -1;
}

static int map_request(struct node *n, struct control *ct, int stream) {
    cJSON *req = cJSON_CreateObject();
    char key[80];
    add_keys(n, req);
    key_string(key, "discokey:", n->disco_pub);
    cJSON_AddStringToObject(req, "DiscoKey", key);
    if (stream) {
        cJSON_AddBoolToObject(req, "Stream", 1);
        cJSON_AddBoolToObject(req, "KeepAlive", 1);
    } else {
        cJSON_AddBoolToObject(req, "OmitPeers", 1);
    }
    cJSON_AddItemToObject(req, "Hostinfo", hostinfo(n));
    if (n->udp >= 0 && n->lan_ip) {
        char ep[32], ip[16];
        ip_string(ip, n->lan_ip);
        snprintf(ep, sizeof(ep), "%s:%u", ip, n->udp_port);
        cJSON *eps = cJSON_AddArrayToObject(req, "Endpoints");
        cJSON_AddItemToArray(eps, cJSON_CreateString(ep));
        cJSON *types = cJSON_AddArrayToObject(req, "EndpointTypes");
        cJSON_AddItemToArray(types, cJSON_CreateNumber(1));     /* local */
    }
    char *json = print_and_free(req);
    if (!stream) return request(n, ct, "/machine/map", json, 30000);
    ct->map.len = 0;
    ct->map_stream = h2_post(n, ct, "/machine/map", json);
    free(json);
    return ct->map_stream ? 0 : -1;
}

/* ------------------------------------------------------------------ map */

static uint32_t parse_ip4(const char *s) {
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 || a > 255 || b > 255 || c > 255 || d > 255)
        return 0;
    return a << 24 | b << 16 | c << 8 | d;
}

static int parse_endpoint(const char *s, struct endpoint *ep) {
    unsigned a, b, c, d, port;
    if (s[0] == '[') return -1;                      /* IPv6: not on a PSP */
    if (sscanf(s, "%u.%u.%u.%u:%u", &a, &b, &c, &d, &port) != 5 || port > 65535) return -1;
    ep->ip = a << 24 | b << 16 | c << 8 | d;
    ep->port = (uint16_t)port;
    return 0;
}

static int home_derp(const cJSON *node) {
    const cJSON *h = cJSON_GetObjectItem(node, "HomeDERP");
    if (cJSON_IsNumber(h) && h->valueint > 0) return h->valueint;
    const cJSON *d = cJSON_GetObjectItem(node, "DERP");
    unsigned r;
    if (cJSON_IsString(d) && sscanf(d->valuestring, "127.3.3.40:%u", &r) == 1) return (int)r;
    return 0;
}

static void read_endpoints(struct peer *p, const cJSON *eps) {
    p->endpoint_count = 0;
    const cJSON *e;
    cJSON_ArrayForEach(e, eps) {
        if (p->endpoint_count >= MAX_ENDPOINTS) break;
        if (cJSON_IsString(e) && parse_endpoint(e->valuestring, &p->endpoints[p->endpoint_count]) == 0)
            p->endpoint_count++;
    }
}

static void upsert_peer(struct node *n, const cJSON *pn) {
    const cJSON *id = cJSON_GetObjectItem(pn, "ID");
    const cJSON *key = cJSON_GetObjectItem(pn, "Key");
    uint8_t k[32];
    if (!cJSON_IsNumber(id) || !cJSON_IsString(key) || key_parse(k, "nodekey:", key->valuestring) < 0)
        return;
    struct peer *p = peer_by_id(n, (int64_t)id->valuedouble);
    if (!p) {
        if (n->peer_count >= MAX_PEERS) return;
        p = &n->peers[n->peer_count++];
        memset(p, 0, sizeof(*p));
        p->id = (int64_t)id->valuedouble;
    }
    if (memcmp(p->node_key, k, 32) != 0) {
        /* A new node key is a new WireGuard identity: nothing carries over. */
        memset(&p->wg, 0, sizeof(p->wg));
        memcpy(p->node_key, k, 32);
    }
    const cJSON *disco = cJSON_GetObjectItem(pn, "DiscoKey");
    p->has_disco = cJSON_IsString(disco) && key_parse(p->disco_key, "discokey:", disco->valuestring) == 0;
    const cJSON *name = cJSON_GetObjectItem(pn, "Name");
    if (cJSON_IsString(name)) {
        snprintf(p->name, sizeof(p->name), "%s", name->valuestring);
        char *dot = strchr(p->name, '.');
        if (dot) {
            /* jellyhop.example.ts.net. -- what follows the short name is
               the tailnet's MagicDNS suffix, the same for every peer. */
            if (!n->suffix[0]) snprintf(n->suffix, sizeof(n->suffix), "%s", dot + 1);
            *dot = '\0';
        }
    }
    p->ip = 0;
    const cJSON *a;
    cJSON_ArrayForEach(a, cJSON_GetObjectItem(pn, "Addresses")) {
        if (cJSON_IsString(a) && !p->ip) p->ip = parse_ip4(a->valuestring);
    }
    int region = home_derp(pn);
    if (region) p->derp_region = region;
    const cJSON *online = cJSON_GetObjectItem(pn, "Online");
    p->online = cJSON_IsTrue(online);
    read_endpoints(p, cJSON_GetObjectItem(pn, "Endpoints"));
}

static void remove_peer(struct node *n, int64_t id) {
    for (int i = 0; i < n->peer_count; i++) {
        if (n->peers[i].id != id) continue;
        n->peers[i] = n->peers[--n->peer_count];
        return;
    }
}

static void read_derp_map(struct node *n, const cJSON *dm) {
    const cJSON *regions = cJSON_GetObjectItem(dm, "Regions");
    const cJSON *r;
    n->region_count = 0;
    cJSON_ArrayForEach(r, regions) {
        if (n->region_count >= MAX_REGIONS) break;
        const cJSON *nodes = cJSON_GetObjectItem(r, "Nodes");
        const cJSON *first = NULL, *nd;
        cJSON_ArrayForEach(nd, nodes) {
            if (!cJSON_IsTrue(cJSON_GetObjectItem(nd, "STUNOnly"))) { first = nd; break; }
        }
        if (!first) continue;
        struct region *g = &n->regions[n->region_count++];
        memset(g, 0, sizeof(*g));
        g->id = cJSON_GetObjectItem(r, "RegionID") ? cJSON_GetObjectItem(r, "RegionID")->valueint : 0;
        const cJSON *code = cJSON_GetObjectItem(r, "RegionCode");
        if (cJSON_IsString(code)) snprintf(g->code, sizeof(g->code), "%s", code->valuestring);
        const cJSON *host = cJSON_GetObjectItem(first, "HostName");
        if (cJSON_IsString(host)) snprintf(g->host, sizeof(g->host), "%s", host->valuestring);
        const cJSON *port = cJSON_GetObjectItem(first, "DERPPort");
        g->port = cJSON_IsNumber(port) && port->valueint > 0 ? (uint16_t)port->valueint : 443;
        g->insecure = cJSON_IsTrue(cJSON_GetObjectItem(first, "InsecureForTests"));
    }
}

static void apply_map(struct node *n, const cJSON *m) {
    const cJSON *self = cJSON_GetObjectItem(m, "Node");
    if (self) {
        const cJSON *a;
        cJSON_ArrayForEach(a, cJSON_GetObjectItem(self, "Addresses")) {
            uint32_t ip = cJSON_IsString(a) ? parse_ip4(a->valuestring) : 0;
            if (ip) { n->ip = ip; break; }
        }
    }
    const cJSON *dm = cJSON_GetObjectItem(m, "DERPMap");
    if (dm) read_derp_map(n, dm);
    const cJSON *domain = cJSON_GetObjectItem(m, "Domain");
    if (cJSON_IsString(domain)) snprintf(n->domain, sizeof(n->domain), "%s", domain->valuestring);

    const cJSON *peers = cJSON_GetObjectItem(m, "Peers"), *p;
    if (cJSON_IsArray(peers)) {
        /* A full list: whoever is not in it is gone. */
        for (int i = 0; i < n->peer_count; ) {
            int found = 0;
            cJSON_ArrayForEach(p, peers) {
                const cJSON *id = cJSON_GetObjectItem(p, "ID");
                if (cJSON_IsNumber(id) && (int64_t)id->valuedouble == n->peers[i].id) found = 1;
            }
            if (found) i++;
            else n->peers[i] = n->peers[--n->peer_count];
        }
        cJSON_ArrayForEach(p, peers) upsert_peer(n, p);
    }
    cJSON_ArrayForEach(p, cJSON_GetObjectItem(m, "PeersChanged")) upsert_peer(n, p);
    cJSON_ArrayForEach(p, cJSON_GetObjectItem(m, "PeersRemoved")) {
        if (cJSON_IsNumber(p)) remove_peer(n, (int64_t)p->valuedouble);
    }
    cJSON_ArrayForEach(p, cJSON_GetObjectItem(m, "PeersChangedPatch")) {
        const cJSON *id = cJSON_GetObjectItem(p, "NodeID");
        struct peer *peer = cJSON_IsNumber(id) ? peer_by_id(n, (int64_t)id->valuedouble) : NULL;
        if (!peer) continue;
        const cJSON *region = cJSON_GetObjectItem(p, "DERPRegion");
        if (cJSON_IsNumber(region) && region->valueint > 0) peer->derp_region = region->valueint;
        const cJSON *eps = cJSON_GetObjectItem(p, "Endpoints");
        if (eps) read_endpoints(peer, eps);
        const cJSON *disco = cJSON_GetObjectItem(p, "DiscoKey");
        if (cJSON_IsString(disco))
            peer->has_disco = key_parse(peer->disco_key, "discokey:", disco->valuestring) == 0;
        const cJSON *online = cJSON_GetObjectItem(p, "Online");
        if (cJSON_IsBool(online)) peer->online = cJSON_IsTrue(online);
    }
    const cJSON *oc = cJSON_GetObjectItem(m, "OnlineChange");
    cJSON_ArrayForEach(p, oc) {
        struct peer *peer = peer_by_id(n, strtoll(p->string, NULL, 10));
        if (peer) peer->online = cJSON_IsTrue(p);
    }
    n->map_count++;
}

static void handle_map_bytes(struct node *n, struct control *ct) {
    while (ct->map.len >= 4) {
        uint32_t len = (uint32_t)ct->map.p[0] | (uint32_t)ct->map.p[1] << 8 |
                       (uint32_t)ct->map.p[2] << 16 | (uint32_t)ct->map.p[3] << 24;
        if (len > BODY_MAX) { ct->dead = 1; return; }
        if (ct->map.len < 4 + (size_t)len) return;
        cJSON *m = cJSON_ParseWithLength((const char *)ct->map.p + 4, len);
        if (m) {
            if (!cJSON_IsTrue(cJSON_GetObjectItem(m, "KeepAlive")) || cJSON_GetArraySize(m) > 1)
                apply_map(n, m);
            cJSON_Delete(m);
        } else {
            plat_log("control: map response of %u bytes did not parse", (unsigned)len);
        }
        buf_drop(&ct->map, 4 + len);
    }
}

/* ------------------------------------------------------------- lifecycle */

/* The server's Noise key, from GET /key: the one thing asked outside Noise,
   and the only answer that has to be taken on the transport's word. */
static int fetch_server_key(struct node *n, uint8_t key[32]) {
    plat_log("control: %s:%u over %s", n->control_host, n->control_port,
             n->control_tls ? "tls" : "plain tcp");
    conn *c = conn_open(n->control_host, n->control_port, n->control_tls);
    if (!c) return -1;
    char req[256], head[2048];
    int len = snprintf(req, sizeof(req),
                       "GET /key?v=%d HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
                       CAPVER, n->control_host);
    int status = conn_write(c, req, (size_t)len) < 0 ? -1
               : conn_read_head(c, head, sizeof(head), 10000);
    char body[1024];
    size_t have = 0;
    uint32_t start = plat_ms();
    while (status == 200 && have < sizeof(body) - 1 && plat_ms() - start < 10000) {
        int got = conn_read(c, body + have, sizeof(body) - 1 - have);
        if (got < 0) break;
        if (got == 0) { plat_sleep_ms(2); continue; }
        have += (size_t)got;
        body[have] = '\0';
        if (strchr(body, '}')) break;
    }
    body[have] = '\0';
    conn_close(c);
    if (status != 200) {
        plat_log("control: GET /key answered %d", status);
        return -1;
    }
    cJSON *j = cJSON_Parse(body);
    const cJSON *pk = j ? cJSON_GetObjectItem(j, "publicKey") : NULL;
    int rc = cJSON_IsString(pk) ? key_parse(key, "mkey:", pk->valuestring) : -1;
    cJSON_Delete(j);
    if (rc < 0) plat_log("control: no key in %.60s", body);
    return rc;
}

static void control_free(struct control *ct) {
    if (!ct) return;
    conn_close(ct->c);
    buf_free(&ct->raw);
    buf_free(&ct->h2);
    buf_free(&ct->body);
    buf_free(&ct->map);
    free(ct);
}

/* What tailscale logout does: the node key registered again with an expiry
   in the past, which the server takes as this device leaving. Only when no
   other request is in flight on the connection. */
int control_logout(struct node *n) {
    struct control *ct = n->control;
    if (!ct || ct->dead || (ct->req_stream && !ct->req_done)) return -1;
    cJSON *req = cJSON_CreateObject();
    add_keys(n, req);
    cJSON_AddStringToObject(req, "Expiry", "1970-01-01T00:02:03Z");
    cJSON_AddItemToObject(req, "Hostinfo", hostinfo(n));
    if (request(n, ct, "/machine/register", print_and_free(req), 15000) < 0) return -1;
    cJSON *resp = finish_json(ct);
    if (!resp) return -1;
    const cJSON *expired = cJSON_GetObjectItem(resp, "NodeKeyExpired");
    int ok = ct->req_status == 200 && (!expired || cJSON_IsTrue(expired));
    cJSON_Delete(resp);
    plat_log("control: logged out%s", ok ? "" : " (not confirmed)");
    return ok ? 0 : -1;
}

void control_stop(struct node *n) {
    control_free(n->control);
    n->control = NULL;
}

int control_start(struct node *n) {
    uint8_t server[32];
    snprintf(n->status, sizeof(n->status), "fetching server key");
    if (fetch_server_key(n, server) < 0) {
        snprintf(n->status, sizeof(n->status), "control server unreachable");
        return -1;
    }
    struct control *ct = calloc(1, sizeof(*ct));
    if (!ct) return -1;
    ct->next_stream = 1;
    snprintf(n->status, sizeof(n->status), "noise handshake");
    ct->c = conn_open(n->control_host, n->control_port, n->control_tls);
    if (!ct->c) { control_free(ct); return -1; }

    struct handshake hs;
    uint8_t init[101];
    char b64[160], req[512], head[2048];
    noise_initiation(n, server, &hs, init);
    base64_encode(b64, init, sizeof(init));
    int len = snprintf(req, sizeof(req),
                       "POST /ts2021 HTTP/1.1\r\nHost: %s\r\nUpgrade: tailscale-control-protocol\r\n"
                       "Connection: upgrade\r\nX-Tailscale-Handshake: %s\r\nContent-Length: 0\r\n\r\n",
                       n->control_host, b64);
    int status = conn_write(ct->c, req, (size_t)len) < 0 ? -1
               : conn_read_head(ct->c, head, sizeof(head), 15000);
    if (status != 101) {
        plat_log("control: upgrade answered %d", status);
        control_free(ct);
        return -1;
    }
    /* The response message: type 2, length 48, then the payload. */
    uint8_t resp[51];
    size_t have = 0;
    uint32_t start = plat_ms();
    while (have < sizeof(resp)) {
        int got = conn_read(ct->c, resp + have, sizeof(resp) - have);
        if (got < 0 || plat_ms() - start > 15000) { control_free(ct); return -1; }
        if (got == 0) { plat_sleep_ms(2); continue; }
        have += (size_t)got;
    }
    if (resp[0] != 2 || be16(resp + 1) != 48 || noise_response(n, ct, &hs, resp + 3) < 0) {
        plat_log("control: noise handshake failed (type %d)", resp[0]);
        control_free(ct);
        return -1;
    }
    ct->last_rx = plat_ms();
    if (h2_start(ct) < 0) { control_free(ct); return -1; }
    plat_log("control: noise and http/2 up with %s", n->control_host);

    snprintf(n->status, sizeof(n->status), "registering");
    n->control = ct;
    if (do_register(n, ct) < 0) {
        n->control = NULL;
        control_free(ct);
        return -1;
    }
    plat_log("control: registered as %s", n->hostname);
    snprintf(n->status, sizeof(n->status), "fetching the tailnet");
    if (map_request(n, ct, 1) < 0) {
        n->control = NULL;
        control_free(ct);
        return -1;
    }
    return 0;
}

void control_update_endpoints(struct node *n) {
    struct control *ct = n->control;
    if (!ct || ct->dead) return;
    if (map_request(n, ct, 0) < 0) plat_log("control: endpoint update failed");
}

void control_poll(struct node *n) {
    struct control *ct = n->control;
    if (!ct) return;
    if (pump(n, ct) < 0) ct->dead = 1;
    if (!ct->dead && plat_ms() - ct->last_rx > WATCHDOG_MS) {
        plat_log("control: nothing heard for %u s", WATCHDOG_MS / 1000);
        ct->dead = 1;
    }
    if (ct->dead) {
        plat_log("control: connection lost");
        snprintf(n->status, sizeof(n->status), "control connection lost");
        n->control = NULL;
        control_free(ct);
    }
}
