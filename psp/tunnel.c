/*
 * The tunnel on the console: one thread runs the node -- control, DERP,
 * WireGuard, lwIP -- and everything else talks to it through one lock.
 * pspkit-https's transport is four functions that take the lock, move
 * bytes in and out of a tunnel TCP handle, and let go again; while they
 * wait, the thread keeps the packets flowing.
 */

#include <pspkernel.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "pspkit-https/https.h"
#include "pspkit-tunnel/tunnel.h"
#include "psp/plat_psp.h"
#include "ts/node.h"
#include "ts/plat.h"
#include "ts/tcp.h"

#define CONTROL_HOST "controlplane.tailscale.com"
#define UP_WAIT_MS 20000            /* a transport connect waits this long for the tunnel */
#define CONNECT_WAIT_MS 10000       /* and this long for the TCP handshake */

static struct node g_node;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_start_lock = PTHREAD_MUTEX_INITIALIZER;   /* start and stop */
static char g_hostname[64] = "psp";
static int g_ephemeral;
static SceUID g_thread = -1;
static volatile int g_stop;
/* What tunnel_state reports, written by the thread and read by anyone:
   under a lock of its own, held for a copy and nothing else. */
static pthread_mutex_t g_status_lock = PTHREAD_MUTEX_INITIALIZER;
static enum tunnel_state g_state = TUNNEL_OFF;
static char g_text[96] = "Off";

void tunnel_set_dir(const char *dir) { plat_psp_set_dir(dir); }
void tunnel_set_ephemeral(int on) { g_ephemeral = on != 0; }
void tunnel_set_name(const char *hostname) {
    if (hostname && *hostname) snprintf(g_hostname, sizeof(g_hostname), "%s", hostname);
}
void tunnel_set_log(void (*line)(const char *text)) { plat_psp_set_log(line); }

int tunnel_has_keys(void) { return plat_exists("tunnel.key"); }

int tunnel_find_key(const char *text, char *out, size_t size) {
    const char *k = text ? strstr(text, "tskey-auth-") : NULL;
    if (!k) return -1;
    size_t len = 0;
    while ((k[len] >= 'a' && k[len] <= 'z') || (k[len] >= 'A' && k[len] <= 'Z') ||
           (k[len] >= '0' && k[len] <= '9') || k[len] == '-')
        len++;
    if (len <= 11 || len >= size) return -1;
    memcpy(out, k, len);
    out[len] = '\0';
    return 0;
}

static void set_state(enum tunnel_state s, const char *text) {
    pthread_mutex_lock(&g_status_lock);
    g_state = s;
    snprintf(g_text, sizeof(g_text), "%s", text);
    pthread_mutex_unlock(&g_status_lock);
}

static enum tunnel_state state_now(void) {
    pthread_mutex_lock(&g_status_lock);
    enum tunnel_state s = g_state;
    pthread_mutex_unlock(&g_status_lock);
    return s;
}

/* A wait inside the node -- a connect, a handshake, a full socket -- lets
   the lock go when it is the tunnel's own thread that waits, so the
   connections already up keep moving meanwhile. Any other thread holds on:
   it is in the middle of something of its own. */
static void wait_ms(unsigned ms) {
    int own = g_thread >= 0 && sceKernelGetThreadId() == g_thread && !tcp_tunnel_in_lwip();
    if (own) pthread_mutex_unlock(&g_lock);
    sceKernelDelayThread(ms * 1000);
    if (own) pthread_mutex_lock(&g_lock);
}

/* What the node's status says, as one of four states. Called with the lock. */
static void update_state(void) {
    struct node *n = &g_node;
    if (n->auth_url[0]) { set_state(TUNNEL_FAILED, "Not in the tailnet: set it up again with a new key."); return; }
    if (!strncmp(n->status, "refused", 7)) {
        char t[96];
        snprintf(t, sizeof(t), "The key was refused: %.60s", n->status + 9);
        set_state(TUNNEL_FAILED, t);
        return;
    }
    if (n->registered && !n->keys_saved) {
        /* In the tailnet, but with nothing kept to come back as. */
        set_state(TUNNEL_FAILED, "Could not save tunnel.key to the Memory Stick.");
        return;
    }
    if (n->registered && n->ip && derp_connected(n)) {
        char ip[16], t[96];
        ip_string(ip, n->ip);
        snprintf(t, sizeof(t), "Connected as %s, %d devices", ip, n->peer_count);
        set_state(TUNNEL_UP, t);
        return;
    }
    set_state(TUNNEL_JOINING, n->registered ? "Reaching the relay..." : "Joining the tailnet...");
}

static int run(SceSize args, void *argp) {
    (void)args; (void)argp;
    while (!g_stop) {
        pthread_mutex_lock(&g_lock);
        node_step(&g_node);
        update_state();
        pthread_mutex_unlock(&g_lock);
        sceKernelDelayThread(1000);
    }
    return 0;
}

static int start_locked(const char *auth_key) {
    if (g_thread >= 0) return -1;
    if (!plat_random_ok()) { set_state(TUNNEL_FAILED, "No randomness for the keys."); return -1; }
    plat_psp_set_wait(wait_ms);
    pthread_mutex_lock(&g_lock);
    memset(&g_node, 0, sizeof(g_node));
    struct node *n = &g_node;
    snprintf(n->control_host, sizeof(n->control_host), "%s", CONTROL_HOST);
    n->control_port = 443;
    n->control_tls = 1;
    snprintf(n->auth_key, sizeof(n->auth_key), "%s", auth_key ? auth_key : "");
    snprintf(n->hostname, sizeof(n->hostname), "%s", g_hostname);
    n->ephemeral = g_ephemeral;
    node_init(n);
    set_state(TUNNEL_JOINING, "Joining the tailnet...");
    pthread_mutex_unlock(&g_lock);
    g_stop = 0;
    /* Above the application's workers, so a download waiting on the
       tunnel never starves the thread that feeds it. */
    g_thread = sceKernelCreateThread("pspkit_tunnel", run, 0x18, 64 * 1024, PSP_THREAD_ATTR_USER, NULL);
    if (g_thread < 0 || sceKernelStartThread(g_thread, 0, NULL) < 0) {
        if (g_thread >= 0) sceKernelDeleteThread(g_thread);
        g_thread = -1;
        pthread_mutex_lock(&g_lock);
        node_stop(&g_node);
        memset(g_node.auth_key, 0, sizeof(g_node.auth_key));
        pthread_mutex_unlock(&g_lock);
        set_state(TUNNEL_FAILED, "Could not start.");
        return -1;
    }
    return 0;
}

int tunnel_start(const char *auth_key) {
    pthread_mutex_lock(&g_start_lock);
    int rc = start_locked(auth_key);
    pthread_mutex_unlock(&g_start_lock);
    return rc;
}

static void stop_locked(void);

void tunnel_stop(void) {
    pthread_mutex_lock(&g_start_lock);
    stop_locked();
    pthread_mutex_unlock(&g_start_lock);
}

static void stop_locked(void) {
    if (g_thread < 0) return;
    g_stop = 1;
    sceKernelWaitThreadEnd(g_thread, NULL);
    sceKernelDeleteThread(g_thread);
    g_thread = -1;
    pthread_mutex_lock(&g_lock);
    tcp_tunnel_close_all();
    node_stop(&g_node);
    memset(g_node.auth_key, 0, sizeof(g_node.auth_key));
    pthread_mutex_unlock(&g_lock);
    set_state(TUNNEL_OFF, "Off");
}

int tunnel_forget(void) {
    pthread_mutex_lock(&g_start_lock);
    int logged_out = 0;
    if (plat_exists("tunnel.key")) {
        /* Up first if it is not, so the server hears this device go. */
        if (g_thread < 0) start_locked(NULL);
        unsigned start = plat_ms();
        enum tunnel_state st;
        while ((st = state_now()) == TUNNEL_JOINING && plat_ms() - start < UP_WAIT_MS)
            sceKernelDelayThread(50 * 1000);
        if (st == TUNNEL_UP) {
            pthread_mutex_lock(&g_lock);
            logged_out = control_logout(&g_node) == 0;
            pthread_mutex_unlock(&g_lock);
        }
    }
    stop_locked();
    int gone = plat_remove("tunnel.key") == 0;
    set_state(TUNNEL_OFF, gone ? "Removed" : "Could not delete tunnel.key.");
    pthread_mutex_unlock(&g_start_lock);
    if (!gone) return -1;
    return logged_out ? 0 : 1;
}

enum tunnel_state tunnel_state(char *text, size_t size) {
    pthread_mutex_lock(&g_status_lock);
    enum tunnel_state s = g_state;
    if (text && size) snprintf(text, size, "%s", g_text);
    pthread_mutex_unlock(&g_status_lock);
    return s;
}

/* ------------------------------------------------------------- transport */

static int t_connect(const char *host, unsigned short port, void *ctx) {
    (void)ctx;
    /* The first request through the tunnel starts it, with the keys a
       setup left; without them there is nothing to start. */
    pthread_mutex_lock(&g_start_lock);
    if (g_thread < 0) {
        if (tunnel_has_keys()) start_locked(NULL);
        else set_state(TUNNEL_FAILED, "Not set up: no tunnel.key.");
    }
    pthread_mutex_unlock(&g_start_lock);
    unsigned start = plat_ms();
    enum tunnel_state st;
    while ((st = state_now()) != TUNNEL_UP) {
        if (st == TUNNEL_OFF || st == TUNNEL_FAILED || plat_ms() - start > UP_WAIT_MS) return -1;
        sceKernelDelayThread(20 * 1000);
    }
    uint32_t ip;
    pthread_mutex_lock(&g_lock);
    int h = node_resolve(&g_node, host, &ip) == 0 ? tcp_tunnel_open(ip, port) : PLAT_ERR;
    pthread_mutex_unlock(&g_lock);
    if (h < 0) { plat_log("tunnel: %s is not in the tailnet", host); return -1; }
    start = plat_ms();
    for (;;) {
        pthread_mutex_lock(&g_lock);
        int r = tcp_tunnel_ready(h);
        if (r == PLAT_ERR) tcp_tunnel_close(h);
        pthread_mutex_unlock(&g_lock);
        if (r == 1) return h;
        if (r == PLAT_ERR) return -1;
        if (plat_ms() - start > CONNECT_WAIT_MS) {
            pthread_mutex_lock(&g_lock);
            tcp_tunnel_close(h);
            pthread_mutex_unlock(&g_lock);
            plat_log("tunnel: %s:%u did not answer", host, port);
            return -1;
        }
        sceKernelDelayThread(2000);
    }
}

static int t_send(int h, const void *buf, int len, void *ctx) {
    (void)ctx;
    pthread_mutex_lock(&g_lock);
    int r = tcp_tunnel_send(h, buf, (size_t)len);
    pthread_mutex_unlock(&g_lock);
    return r == PLAT_AGAIN ? HTTPS_AGAIN : r;
}

static int t_recv(int h, void *buf, int len, void *ctx) {
    (void)ctx;
    pthread_mutex_lock(&g_lock);
    int r = tcp_tunnel_recv(h, buf, (size_t)len);
    pthread_mutex_unlock(&g_lock);
    return r == PLAT_AGAIN ? HTTPS_AGAIN : r;
}

static void t_close(int h, void *ctx) {
    (void)ctx;
    pthread_mutex_lock(&g_lock);
    tcp_tunnel_close(h);
    pthread_mutex_unlock(&g_lock);
}

static const struct https_transport g_transport = { t_connect, t_send, t_recv, t_close, NULL };

const struct https_transport *tunnel_transport(void) { return &g_transport; }
