/*
 * The tunnel on a real console, measured. Run from PSPLink with host0: on
 * the desk: it reads host0:/tunnel-test/config.txt, joins the tailnet,
 * and fetches the same file both ways -- straight over the radio, and
 * through the tunnel -- writing one line per fetch to result.txt and every
 * log line to log.txt beside it.
 *
 *   authkey=tskey-auth-...      for a device not registered yet
 *   hostname=pspkit-test-07
 *   dir=ms0:/PSP/TUNNELTEST/07  where tunnel.key goes
 *   direct=http://192.168.10.10:8100/discs/X.iso
 *   tunnel=https://jellyhop.example.ts.net:8100/discs/X.iso
 *   basic=pspdx:password        for the tunnel's host only
 *   times=2
 *   limit=0                     seconds per fetch, 0 for none
 */

#include <pspkernel.h>
#include <pspdebug.h>
#include <pspiofilemgr.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "pspkit-https/entropy.h"
#include "pspkit-https/https.h"
#include "pspkit-tunnel/tunnel.h"

PSP_MODULE_INFO("tunneltest", 0, 1, 0);
PSP_MAIN_THREAD_ATTR(THREAD_ATTR_USER);
PSP_HEAP_SIZE_KB(16 * 1024);

/* The folder the program was loaded from: host0:/tunnel-test/ under
   PSPLink, the EBOOT's own folder on a stick or in an emulator. */
static char BASE_DIR[192] = "host0:/tunnel-test/";
/* Built once at start: the log is written from three threads. */
static char LOG_PATH[256], RESULT_PATH[256], CONFIG_PATH[256];

static struct {
    char sha256[72], authkey[128], hostname[64], dir[128], direct[512], tunnel[256], basic[160], scenarios[160];
    int times, limit, cycles, fresh, ephemeral, first;
} cfg;

static void append(const char *name, const char *line) {
    char file[256];
    snprintf(file, sizeof(file), "%s", name);
    int fd = sceIoOpen(file, PSP_O_WRONLY | PSP_O_CREAT | PSP_O_APPEND, 0777);
    if (fd < 0) return;
    sceIoWrite(fd, line, strlen(line));
    sceIoWrite(fd, "\n", 1);
    sceIoClose(fd);
}

static void logline(const char *text) {
    char line[200];
    snprintf(line, sizeof(line), "%8.3f %s", sceKernelGetSystemTimeWide() / 1e6, text);
    append(LOG_PATH, line);
}

static void say(const char *fmt, ...) {
    char line[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    logline(line);
    append(RESULT_PATH, line);
    pspDebugScreenPrintf("%s\n", line);
}

static void read_config(void) {
    static char buf[2048];
    int fd = sceIoOpen(CONFIG_PATH, PSP_O_RDONLY, 0777);
    int n = fd >= 0 ? sceIoRead(fd, buf, sizeof(buf) - 1) : -1;
    if (fd >= 0) sceIoClose(fd);
    if (n <= 0) return;
    buf[n] = '\0';
    cfg.times = 1;
    for (char *line = strtok(buf, "\r\n"); line; line = strtok(NULL, "\r\n")) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *k = line, *v = eq + 1;
#define S(name) if (!strcmp(k, #name)) snprintf(cfg.name, sizeof(cfg.name), "%s", v)
        S(sha256); S(authkey); S(hostname); S(dir); S(direct); S(tunnel); S(basic); S(scenarios);
        if (!strcmp(k, "cycles")) cfg.cycles = atoi(v);
        if (!strcmp(k, "fresh")) cfg.fresh = atoi(v);
        if (!strcmp(k, "ephemeral")) cfg.ephemeral = atoi(v);
        if (!strcmp(k, "first")) cfg.first = atoi(v);
        if (!strcmp(k, "times")) cfg.times = atoi(v);
        if (!strcmp(k, "limit")) cfg.limit = atoi(v);
    }
}

/* The host of a URL, for the transport and the password. */
static void host_of(const char *url, char *out, size_t size) {
    const char *h = strstr(url, "://");
    h = h ? h + 3 : url;
    size_t len = strcspn(h, ":/");
    snprintf(out, size, "%.*s", (int)(len < size ? len : size - 1), h);
}

/* Every byte counted and hashed: a sha256= in the config is checked
   against what came through. */
static wc_Sha256 g_sha;
static int count(void *ctx, const void *data, size_t len) {
    *(long long *)ctx += (long long)len;
    wc_Sha256Update(&g_sha, data, (word32)len);
    return 0;
}

static int hash_matches(void) {
    unsigned char d[32];
    char hex[65];
    wc_Sha256Final(&g_sha, d);
    for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "%02x", d[i]);
    if (!cfg.sha256[0]) return 1;
    int ok = !strcmp(hex, cfg.sha256);
    say("sha256 %s: %s", ok ? "matches" : "DIFFERS", hex);
    return ok;
}

static int measure(const char *label, const char *url) {
    int ok = 0;
    for (int i = 0; i < cfg.times; i++) {
        long long got = 0;
        struct https_result r;
        memset(&r, 0, sizeof(r));
        https_set_time_limit((unsigned)cfg.limit);
        u64 t0 = sceKernelGetSystemTimeWide();
        wc_InitSha256(&g_sha);
        int rc = https_get(url, count, &got, NULL, NULL, &r);
        int same = strstr(label, "direct") ? 1 : hash_matches();
        double s = (sceKernelGetSystemTimeWide() - t0) / 1e6;
        say("%s %d: rc %d status %d, %lld bytes in %.2f s, %.0f KB/s, handshake %u ms",
            label, i + 1, rc, r.status, got, s, s > 0 ? got / 1024.0 / s : 0, r.handshake_ms);
        ok += rc == 0 && r.status == 200 && same;
    }
    return ok;
}

static double secs(u64 since) { return (sceKernelGetSystemTimeWide() - since) / 1e6; }

/* Waits while the tunnel is joining; the state it settled in. */
static enum tunnel_state settle(char *text, size_t size, unsigned max_s) {
    u64 t0 = sceKernelGetSystemTimeWide();
    enum tunnel_state st;
    while ((st = tunnel_state(text, size)) == TUNNEL_JOINING && secs(t0) < max_s)
        sceKernelDelayThread(50 * 1000);
    return st;
}

/* A download on a thread of its own, for the scenario that stops the
   tunnel under it. */
static volatile int g_bg_done, g_bg_rc;
static char g_bg_url[256];
static int bg_get(SceSize a, void *b) {
    (void)a; (void)b;
    struct https_result r;
    g_bg_rc = https_get(g_bg_url, NULL, NULL, NULL, NULL, &r);
    g_bg_done = 1;
    return sceKernelExitDeleteThread(0);
}

static char g_host[128];

/* Four at once, the way an application fetches icons: each its own
   connection through the tunnel. */
#define PARALLEL 4
static volatile int g_par_done[PARALLEL], g_par_rc[PARALLEL];
static volatile long long g_par_got[PARALLEL];
static int par_count(void *ctx, const void *data, size_t len) {
    (void)data;
    *(long long *)ctx += (long long)len;
    return 0;
}
static int par_get(SceSize a, void *b) {
    int i = *(int *)b;
    struct https_result r;
    long long got = 0;
    g_par_rc[i] = https_get(g_bg_url, par_count, &got, NULL, NULL, &r);
    if (r.status != 200) g_par_rc[i] = -2;
    g_par_got[i] = got;
    g_par_done[i] = 1;
    (void)a;
    return sceKernelExitDeleteThread(0);
}

/* One cycle of one scenario. 1 passed, 0 failed. */
static int cycle(int n, const char *scenario) {
    char dir[160], name[64], text[96];
    snprintf(dir, sizeof(dir), "%s/%02d", cfg.dir, cfg.fresh ? n : 0);
    snprintf(name, sizeof(name), "%s-%02d", cfg.hostname, cfg.fresh ? n : 0);
    if (!strcmp(scenario, "badkey")) snprintf(dir, sizeof(dir), "%s/bad", cfg.dir);
    tunnel_set_dir(dir);
    tunnel_set_name(name);
    tunnel_set_ephemeral(cfg.ephemeral);
    int had = tunnel_has_keys(), pass = 0;
    u64 t0 = sceKernelGetSystemTimeWide();
    say("cycle %d %s: %s, keys %s", n, scenario, name, had ? "kept" : "none");

    if (!strcmp(scenario, "badkey")) {
        tunnel_start("tskey-auth-kXXXXXXXXXXCNTRL-notarealkeyatall0000000000000");
        enum tunnel_state st = settle(text, sizeof(text), 30);
        pass = st == TUNNEL_FAILED && !tunnel_has_keys();
        say("cycle %d badkey: state %d \"%s\" in %.2f s, keys %s -> %s", n, st, text, secs(t0),
            tunnel_has_keys() ? "written" : "none", pass ? "PASS" : "FAIL");
        tunnel_stop();
        return pass;
    }
    https_set_transport(g_host, tunnel_transport());
    if (!strcmp(scenario, "lazy")) {
        /* No start: the first request starts it -- or, with no keys yet,
           says so at once and sends nothing. */
        int ok = measure("lazy", cfg.tunnel);
        enum tunnel_state st = tunnel_state(text, sizeof(text));
        pass = had ? ok == cfg.times : ok == 0 && st == TUNNEL_FAILED && secs(t0) < 2;
        say("cycle %d lazy: %s, %.2f s in all -> %s", n, text, secs(t0), pass ? "PASS" : "FAIL");
    } else {
        tunnel_start(had ? NULL : cfg.authkey);
        enum tunnel_state st = settle(text, sizeof(text), 60);
        say("cycle %d join: \"%s\" in %.2f s", n, text, secs(t0));
        if (st == TUNNEL_UP && !strcmp(scenario, "parallel")) {
            snprintf(g_bg_url, sizeof(g_bg_url), "%s", cfg.tunnel);
            static int idx[PARALLEL];
            u64 tp = sceKernelGetSystemTimeWide();
            for (int i = 0; i < PARALLEL; i++) {
                idx[i] = i;
                g_par_done[i] = 0;
                g_par_got[i] = 0;
                SceUID th = sceKernelCreateThread("par", par_get, 0x30, 64 * 1024, PSP_THREAD_ATTR_USER, NULL);
                sceKernelStartThread(th, sizeof(int), &idx[i]);
            }
            int done = 0;
            while (secs(tp) < 120) {
                done = 0;
                for (int i = 0; i < PARALLEL; i++) done += g_par_done[i];
                if (done == PARALLEL) break;
                sceKernelDelayThread(50 * 1000);
            }
            long long all = 0;
            int good = 0;
            for (int i = 0; i < PARALLEL; i++) { all += g_par_got[i]; good += g_par_done[i] && g_par_rc[i] == 0; }
            double sp = secs(tp);
            say("cycle %d parallel: %d of %d complete, %lld bytes in %.2f s, %.0f KB/s together", n, good,
                PARALLEL, all, sp, sp > 0 ? all / 1024.0 / sp : 0);
            pass = good == PARALLEL;
        } else if (st == TUNNEL_UP && !strcmp(scenario, "stopmid")) {
            snprintf(g_bg_url, sizeof(g_bg_url), "%s", cfg.tunnel);
            g_bg_done = 0;
            SceUID th = sceKernelCreateThread("bg", bg_get, 0x20, 64 * 1024, PSP_THREAD_ATTR_USER, NULL);
            sceKernelStartThread(th, 0, NULL);
            sceKernelDelayThread(1500 * 1000);
            u64 ts = sceKernelGetSystemTimeWide();
            tunnel_stop();
            double stop_s = secs(ts);
            while (!g_bg_done && secs(ts) < 60) sceKernelDelayThread(50 * 1000);
            say("cycle %d stopmid: stop took %.2f s, download ended %s rc %d", n, stop_s,
                g_bg_done ? "" : "NOT", g_bg_rc);
            tunnel_start(NULL);
            st = settle(text, sizeof(text), 60);
            int ok = st == TUNNEL_UP ? measure("after", cfg.tunnel) : 0;
            pass = g_bg_done && ok == cfg.times;
        } else if (st == TUNNEL_UP) {
            pass = measure("tunnel", cfg.tunnel) == cfg.times;
            if (!strcmp(scenario, "restart")) {
                tunnel_stop();
                u64 tr = sceKernelGetSystemTimeWide();
                tunnel_start(NULL);
                st = settle(text, sizeof(text), 60);
                say("cycle %d restart: \"%s\" in %.2f s", n, text, secs(tr));
                pass = pass && st == TUNNEL_UP && measure("again", cfg.tunnel) == cfg.times;
            }
        }
        say("cycle %d %s: %.2f s in all, keys %s -> %s", n, scenario, secs(t0),
            tunnel_has_keys() ? "kept" : "none", pass ? "PASS" : "FAIL");
    }
    tunnel_stop();
    https_set_transport(g_host, NULL);
    return pass;
}

int main(int argc, char **argv) {
    if (argc > 0 && argv[0] && strrchr(argv[0], '/'))
        snprintf(BASE_DIR, sizeof(BASE_DIR), "%.*s/", (int)(strrchr(argv[0], '/') - argv[0]), argv[0]);
    snprintf(LOG_PATH, sizeof(LOG_PATH), "%slog.txt", BASE_DIR);
    snprintf(RESULT_PATH, sizeof(RESULT_PATH), "%sresult.txt", BASE_DIR);
    snprintf(CONFIG_PATH, sizeof(CONFIG_PATH), "%sconfig.txt", BASE_DIR);
    pspDebugScreenInit();
    read_config();
    if (!cfg.dir[0]) snprintf(cfg.dir, sizeof(cfg.dir), "ms0:/PSP/TUNNELTEST");
    if (!cfg.scenarios[0]) snprintf(cfg.scenarios, sizeof(cfg.scenarios), "normal");
    if (cfg.cycles <= 0) cfg.cycles = 1;
    if (cfg.first <= 0) cfg.first = 1;
    say("--- tunneltest %s, %d cycles from %d of %s", cfg.hostname, cfg.cycles, cfg.first, cfg.scenarios);
    https_set_log(logline);
    tunnel_set_log(logline);

    entropy_init();
    entropy_set_seed_file("ms0:/PSP/PSPDX/CRYPTO/seed.bin");
    if (entropy_load() < 0) {
        say("no seed file: running on the jitter alone (test only)");
        entropy_allow_unswept();
    }
    u64 t0 = sceKernelGetSystemTimeWide();
    if (https_net_connect() < 0) { say("radio: no connection"); goto done; }
    say("radio up in %.2f s", secs(t0));

    char user[64] = "", *pass = NULL;
    if (cfg.basic[0]) {
        snprintf(user, sizeof(user), "%s", cfg.basic);
        char *colon = strchr(user, ':');
        if (colon) { *colon = '\0'; pass = strchr(cfg.basic, ':') + 1; }
    }
    /* direct= may name several URLs, a space between: raw HTTP and HTTPS
       side by side, say, before the tunnel. */
    char urls[sizeof(cfg.direct)];
    snprintf(urls, sizeof(urls), "%s", cfg.direct);
    for (char *u = strtok(urls, " "); u; u = strtok(NULL, " ")) {
        /* No password here: basic= is the shelf's, and goes to the
           tunnel's host alone, never to a server measured for speed. */
        measure(strncmp(u, "https", 5) ? "direct http" : "direct https", u);
    }
    if (cfg.tunnel[0]) {
        host_of(cfg.tunnel, g_host, sizeof(g_host));
        if (pass) https_set_basic(g_host, user, pass);
        char list[160];
        int passed = 0, ran = 0;
        for (int n = cfg.first; n < cfg.first + cfg.cycles; n++) {
            snprintf(list, sizeof(list), "%s", cfg.scenarios);
            int k = 0, want = (n - cfg.first), count = 1;
            for (char *c = list; *c; c++) count += *c == ',';
            want %= count;
            char *sc = strtok(list, ",");
            while (sc && k < want) { sc = strtok(NULL, ","); k++; }
            passed += cycle(n, sc ? sc : "normal");
            ran++;
        }
        say("=== %d of %d cycles passed", passed, ran);
    }
done:
    https_net_disconnect();
    say("--- done");
    sceKernelExitGame();
    return 0;
}
