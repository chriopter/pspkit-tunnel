#ifndef PSPKIT_TUNNEL_H
#define PSPKIT_TUNNEL_H

/* A PSP in a tailnet: WireGuard to the other devices in it, relayed by
   DERP, so that a host there -- a catalog at home, say -- is reachable from
   wherever the PSP is. Compatible with Tailscale's coordination server;
   not a Tailscale product.

   It runs on a thread of its own once started. pspkit-https reaches a host
   through it after https_set_transport(host, tunnel_transport()): TLS and
   HTTP are pspkit-https's as always, the bytes go through the tunnel.

   The radio must be up first (https_net_connect). Nothing here blocks the
   caller for long; every function may be called from any thread. */

#include <stddef.h>

struct https_transport;

/* Where the device's keys live (tunnel.key), the name it has in the
   tailnet ("psp" until set), and what the log goes to. Before starting. */
void tunnel_set_dir(const char *dir);
void tunnel_set_name(const char *hostname);
/* A device the tailnet forgets soon after it goes offline -- for tests and
   demonstrations; off unless set. */
void tunnel_set_ephemeral(int on);
void tunnel_set_log(void (*line)(const char *text));

/* Starts the thread and joins the tailnet. auth_key (tskey-auth-...) is
   only needed while the device is not registered yet; NULL or "" after.
   0, or -1 when it is running already or the thread could not start. */
int tunnel_start(const char *auth_key);
void tunnel_stop(void);

enum tunnel_state {
    TUNNEL_OFF,                     /* not started */
    TUNNEL_JOINING,                 /* talking to the coordination server */
    TUNNEL_UP,                      /* registered, with an address and a relay */
    TUNNEL_FAILED,                  /* refused, or needs a new key; see the text */
};
/* The state, and a line for a person in text. */
enum tunnel_state tunnel_state(char *text, size_t size);

/* Leaves the tailnet: logs the device out at the coordination server (it
   is started for that if it is not running) and deletes tunnel.key. 0 when
   both happened, 1 when the keys are gone but the server could not be
   told (offline, say -- the device then stays listed in the admin console
   until it is removed there), -1 when tunnel.key could not be deleted. */
int tunnel_forget(void);

/* Whether the keys of a registered device are in the directory. */
int tunnel_has_keys(void);

/* tskey-auth-... out of whatever text it is in (a whole install command,
   say), into out. 0, or -1 when there is none. */
int tunnel_find_key(const char *text, char *out, size_t size);

/* For https_set_transport. Its connect starts the tunnel when it is not
   running and keys are there, and waits for it to come up. */
const struct https_transport *tunnel_transport(void);

#endif
