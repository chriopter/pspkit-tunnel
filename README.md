# pspkit-tunnel

**A PSP in your tailnet** — WireGuard from a PSP to the other devices in a
tailnet, compatible with Tailscale and Headscale, so homebrew reaches a
server at home from wherever the PSP is. Built for [pspkit-https](https://github.com/chriopter/pspkit-https):
TLS and HTTP stay as they are, only the bytes take the tunnel.

## What it does

- **Joins with an auth key:** one `tskey-auth-…` from the admin console; afterwards the PSP keeps its own keys and needs nothing else
- **Works in any network:** traffic is relayed by DERP, chosen automatically — the region the other devices use
- **Plugs into pspkit-https:** `https_set_transport(host, tunnel_transport())`, and every request to that host goes through the tunnel, its own certificate check included
- **Starts when needed:** the first request through the tunnel starts it; nothing runs before

Compatible with Tailscale and its coordination protocol; not affiliated with or endorsed by Tailscale Inc.

## Speed

Measured on a PSP-1000 over Wi-Fi, one ISO from a server in the tailnet:

| | |
|---|---|
| Joining a tailnet, new device | 1.5–1.7 s |
| Joining again, kept keys | 1.2–1.6 s |
| HTTPS through the tunnel (TLS in WireGuard in DERP's TLS) | 310–330 KB/s |
| Four downloads through it at once, together | 185–200 KB/s |
| Plain HTTP straight from the internet, for comparison | 402 KB/s |

Three whole 57 MB downloads through it arrived with their SHA-256 intact;
eight cold boots in a row came back up with the kept keys.

## How to use

**1. Include it** after pspkit-https, before `build.mak`:

```make
include lib/pspkit-https/module.mk
include lib/pspkit-tunnel/module.mk
```

Needs [pspkit-https](https://github.com/chriopter/pspkit-https) 0.2.11 or
later, whose wolfSSL does the TLS; the application links cJSON (`-lcjson`).

**2. Join once, then route a host through it.**

```c
#include "pspkit-https/https.h"
#include "pspkit-tunnel/tunnel.h"

tunnel_set_dir("ms0:/PSP/MYAPP");          /* tunnel.key goes here */
tunnel_set_name("psp");                     /* how the tailnet shows it */

https_net_connect();
tunnel_start("tskey-auth-...");            /* first time; NULL after */
https_set_transport("myserver.example.ts.net", tunnel_transport());
https_get("https://myserver.example.ts.net/", on_data, NULL, NULL, NULL, &result);
```

`tunnel_state()` says how far it got. Once the device is registered, the
key is not needed any more: later runs only route the host, and the first
request starts the tunnel by itself.

## Inside

`ts/` speaks the protocols — the coordination server (Noise IK, HTTP/2),
DERP, disco, WireGuard — and [lwIP](https://savannah.nongnu.org/projects/lwip/)
does TCP. `psp/` is the console's half: sockets, files and a thread of its
own. `host/` builds the same `ts/` for Linux, which is how it is tested
against a real tailnet without a PSP: `dev/testnet up` starts Headscale and
an ordinary tailscaled as the peer, `host/check` proves the client is a node
of it. [`test/psp/`](test/psp/) is the runner that measured the numbers above
on a console.

Based on the protocol as the open-source Go client and Headscale implement
it, and on what the ESP32 ports ([tsesp](https://github.com/Korkuttum/tsesp),
[microlink](https://github.com/Sc1pex/microlink)) found out. GPL-2.0;
lwIP in `third_party/lwip` keeps its BSD-3 license.
