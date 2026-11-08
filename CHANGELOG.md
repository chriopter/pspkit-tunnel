# Changelog

## 1.1.0

- The coordination server and the relays are checked against pspkit-https's roots (0.2.12's `https_load_roots`), which that library keeps current every week, instead of a fixed bundle of the tunnel's own; an application carries one set of roots, not two
- The desk build trusts the system's roots

## 1.0.0

- A PSP joins a tailnet with one auth key and keeps its own keys in `tunnel.key`; `tunnel_forget()` logs it out again and deletes them
- Traffic relayed by DERP, the region chosen from where the other devices are; TCP through lwIP over WireGuard
- `tunnel_transport()` for pspkit-https 0.2.11's `https_set_transport()`: a host's requests go through the tunnel, its own TLS and certificate check included; the first one starts the tunnel
- Tested on a PSP-1000: joining in 1.5–1.7 s, 310–330 KB/s of HTTPS through the tunnel, whole 57 MB downloads with their SHA-256 intact, cold boots, stops mid-download and refused keys
