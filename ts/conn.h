#ifndef TS_CONN_H
#define TS_CONN_H

/* A byte stream to a server, in the clear or under TLS: the control
   connection is either (Tailscale's own control plane answers Noise on port
   80 as well as 443, since the Noise layer is the encryption that counts),
   DERP is always TLS. Opening blocks; reading never does. */

#include <stddef.h>
#include <stdint.h>

typedef struct conn conn;

conn *conn_open(const char *host, uint16_t port, int tls);
/* Bytes read, 0 when nothing is there yet, -1 when the stream has ended. */
int conn_read(conn *c, void *buf, size_t len);
/* Everything or -1. Blocks for as long as the socket is full. */
int conn_write(conn *c, const void *buf, size_t len);
void conn_close(conn *c);

/* Reads an HTTP/1.1 response head and not a byte more, blocking up to
   timeout_ms, and leaves it NUL-terminated in head. Returns the status code
   or -1. */
int conn_read_head(conn *c, char *head, size_t head_max, unsigned timeout_ms);

#endif
