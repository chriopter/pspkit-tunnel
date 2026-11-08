#ifndef TS_TCP_H
#define TS_TCP_H

/* TCP through the tunnel: lwIP under it, WireGuard under lwIP. Handles are
   small integers. Nothing blocks: every call returns at once, and the
   bytes move when node_step runs. The conventions are plat.h's: PLAT_AGAIN
   for "nothing yet" or "no room yet", PLAT_ERR for a connection that failed
   or was reset, 0 from recv when the far side closed in order. */

#include <stddef.h>
#include <stdint.h>

struct node;

void tcp_tunnel_init(struct node *n);
/* lwIP's timers; node_step calls it. */
void tcp_tunnel_poll(void);
/* An IPv4 packet for us with protocol 6, from netstack. */
void tcp_tunnel_input(const uint8_t *ip, int len);

#define TCP_TUNNEL_MAX 8

/* ip is a tailnet address, host order. Returns a handle, or PLAT_ERR when
   no peer has the address or every handle is in use. */
int tcp_tunnel_open(uint32_t ip, uint16_t port);
/* 1 once established, PLAT_AGAIN while connecting, PLAT_ERR if it failed. */
int tcp_tunnel_ready(int h);
int tcp_tunnel_send(int h, const void *buf, size_t len);
int tcp_tunnel_recv(int h, void *buf, size_t len);
void tcp_tunnel_close(int h);
void tcp_tunnel_close_all(void);
/* Whether lwIP is running right now, further up this thread's stack. */
int tcp_tunnel_in_lwip(void);

#endif
