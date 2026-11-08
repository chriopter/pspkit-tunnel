#ifndef TS_PLAT_H
#define TS_PLAT_H

/* What the client needs from the machine under it, and nothing more: a clock,
   randomness, a log, two small files, and raw sockets. plat_psp.c answers
   with the PSP's sceNetInet, host/plat_posix.c with BSD sockets, so the whole
   protocol stack above is the same C on both and can be run against a real
   control server on the desk before it ever reaches the emulator. */

#include <stddef.h>
#include <stdint.h>

uint32_t plat_ms(void);
/* Wall-clock time, for WireGuard's handshake timestamps. It only has to rise
   from one handshake to the next; a PSP whose clock is wrong is still fine. */
uint64_t plat_unix_ms(void);
void plat_sleep_ms(unsigned ms);
void plat_random(void *out, size_t len);
void plat_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Files beside the program. load returns the bytes read or -1. */
int plat_load(const char *name, void *buf, size_t max);
int plat_save(const char *name, const void *buf, size_t len);

/* IPv4 addresses are host order throughout. */
int plat_resolve(const char *host, uint32_t *ip);
uint32_t plat_local_ip(void);

/* TCP. connect blocks until the connection stands or a timeout passes and
   returns a descriptor or -1. send and recv never block: they return the
   bytes moved, PLAT_AGAIN when the socket has nothing or no room, and
   PLAT_ERR on failure; recv returns 0 when the peer closed. */
#define PLAT_AGAIN (-1)
#define PLAT_ERR (-2)
int plat_tcp_connect(uint32_t ip, uint16_t port);
int plat_tcp_send(int fd, const void *buf, size_t len);
int plat_tcp_recv(int fd, void *buf, size_t len);
void plat_tcp_close(int fd);

/* UDP, the same conventions. open binds to port (0: any) and reports the
   port it got. */
int plat_udp_open(uint16_t port, uint16_t *bound);
int plat_udp_send(int fd, uint32_t ip, uint16_t port, const void *buf, size_t len);
int plat_udp_recv(int fd, void *buf, size_t len, uint32_t *ip, uint16_t *port);
void plat_udp_close(int fd);

#endif
