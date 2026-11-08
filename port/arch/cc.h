#ifndef PSPKIT_TUNNEL_ARCH_CC_H
#define PSPKIT_TUNNEL_ARCH_CC_H

/* lwIP's view of the compiler and the machine: the same on the PSP (MIPS,
   little-endian) and the desk. Asserts and diagnostics go to plat_log. */
#include <stdint.h>
#include <stdlib.h>

#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#define LWIP_NO_INTTYPES_H 0
#define LWIP_TIMEVAL_PRIVATE 0

void lwip_port_log(const char *fmt, ...);
#define LWIP_PLATFORM_DIAG(x)   do { lwip_port_log x; } while (0)
#define LWIP_PLATFORM_ASSERT(x) do { lwip_port_log("lwip assert: %s (%s:%d)", x, __FILE__, __LINE__); abort(); } while (0)

#endif
