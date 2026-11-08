#ifndef PSPKIT_TUNNEL_LWIPOPTS_H
#define PSPKIT_TUNNEL_LWIPOPTS_H

/* lwIP as the tunnel's TCP and nothing else: no OS (one loop drives it),
   no sockets API (ts/tcp.c is the API), IPv4 only, no ARP or Ethernet --
   packets come out of WireGuard and go back into it. ICMP is answered by
   ts/netstack.c before lwIP sees anything. */

#define NO_SYS                  1
#define LWIP_SOCKET             0
#define LWIP_NETCONN            0
#define LWIP_IPV4               1
#define LWIP_IPV6               0
#define LWIP_ARP                0
#define LWIP_ETHERNET           0
#define LWIP_ICMP               0
#define LWIP_RAW                0
#define LWIP_UDP                0
#define LWIP_DHCP               0
#define LWIP_DNS                0
#define LWIP_IGMP               0
#define LWIP_STATS              0
#define LWIP_NETIF_LOOPBACK     0
#define LWIP_HAVE_LOOPIF        0
#define IP_REASSEMBLY           0
#define IP_FRAG                 0
#define LWIP_TCP                1
#define SYS_LIGHTWEIGHT_PROT    0

/* WireGuard has authenticated every byte by the time lwIP sees it, so the
   checksums it would check prove nothing more; on a 333 MHz CPU they are
   time a download pays. Outgoing ones are still written: the peer checks. */
#define CHECKSUM_CHECK_IP       0
#define CHECKSUM_CHECK_TCP      0

#define MEM_ALIGNMENT           4
#define MEM_SIZE                (64 * 1024)

/* The tunnel's MTU is 1280: 40 bytes of IPv4 and TCP header leave 1240. */
#define TCP_MSS                 1240
/* A relay round trip is 30-80 ms, so the window decides the speed: 128 KiB
   in flight is about 2-4 MB/s, more than the PSP decrypts three layers of. */
#define LWIP_WND_SCALE          1
#define TCP_RCV_SCALE           2
#define TCP_WND                 (104 * TCP_MSS)
#define TCP_SND_BUF             (16 * TCP_MSS)
#define TCP_SND_QUEUELEN        (4 * TCP_SND_BUF / TCP_MSS)
#define TCP_QUEUE_OOSEQ         1
#define TCP_OOSEQ_MAX_PBUFS     32
#define MEMP_NUM_TCP_PCB        8
#define MEMP_NUM_TCP_PCB_LISTEN 1
#define MEMP_NUM_TCP_SEG        (TCP_SND_QUEUELEN + 32)
#define MEMP_NUM_PBUF           32
/* Every segment received and not yet read sits in one of these: the pool
   is the receive window and a little more. */
#define PBUF_POOL_SIZE          144
#define PBUF_POOL_BUFSIZE       1300
#define LWIP_TCP_KEEPALIVE      1
/* A relay's round trip is tens of milliseconds, not the three seconds
   lwIP assumes before it has measured one: a lost SYN costs a second. */
#define LWIP_TCP_RTO_TIME       1000

/* Initial sequence numbers from the platform's randomness, not rand(). */
unsigned lwip_port_rand(void);
#define LWIP_RAND()             lwip_port_rand()

#endif
