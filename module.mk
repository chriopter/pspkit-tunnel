# pspkit-tunnel in an application's Makefile:
#
#   include lib/pspkit-https/module.mk
#   include lib/pspkit-tunnel/module.mk
#
# after OBJS, CFLAGS and LIBS are set and before build.mak. It adds the
# tunnel's objects (the protocols, lwIP's TCP, the console's platform
# layer) and its header, included as "pspkit-tunnel/tunnel.h". TLS comes
# from pspkit-https's wolfSSL, so that module goes first; JSON from cJSON,
# which the application links (-lcjson).
PSPKIT_TUNNEL := $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))
PSPKIT_TUNNEL_LWIP := $(PSPKIT_TUNNEL)/third_party/lwip/src

PSPKIT_TUNNEL_LWIP_SRCS := $(filter-out %/altcp_alloc.c %/altcp.c %/altcp_tcp.c %/dns.c %/raw.c %/udp.c, \
                             $(wildcard $(PSPKIT_TUNNEL_LWIP)/core/*.c)) \
                           $(wildcard $(PSPKIT_TUNNEL_LWIP)/core/ipv4/*.c)
OBJS += $(patsubst %.c,%.o,$(wildcard $(PSPKIT_TUNNEL)/ts/*.c)) \
        $(PSPKIT_TUNNEL)/psp/plat.o $(PSPKIT_TUNNEL)/psp/tunnel.o \
        $(patsubst %.c,%.o,$(PSPKIT_TUNNEL_LWIP_SRCS))
CFLAGS += -I$(PSPKIT_TUNNEL)/include -I$(PSPKIT_TUNNEL) -I$(PSPKIT_TUNNEL)/port \
          -I$(PSPKIT_TUNNEL_LWIP)/include
