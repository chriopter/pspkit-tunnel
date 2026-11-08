# The host build of the client: ts/ as it is, with plat_posix.c under it and
# wolfSSL built for this machine by build-wolfssl.sh.
#
#   make           trusts the testnet CA (../work/testca.h, from testnet up)
#   make CA=real   trusts the bundle the PSP client ships, for a real tailnet
WORK = ../work
WOLF = $(WORK)/wolfssl-host
CA ?= test

# The selftest touches no TLS, so it does not want the CA header -- which
# testnet up writes, and which is therefore not there on a first checkout.
LWIP = ../third_party/lwip/src
CFLAGS = -O2 -g -Wall -Wextra -Wno-unused-parameter -I.. -I$(WOLF)/include -I../port -I$(LWIP)/include
CLIENT_CFLAGS = $(CFLAGS)
ifeq ($(CA),test)
CLIENT_CFLAGS += -include $(WORK)/testca.h
endif

LWIP_SRCS = $(filter-out %/altcp_alloc.c %/altcp.c %/altcp_tcp.c %/dns.c %/raw.c %/udp.c,$(wildcard $(LWIP)/core/*.c)) \
            $(wildcard $(LWIP)/core/ipv4/*.c)
SRCS = $(wildcard ../ts/*.c) $(LWIP_SRCS) plat_posix.c main.c fetch.c
LIBS = $(WOLF)/lib/libwolfssl.a -lcjson -lm -lpthread

tailscale-host: $(SRCS) $(wildcard ../ts/*.h) $(WOLF)/lib/libwolfssl.a
	$(CC) $(CLIENT_CFLAGS) -o $@ $(SRCS) $(LIBS)

selftest: selftest.c ../ts/crypto.c plat_posix.c $(WOLF)/lib/libwolfssl.a
	$(CC) $(CFLAGS) -o $@ selftest.c ../ts/crypto.c plat_posix.c $(LIBS)
	./selftest

$(WOLF)/lib/libwolfssl.a:
	./build-wolfssl.sh

clean:
	rm -f tailscale-host selftest

.PHONY: selftest clean
