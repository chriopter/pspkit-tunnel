# The tunnel test for a real console, as a PRX PSPLink runs from host0:.
#   docker run --rm -v ~/git:/git -w /git/pspkit-tunnel/test/psp pspdev/pspdev make
# PSPKIT_HTTPS points at a pspkit-https checkout with build/wolfssl in it.
TARGET = tunneltest
OBJS = main.o
CFLAGS = -O2 -G0 -Wall
LIBS = -lcjson
BUILD_PRX = 1
EXTRA_TARGETS = EBOOT.PBP
PSP_EBOOT_TITLE = tunneltest
PSPKIT_HTTPS ?= ../../../pspkit-https
include $(PSPKIT_HTTPS)/module.mk
include ../../module.mk
ASFLAGS = $(CFLAGS)
PSPSDK = $(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build.mak
