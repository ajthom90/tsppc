# Targets: test (host), asan (host + sanitizers), ppc-test (PowerPC, build only
# here; run the binary on a PowerPC Mac). GNU make 3.81 and /bin/sh compatible.
# New src/**/*.c files are picked up automatically.

SHELL := /bin/sh

BEARSSL := vendor/bearssl-0.6
SRCS    := $(shell find src -name '*.c' | sort)
TESTS   := $(wildcard tests/*.c)
BSRCS   := $(shell find $(BEARSSL)/src -name '*.c' | sort)

ifeq ($(TARGET),)
.PHONY: test asan ppc-test clean
test asan ppc-test:
	@$(MAKE) --no-print-directory TARGET=$@ build/$@/test_all
	@./build/$@/test_all

clean:
	rm -rf build
else

ifeq ($(TARGET),ppc-test)
CC     := gcc-4.0
ARCH   := -std=gnu99 -arch ppc -isysroot /Developer/SDKs/MacOSX10.4u.sdk -mmacosx-version-min=10.4
VENDOR := ppc
SAN    :=
# G3/G4 multiplies are variable-time: force BearSSL's constant-time multiply.
CTMUL  := -DBR_CT_MUL31=1
else
CC     := cc
ARCH   := -std=gnu99
VENDOR := host
ifeq ($(TARGET),asan)
SAN    := -fsanitize=address,undefined -fno-omit-frame-pointer
else
SAN    :=
endif
endif

OPT    := -O1 -g
CFLAGS := $(ARCH) $(CTMUL) $(OPT) $(SAN) -Wall -Wextra -Werror -MMD -MP -I. -I$(BEARSSL)/inc
VFLAGS := $(ARCH) $(CTMUL) -O2 -w -I$(BEARSSL)/inc -I$(BEARSSL)/src

OBJDIR  := build/$(TARGET)
VOBJDIR := build/vendor-$(VENDOR)
OBJS    := $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS) $(TESTS))
VOBJS   := $(patsubst %.c,$(VOBJDIR)/%.o,$(BSRCS))

$(OBJDIR)/test_all: $(OBJS) $(VOBJS)
	$(CC) $(ARCH) $(SAN) -o $@ $(OBJS) $(VOBJS)

$(OBJDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(VOBJDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(VFLAGS) -c -o $@ $<

-include $(OBJS:.o=.d)
endif
