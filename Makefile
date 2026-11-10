# Targets: test (host), asan (host + sanitizers), ct-test (host + sanitizers,
# PowerPC constant-time code paths and sanitized vendor objects), ppc-test
# (PowerPC, build only here; run the binary on a PowerPC Mac; also builds the
# tun_check driver check tool, which tools/driver.sh runs). GNU make 3.81 and
# /bin/sh compatible.
# New src/**/*.c files are picked up automatically.

SHELL := /bin/sh

BEARSSL := vendor/bearssl-0.6
SRCS    := $(shell find src -name '*.c' | sort)
TESTS   := $(wildcard tests/*.c)
BSRCS   := $(shell find $(BEARSSL)/src -name '*.c' | sort)

ifeq ($(TARGET),)
.PHONY: test asan ct-test ppc-test clean
test asan ct-test ppc-test:
	@$(MAKE) --no-print-directory TARGET=$@ build/$@/test_all $(if $(filter ppc-test,$@),build/ppc-test/tun_check)
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
CTMUL  := -DBR_CT_MUL31=1 -DBR_CT_MUL15=1
VSAN   :=
else
CC     := cc
ARCH   := -std=gnu99
ifeq ($(TARGET),ct-test)
# The PowerPC constant-time paths, run on the host with sanitized vendor code.
VENDOR := ct
SAN    := -fsanitize=address,undefined -fno-omit-frame-pointer
VSAN   := $(SAN)
CTMUL  := -DBR_CT_MUL15=1 -DBR_CT_MUL31=1 -DTS_FORCE_CT_POLY=1
else
VENDOR := host
VSAN   :=
CTMUL  :=
ifeq ($(TARGET),asan)
SAN    := -fsanitize=address,undefined -fno-omit-frame-pointer
else
SAN    :=
endif
endif
endif

OPT    := -O1 -g
CFLAGS := $(ARCH) $(CTMUL) $(OPT) $(SAN) -Wall -Wextra -Werror -MMD -MP -I. -I$(BEARSSL)/inc
VFLAGS := $(ARCH) $(CTMUL) $(VSAN) -O2 -w -I$(BEARSSL)/inc -I$(BEARSSL)/src

OBJDIR  := build/$(TARGET)
VOBJDIR := build/vendor-$(VENDOR)
OBJS    := $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS) $(TESTS))
VOBJS   := $(patsubst %.c,$(VOBJDIR)/%.o,$(BSRCS))

# Each object depends on a stamp holding the compiler and flags it was built
# with. The stamp is rewritten only when that text changes, so a changed flag
# rebuilds the objects even where stale ones are kept (build/vendor-ppc on the VM).
# Vendor objects have no dependency files, so the vendor stamp also holds a
# checksum of the vendored headers: a patched header rebuilds them.
VHEADERSUM := $(shell cat $(sort $(wildcard $(BEARSSL)/inc/*.h $(BEARSSL)/src/*.h)) | cksum)
FLAGSTAMP  := $(OBJDIR)/.flags
VFLAGSTAMP := $(VOBJDIR)/.flags

.PHONY: FORCE
FORCE:

# $(1) is the stamp's text. Make compares whole seconds, so wait a second before
# a rewrite: the stamp must be strictly newer than objects built just before it.
update_stamp = mkdir -p $(dir $@); printf '%s\n' '$(1)' >$@.new; \
	if cmp -s $@.new $@; then rm -f $@.new; else sleep 1; mv $@.new $@; touch $@; fi

$(FLAGSTAMP): FORCE
	@$(call update_stamp,$(CC) $(CFLAGS))

$(VFLAGSTAMP): FORCE
	@$(call update_stamp,$(CC) $(VFLAGS) headers $(VHEADERSUM))

$(OBJDIR)/test_all: $(OBJS) $(VOBJS)
	$(CC) $(ARCH) $(SAN) -o $@ $(OBJS) $(VOBJS)

CHECKOBJS := $(OBJDIR)/tools/tun_check.o $(OBJDIR)/src/core/bytes.o

$(OBJDIR)/tun_check: $(CHECKOBJS)
	$(CC) $(ARCH) -o $@ $(CHECKOBJS)

$(OBJDIR)/%.o: %.c $(FLAGSTAMP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(VOBJDIR)/%.o: %.c $(VFLAGSTAMP)
	@mkdir -p $(dir $@)
	$(CC) $(VFLAGS) -c -o $@ $<

-include $(OBJS:.o=.d) $(CHECKOBJS:.o=.d)
endif
