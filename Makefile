# Targets: test (host), asan (host + sanitizers), ct-test (host + sanitizers,
# PowerPC constant-time code paths and sanitized vendor objects), fuzz (mutation
# fuzzing of every parser, ASan + UBSan, aborting on any fault; set
# TS_FUZZ_ITERS to change the 200000 iterations per target), ppc-test
# (PowerPC, build only here; run the binary on a PowerPC Mac; also builds the
# tun_check driver check tool, which tools/driver.sh runs, and the
# keyfetch_check live TLS check), keyfetch-check (host build of keyfetch_check),
# release (host tsppcd and tsppc without test hooks), ppc (the same for
# PowerPC, with the ppc-test compiler and flags).
# test, asan and ppc-test also build their own tsppcd and tsppc (with test
# hooks, for the daemon tests) and the matching release programs, and check
# with tools/check-release.sh that the release daemon has no test hooks.
# GNU make 3.81 and /bin/sh compatible.
# New src/**/*.c files are picked up automatically; src/daemon/main.c and
# src/cli/main.c are the programs' mains and stay out of the test binaries.

SHELL := /bin/sh

BEARSSL := vendor/bearssl-0.6
SRCS    := $(shell find src -name '*.c' | sort)
MAINS   := src/daemon/main.c src/cli/main.c
LIBSRCS := $(filter-out $(MAINS),$(SRCS))
ALLTESTS := $(wildcard tests/*.c)
BSRCS   := $(shell find $(BEARSSL)/src -name '*.c' | sort)

ifeq ($(TARGET),)
.PHONY: test asan ct-test ppc-test fuzz keyfetch-check release ppc clean
# The release build that goes with each test target.
rel_test := release
rel_asan := release
rel_ppc-test := ppc
test asan ppc-test:
	@$(MAKE) --no-print-directory TARGET=$@ build/$@/test_all build/$@/tsppcd build/$@/tsppc $(if $(filter ppc-test,$@),build/ppc-test/tun_check build/ppc-test/keyfetch_check)
	@$(MAKE) --no-print-directory TARGET=$(rel_$@) build/$(rel_$@)/tsppcd build/$(rel_$@)/tsppc
	@sh tools/check-release.sh build/$(rel_$@)/tsppcd build/$@/tsppcd
	@./build/$@/test_all

ct-test:
	@$(MAKE) --no-print-directory TARGET=$@ build/$@/test_all
	@./build/$@/test_all

release ppc:
	@$(MAKE) --no-print-directory TARGET=$@ build/$@/tsppcd build/$@/tsppc
	@sh tools/check-release.sh build/$@/tsppcd

keyfetch-check:
	@$(MAKE) --no-print-directory TARGET=test build/test/keyfetch_check

fuzz:
	@$(MAKE) --no-print-directory TARGET=fuzz build/fuzz/fuzz_all
	@./build/fuzz/fuzz_all

clean:
	rm -rf build
else

ifneq ($(filter ppc-test ppc,$(TARGET)),)
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
else ifeq ($(TARGET),fuzz)
# Undefined behaviour must abort, not just print, so the harness reports it.
SAN    := -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer
# A small HTTP/2 credit threshold makes WINDOW_UPDATE emission reachable by short inputs.
FZDEF  := -DCREDIT_THRESHOLD=64
else
SAN    :=
endif
endif
endif

# The fuzz binary has its own main (tests/fuzz.c) and only the fuzz_*.c targets;
# the test binaries get everything else.
ifeq ($(TARGET),fuzz)
TESTS  := $(wildcard tests/fuzz*.c)
else
TESTS  := $(filter-out tests/fuzz%,$(ALLTESTS))
endif

# Release programs have no test hooks: no environment overrides, no test-only
# functions. Everything else is built with them.
ifneq ($(filter release ppc,$(TARGET)),)
HOOKS  :=
else
HOOKS  := -DTS_TEST_HOOKS
endif

OPT    := -O1 -g
CFLAGS := $(ARCH) $(CTMUL) $(FZDEF) $(HOOKS) -DTS_BIN_DIR=\"build/$(TARGET)\" $(OPT) $(SAN) -Wall -Wextra -Werror -MMD -MP -I. -I$(BEARSSL)/inc
VFLAGS := $(ARCH) $(CTMUL) $(VSAN) -O2 -w -I$(BEARSSL)/inc -I$(BEARSSL)/src

OBJDIR  := build/$(TARGET)
VOBJDIR := build/vendor-$(VENDOR)
LIBOBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(LIBSRCS))
OBJS    := $(patsubst %.c,$(OBJDIR)/%.o,$(LIBSRCS) $(TESTS))
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

# The fuzz registry lists every tests/fuzz_<name>.c as ts_fuzz_<name>().
FUZZNAMES := $(patsubst tests/fuzz_%.c,%,$(filter tests/fuzz_%.c,$(TESTS)))
REGISTRY  := $(OBJDIR)/registry.c

$(REGISTRY): FORCE
	@mkdir -p $(dir $@); { \
	  echo '#include <stddef.h>'; echo '#include "tests/fuzz.h"'; \
	  for n in $(FUZZNAMES); do echo "extern void ts_fuzz_$$n(void);"; done; \
	  echo "const char *const ts_fuzz_names[] = { $(foreach n,$(FUZZNAMES),\"$(n)\",) 0 };"; \
	  echo "void (*const ts_fuzz_funcs[])(void) = { $(foreach n,$(FUZZNAMES),ts_fuzz_$(n),) 0 };"; \
	  echo "const size_t ts_fuzz_count = $(words $(FUZZNAMES));"; \
	} >$@.new; \
	if cmp -s $@.new $@; then rm -f $@.new; else mv $@.new $@; fi

$(OBJDIR)/registry.o: $(REGISTRY) $(FLAGSTAMP)
	$(CC) $(CFLAGS) -Wno-missing-prototypes -c -o $@ $<

$(OBJDIR)/fuzz_all: $(OBJS) $(OBJDIR)/registry.o $(VOBJS)
	$(CC) $(ARCH) $(SAN) -o $@ $(OBJS) $(OBJDIR)/registry.o $(VOBJS)

CHECKOBJS := $(OBJDIR)/tools/tun_check.o $(OBJDIR)/src/core/bytes.o

$(OBJDIR)/tun_check: $(CHECKOBJS)
	$(CC) $(ARCH) -o $@ $(CHECKOBJS)

KFOBJS := $(OBJDIR)/tools/keyfetch_check.o $(LIBOBJS)

$(OBJDIR)/tsppcd: $(OBJDIR)/src/daemon/main.o $(LIBOBJS) $(VOBJS)
	$(CC) $(ARCH) $(SAN) -o $@ $(OBJDIR)/src/daemon/main.o $(LIBOBJS) $(VOBJS)

# The CLI needs only the socket and reply code.
$(OBJDIR)/tsppc: $(OBJDIR)/src/cli/main.o $(OBJDIR)/src/daemon/ipc.o $(OBJDIR)/src/daemon/ipc_reply.o
	$(CC) $(ARCH) $(SAN) -o $@ $(OBJDIR)/src/cli/main.o $(OBJDIR)/src/daemon/ipc.o $(OBJDIR)/src/daemon/ipc_reply.o

$(OBJDIR)/keyfetch_check: $(KFOBJS) $(VOBJS)
	$(CC) $(ARCH) $(SAN) -o $@ $(KFOBJS) $(VOBJS)

$(OBJDIR)/%.o: %.c $(FLAGSTAMP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(VOBJDIR)/%.o: %.c $(VFLAGSTAMP)
	@mkdir -p $(dir $@)
	$(CC) $(VFLAGS) -c -o $@ $<

-include $(OBJS:.o=.d) $(CHECKOBJS:.o=.d) $(OBJDIR)/tools/keyfetch_check.d $(patsubst %.c,$(OBJDIR)/%.d,$(MAINS))
endif
