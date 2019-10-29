# SPDX-License-Identifier: GPL-2.0

LIBDIR := $(abspath ../../../lib)
BPFDIR := $(LIBDIR)/bpf
TOOLSDIR := $(abspath ../../../include)
APIDIR := $(TOOLSDIR)/uapi

CFLAGS += -g -Wall -O2 -I$(APIDIR) -I$(LIBDIR) -I$(TOOLSDIR)
LDLIBS += -lelf

test_src = $(wildcard test_*.c)

TEST_GEN_PROGS := $(test_src:.c=)

include ../lib.mk

BPFOBJ := $(OUTPUT)/libbpf.a

$(TEST_GEN_PROGS): $(BPFOBJ) ../kselftest_harness.h

.PHONY: force

# force a rebuild of BPFOBJ when its dependencies are updated
force:

$(BPFOBJ): force
	$(MAKE) -C $(BPFDIR) OUTPUT=$(OUTPUT)/
