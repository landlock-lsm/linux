LIBDIR := ../../../lib
BPFOBJ := $(LIBDIR)/bpf/bpf.o
LOADOBJ := ../../../../samples/bpf/bpf_load.o

CFLAGS += -Wl,-no-as-needed -Wall -O2 -I../../../include/uapi -I$(LIBDIR)
LDFLAGS += -lelf

test_src = $(wildcard test_*.c)
rule_src = $(wildcard bpf/rule_*.c)

test_objs := $(test_src:.c=)
rule_objs := $(notdir $(rule_src:.c=.o))

TEST_PROGS := $(test_objs)
TEST_PROGS_EXTENDED := $(rule_objs)

.PHONY: all clean clean_tmp force

all: $(test_objs) $(rule_objs)

# force a rebuild of BPFOBJ when its dependencies are updated
force:

$(BPFOBJ): force
	$(MAKE) -C $(dir $(BPFOBJ))

$(LOADOBJ): force
	$(MAKE) -C $(dir $(LOADOBJ))

# minimize builds
bpf/modules.order: $(rule_src)
	$(MAKE) -C bpf
	@touch $@

$(rule_objs): bpf/modules.order
	@

$(test_objs): $(BPFOBJ) $(LOADOBJ) ../kselftest_harness.h

include ../lib.mk

clean_tmp:
	$(RM) -r tmp_*

clean: clean_tmp
	$(MAKE) -C bpf clean
	$(RM) $(test_objs)

