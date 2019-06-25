LIBDIR := ../../../lib
BPFDIR := $(LIBDIR)/bpf
APIDIR := ../../../include/uapi
GENDIR := ../../../../include/generated
GENHDR := $(GENDIR)/autoconf.h

ifneq ($(wildcard $(GENHDR)),)
  GENFLAGS := -DHAVE_GENHDR
endif

BPFOBJS := $(BPFDIR)/bpf.o $(BPFDIR)/nlattr.o
LOADOBJ := ../../../../samples/bpf/bpf_load.o

CFLAGS += -Wl,-no-as-needed -Wall -O2 -I$(APIDIR) -I$(LIBDIR) -I$(BPFDIR) -I$(GENDIR) $(GENFLAGS) -I../../../include
LDFLAGS += -lelf

test_src = $(wildcard test_*.c)

test_objs := $(test_src:.c=)

TEST_GEN_PROGS := $(test_objs)

.PHONY: all clean force

all: $(test_objs)

# force a rebuild of BPFOBJS when its dependencies are updated
force:

# rebuild bpf.o as a workaround for the samples/bpf bug
$(BPFOBJS): $(LOADOBJ) force
	$(MAKE) -C $(BPFDIR)

$(LOADOBJ): force
	$(MAKE) -C $(dir $(LOADOBJ))

$(test_objs): $(BPFOBJS) $(LOADOBJ) ../kselftest_harness.h

include ../lib.mk
