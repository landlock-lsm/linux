LIBDIR := ../../../lib
OBJDIR := ../../../lib/bpf
BPFOBJS := $(OBJDIR)/bpf.o $(OBJDIR)/nlattr.o
LOADOBJ := ../../../../samples/bpf/bpf_load.o

CFLAGS += -Wl,-no-as-needed -Wall -O2 -I../../../include/uapi -I$(LIBDIR)
LDFLAGS += -lelf

test_src = $(wildcard test_*.c)

test_objs := $(test_src:.c=)

TEST_PROGS := $(test_objs)

.PHONY: all clean force

all: $(test_objs)

# force a rebuild of BPFOBJS when its dependencies are updated
force:

# rebuild bpf.o as a workaround for the samples/bpf bug
$(BPFOBJS): $(LOADOBJ) force
	$(MAKE) -C $(OBJDIR)

$(LOADOBJ): force
	$(MAKE) -C $(dir $(LOADOBJ))

$(test_objs): $(BPFOBJS) $(LOADOBJ) ../kselftest_harness.h

include ../lib.mk

clean:
	$(RM) $(test_objs)

