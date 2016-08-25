# kbuild trick to avoid linker error. Can be omitted if a module is built.
obj- := dummy.o

hostprogs-$(CONFIG_SECURITY_LANDLOCK) := sandbox
sandbox-objs := sandbox.o

always := $(hostprogs-y)

HOSTCFLAGS += -I$(objtree)/usr/include

# Trick to allow make to be run from this directory
all:
	$(MAKE) -C ../../ $$PWD/

clean:
	$(MAKE) -C ../../ M=$$PWD clean
