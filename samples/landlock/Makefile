# SPDX-License-Identifier: BSD-3-Clause

hostprogs-y := sandboxer

always := $(hostprogs-y)

KBUILD_HOSTCFLAGS += -I$(objtree)/usr/include

.PHONY: all clean

all:
	$(MAKE) -C ../.. samples/landlock/

clean:
	$(MAKE) -C ../.. M=samples/landlock/ clean
