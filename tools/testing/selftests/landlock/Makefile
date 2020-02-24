# SPDX-License-Identifier: GPL-2.0

test_src := $(wildcard test_*.c)

TEST_GEN_PROGS := $(test_src:.c=)

usr_include := ../../../../usr/include

CFLAGS += -Wall -O2 -I$(usr_include)

include ../lib.mk

$(TEST_GEN_PROGS): ../kselftest_harness.h $(usr_include)/linux/landlock.h
