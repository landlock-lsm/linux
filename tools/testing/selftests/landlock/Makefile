# SPDX-License-Identifier: GPL-2.0

test_src := $(wildcard test_*.c)

TEST_GEN_PROGS := $(test_src:.c=)

TEST_GEN_PROGS_EXTENDED := true

KSFT_KHDR_INSTALL := 1
include ../lib.mk

# Cf. tools/testing/selftests/arm64/Makefile
ifeq ($(KBUILD_OUTPUT),)
khdr_dir = $(top_srcdir)/usr/include
else
khdr_dir = $(KBUILD_OUTPUT)/kselftest/usr/include
endif

CFLAGS += -Wall -O2 -I$(khdr_dir)

$(khdr_dir)/linux/landlock.h: khdr

$(TEST_GEN_PROGS): $(khdr_dir)/linux/landlock.h ../kselftest_harness.h common.h

$(OUTPUT)/true: true.c
	$(CC) -Os -static -o $@ $<
