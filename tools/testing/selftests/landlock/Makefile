# SPDX-License-Identifier: GPL-2.0

test_src := $(wildcard test_*.c)

TEST_GEN_PROGS := $(test_src:.c=)

TEST_GEN_PROGS_EXTENDED := true

KSFT_KHDR_INSTALL := 1
OVERRIDE_TARGETS := 1
include ../lib.mk

# Cf. tools/testing/selftests/arm64/Makefile
ifeq ($(KBUILD_OUTPUT),)
khdr_dir = $(top_srcdir)/usr/include
else
khdr_dir = $(KBUILD_OUTPUT)/kselftest/usr/include
endif

CFLAGS += -Wall -O2

$(khdr_dir)/linux/landlock.h: khdr
	@:

$(OUTPUT)/true: true.c
	$(LINK.c) $< $(LDLIBS) -o $@ -static

$(OUTPUT)/test_%:test_%.c $(khdr_dir)/linux/landlock.h ../kselftest_harness.h common.h
	$(LINK.c) $< $(LDLIBS) -o $@ -lcap -I$(khdr_dir)
