/*
 * Landlock LSM - hooks helpers
 *
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <asm/current.h>
#include <linux/bpf.h> /* enum bpf_access_type */
#include <linux/lsm_hooks.h>
#include <linux/sched.h> /* struct task_struct */
#include <linux/seccomp.h>

/* separators */
#define SEP_COMMA() ,
#define SEP_SPACE()
#define SEP_AND() &&

#define MAP2x1(s, m, x1, x2, ...) m(x1, x2)
#define MAP2x2(s, m, x1, x2, ...) m(x1, x2) s() MAP2x1(s, m, __VA_ARGS__)
#define MAP2x3(s, m, x1, x2, ...) m(x1, x2) s() MAP2x2(s, m, __VA_ARGS__)
#define MAP2x4(s, m, x1, x2, ...) m(x1, x2) s() MAP2x3(s, m, __VA_ARGS__)
#define MAP2x5(s, m, x1, x2, ...) m(x1, x2) s() MAP2x4(s, m, __VA_ARGS__)
#define MAP2x6(s, m, x1, x2, ...) m(x1, x2) s() MAP2x5(s, m, __VA_ARGS__)
#define MAP2x(n, ...) MAP2x##n(__VA_ARGS__)

#define MAP1x1(s, m, x1, ...) m(x1)
#define MAP1x2(s, m, x1, ...) m(x1) s() MAP1x1(s, m, __VA_ARGS__)
#define MAP1x(n, ...) MAP1x##n(__VA_ARGS__)

#define SKIP2x1(x1, x2, ...) __VA_ARGS__
#define SKIP2x2(x1, x2, ...) SKIP2x1(__VA_ARGS__)
#define SKIP2x3(x1, x2, ...) SKIP2x2(__VA_ARGS__)
#define SKIP2x4(x1, x2, ...) SKIP2x3(__VA_ARGS__)
#define SKIP2x5(x1, x2, ...) SKIP2x4(__VA_ARGS__)
#define SKIP2x6(x1, x2, ...) SKIP2x5(__VA_ARGS__)
#define SKIP2x(n, ...) SKIP2x##n(__VA_ARGS__)

/* LSM hook argument helpers */
#define MAP_HOOK_COMMA(n, ...) MAP2x(n, SEP_COMMA, __VA_ARGS__)

#define GET_HOOK_TA(t, a) t a

/* Landlock event argument helpers  */
#define MAP_EVENT_COMMA(h, n, m, ...) MAP2x(n, SEP_COMMA, m, SKIP2x(h, __VA_ARGS__))
#define MAP_EVENT_SPACE(h, n, m, ...) MAP2x(n, SEP_SPACE, m, SKIP2x(h, __VA_ARGS__))
#define MAP_EVENT_AND(h, n, m, ...) MAP2x(n, SEP_AND, m, SKIP2x(h, __VA_ARGS__))

#define GET_CMD(h, n, ...) SKIP2x(n, SKIP2x(h, __VA_ARGS__))

#define EXPAND_TYPE(d) d##_TYPE
#define EXPAND_BPF(d) d##_BPF
#define EXPAND_C(d) d##_C

#define GET_TYPE_BPF(t) EXPAND_BPF(t)
#define GET_TYPE_C(t) EXPAND_C(t) *

#define GET_EVENT_C(d, a) GET_TYPE_C(EXPAND_TYPE(d))
#define GET_EVENT_U64(d, a) ((u64)(d##_VAL(a)))
#define GET_EVENT_DEC(d, a) d##_DEC(a)
#define GET_EVENT_OK(d, a) d##_OK(a)

/**
 * HOOK_ACCESS
 *
 * @EVENT: Landlock event name
 * @NA: number of event arguments
 *
 * The __consistent_##EVENT() extern functions and __wrapcheck_* types are
 * useful to catch inconsistencies in LSM hook definitions thanks to the
 * compiler type checking.
 */
#define HOOK_ACCESS(EVENT, NA, ...)					\
	inline bool landlock_is_valid_access_event_##EVENT(		\
			int off, int size, enum bpf_access_type type,	\
			enum bpf_reg_type *reg_type,			\
			union bpf_prog_subtype *prog_subtype)		\
	{								\
		enum bpf_reg_type _ctx_types[CTX_ARG_NB] = {		\
			MAP1x(NA, SEP_COMMA, GET_TYPE_BPF, __VA_ARGS__)	\
		};							\
		return landlock_is_valid_access(off, size, type,	\
				reg_type, _ctx_types, prog_subtype);	\
	}								\
	extern void __consistent_##EVENT(				\
			MAP1x(NA, SEP_COMMA, GET_TYPE_C, __VA_ARGS__))

/**
 * HOOK_NEW
 *
 * @INST: event instance for this hook
 * @EVENT: Landlock event name
 * @NE: number of event arguments
 * @HOOK: LSM hook name
 * @NH: number of hook arguments
 */
#define HOOK_NEW(INST, EVENT, NE, HOOK, NH, ...)			\
	static int landlock_hook_##EVENT##_##HOOK##_##INST(		\
			MAP_HOOK_COMMA(NH, GET_HOOK_TA, __VA_ARGS__))	\
	{								\
		if (!landlocked(current))				\
			return 0;					\
		if (!(MAP_EVENT_AND(NH, NE, GET_EVENT_OK,		\
						__VA_ARGS__)))		\
			return 0;					\
		{							\
		MAP_EVENT_SPACE(NH, NE, GET_EVENT_DEC, __VA_ARGS__)	\
		__u64 _ctx_values[CTX_ARG_NB] = {			\
			MAP_EVENT_COMMA(NH, NE, GET_EVENT_U64,		\
					__VA_ARGS__)			\
		};							\
		u32 _cmd = GET_CMD(NH, NE, __VA_ARGS__);		\
		return landlock_decide(LANDLOCK_SUBTYPE_EVENT_##EVENT,	\
				_ctx_values, _cmd, #HOOK);		\
		}							\
	}								\
	extern void __consistent_##EVENT(MAP_EVENT_COMMA(		\
				NH, NE, GET_EVENT_C, __VA_ARGS__))

/*
 * The WRAP_TYPE_* definitions group the bpf_reg_type enum value and the C
 * type. This C type may remains unused except to catch inconsistencies in LSM
 * hook definitions thanks to the compiler type checking.
 */

/* WRAP_TYPE_NONE */
#define WRAP_TYPE_NONE_BPF	NOT_INIT
#define WRAP_TYPE_NONE_C	struct __wrapcheck_none
WRAP_TYPE_NONE_C;

/* WRAP_TYPE_RAW */
#define WRAP_TYPE_RAW_BPF	UNKNOWN_VALUE
#define WRAP_TYPE_RAW_C		struct __wrapcheck_raw
WRAP_TYPE_RAW_C;

/*
 * The WRAP_ARG_* definitions group the LSM hook argument type (C and BPF), the
 * wrapping struct declaration (if any) and the value to copy to the BPF
 * context. This definitions may be used thanks to the EXPAND_* helpers.
 *
 * WRAP_ARG_*_TYPE: type for BPF and C (cf. WRAP_TYPE_*)
 * WRAP_ARG_*_DEC: declare a wrapper
 * WRAP_ARG_*_VAL: get this wrapper's address
 * WRAP_ARG_*_OK: check if the argument is usable
 */

/* WRAP_ARG_NONE */
#define WRAP_ARG_NONE_TYPE	WRAP_TYPE_NONE
#define WRAP_ARG_NONE_DEC(arg)
#define WRAP_ARG_NONE_VAL(arg)	0
#define WRAP_ARG_NONE_OK(arg)	(!WARN_ON(true))

/* WRAP_ARG_RAW */
#define WRAP_ARG_RAW_TYPE	WRAP_TYPE_RAW
#define WRAP_ARG_RAW_DEC(arg)
#define WRAP_ARG_RAW_VAL(arg)	arg
#define WRAP_ARG_RAW_OK(arg)	(true)


#define CTX_ARG_NB 2

static inline bool landlocked(const struct task_struct *task)
{
#ifdef CONFIG_SECCOMP_FILTER
	return !!(task->seccomp.landlock_events);
#else
	return false;
#endif /* CONFIG_SECCOMP_FILTER */
}

__init void landlock_register_hooks(struct security_hook_list *hooks, int count);

bool landlock_is_valid_access(int off, int size, enum bpf_access_type type,
		enum bpf_reg_type *reg_type,
		enum bpf_reg_type ctx_types[CTX_ARG_NB],
		union bpf_prog_subtype *prog_subtype);

int landlock_decide(enum landlock_subtype_event event,
		__u64 ctx_values[CTX_ARG_NB], u32 cmd, const char *hook);
