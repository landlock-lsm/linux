==============================
Landlock: kernel documentation
==============================

eBPF properties
===============

To get an expressive language while still being safe and small, Landlock is
based on eBPF. Landlock should be usable by untrusted processes and must
therefore expose a minimal attack surface. The eBPF bytecode is minimal,
powerful, widely used and designed to be used by untrusted applications. Thus,
reusing the eBPF support in the kernel enables a generic approach while
minimizing new code.

An eBPF program has access to an eBPF context containing some fields used to
inspect the current object. These arguments may be used directly (e.g. raw
value) or passed to helper functions according to their types (e.g. pointer).
It is then possible to do complex access checks without race conditions or
inconsistent evaluation (i.e.  `incorrect mirroring of the OS code and state
<https://www.ndss-symposium.org/ndss2003/traps-and-pitfalls-practical-problems-system-call-interposition-based-security-tools/>`_).

A Landlock hook describes a particular access type.  For now, there is one hook
dedicated to ptrace related operations: ``BPF_LANDLOCK_PTRACE``.  A Landlock
program is tied to one hook.  This makes it possible to statically check
context accesses, potentially performed by such program, and hence prevents
kernel address leaks and ensure the right use of hook arguments with eBPF
functions.  Any user can add multiple Landlock programs per Landlock hook.
They are stacked and evaluated one after the other, starting from the most
recent program, as seccomp-bpf does with its filters.  Underneath, a hook is an
abstraction over a set of LSM hooks.


Guiding principles
==================

Unprivileged use
----------------

* As far as possible, Landlock helpers and contexts should be *designed* to be
  usable by unprivileged programs while following the system security policy
  enforced by other access control mechanisms (e.g. DAC, LSM).  Indeed, a
  Landlock program shall not interfere with other access-controls enforced on
  the system.

Because one of the Landlock's goal is to create scoped access-control (i.e.
sandboxing), it makes sense to make it possible to have access-control-safe
programs.  This enables to avoid unneeded security risks when writing a
security policy.  We should also keep in mind that a Landlock program may be
written and loaded in the kernel by a trusted process, but applied by a
non-root (and possibly malicious) process to sandbox itself e.g., using a
sandboxer service.  This sandboxed process must not be able to leverage one of
the Landlock program applied on itself to do a privilege escalation nor to
infer data that should not be accessible otherwise (i.e. side-channels).

However, when justified, it should be possible to have dedicated
privileged-only program types e.g., to make a security decision based on
properties inaccessible by unprivileged processes, or to log actions with
additional metadata.  As explained above, these properties should not be
inferable from the enforced access-control.  Care must be taken to not only
focus on these programs' context or helpers to avoid putting everything in a
root-only realm (cf. `CAP_SYS_ADMIN: the new root
<https://lwn.net/Articles/486306/>`_).

It should be noted that ``CAP_SYS_ADMIN`` is currently required for loading and
for enforcing any Landlock programs, but more fine-grained rights may be
discussed in the future.


Landlock hook and context
-------------------------

* A Landlock hook shall be focused on access control on kernel objects instead
  of syscall filtering (i.e. syscall arguments), which is the purpose of
  seccomp-bpf.
* A Landlock context provided by a hook shall express the minimal and more
  generic interface to control an access for a kernel object.  This may be
  implemented with kernel pointers used as security capabilities (i.e.
  unforgeable token enabling actions on an object according to a set of
  rights).
* A hook shall guaranty that all the BPF function calls from a program are
  safe.  Thus, the related Landlock context arguments shall always be of the
  same type for a particular hook.  For example, a network hook could share
  helpers with a file hook because of UNIX socket.  However, the same helpers
  may not be compatible for a file system handle and a net handle.
* Multiple hooks may use the same context interface.


Landlock helpers
----------------

* Landlock helpers shall be as generic as possible while at the same time being
  as simple as possible and following the syscall creation principles (cf.
  :doc:`/process/adding-syscalls`).
* The only behavior change allowed on a helper is to fix a (logical) bug to
  match the initial semantic.
* Helpers shall be reentrant, i.e. only take inputs from arguments (e.g. from
  the BPF context), to enable a hook to use a cache.  Future program options
  might change this cache behavior.
* It is quite easy to add new helpers to extend Landlock.  The main concern
  should be about the possibility to leak information from the kernel that may
  not be accessible otherwise (i.e. side-channel attack).


Landlock domain
===============

A Landlock domain is a set of eBPF programs.  There is a list for each
different program types that can be run on a specific Landlock hook (e.g.
ptrace).  A domain is tied to a set of subjects (i.e. tasks).

A Landlock program should not try (nor be able) to infer which subject is
currently enforced, but to have a unique security policy for all subjects tied
to the same domain.  This make the reasoning much easier and help avoid
pitfalls.

.. kernel-doc:: security/landlock/common.h
    :functions: landlock_domain

.. kernel-doc:: security/landlock/domain_manage.c
    :functions: landlock_prepend_prog


Adding a Landlock program with seccomp
--------------------------------------

The :manpage:`seccomp(2)` syscall can be used with the
``SECCOMP_PREPEND_LANDLOCK_PROG`` operation to prepend a Landlock program to
the current task's domain.

.. kernel-doc:: security/landlock/domain_syscall.c
    :functions: landlock_seccomp_prepend_prog


Running a list of Landlock programs
-----------------------------------

.. kernel-doc:: security/landlock/bpf_run.c
    :functions: landlock_access_denied


LSM hooks
=========

.. kernel-doc:: security/landlock/hooks_ptrace.c
    :functions: hook_ptrace_access_check

.. kernel-doc:: security/landlock/hooks_ptrace.c
    :functions: hook_ptrace_traceme


Questions and answers
=====================

Why a program does not return an errno or a kill code?
------------------------------------------------------

seccomp filters can return multiple kind of code, including an errno value or a
kill signal, which may be convenient for access control.  Those return codes
are hardwired in the userland ABI.  Instead, Landlock's approach is to return a
bitmask to allow or deny an action, which is much simpler and more generic.
Moreover, we do not really have a choice because, unlike to seccomp, Landlock
programs are not enforced at the syscall entry point but may be executed at any
point in the kernel (through LSM hooks) where an errno return code may not make
sense.  However, with this simple ABI and with the ability to call helpers,
Landlock may gain features similar to seccomp-bpf in the future while being
compatible with previous programs.
