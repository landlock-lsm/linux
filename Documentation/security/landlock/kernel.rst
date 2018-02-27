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
inspect the current object. These arguments can be used directly (e.g. cookie)
or passed to helper functions according to their types (e.g. inode pointer). It
is then possible to do complex access checks without race conditions or
inconsistent evaluation (i.e.  `incorrect mirroring of the OS code and state
<https://www.ndss-symposium.org/ndss2003/traps-and-pitfalls-practical-problems-system-call-interposition-based-security-tools/>`_).

A Landlock hook describes a particular access type.  For now, there is three
hooks dedicated to filesystem related operations: LANDLOCK_HOOK_FS_PICK,
LANDLOCK_HOOK_FS_WALK and LANDLOCK_HOOK_FS_GET.  A Landlock program is tied to
one hook.  This makes it possible to statically check context accesses,
potentially performed by such program, and hence prevents kernel address leaks
and ensure the right use of hook arguments with eBPF functions.  Any user can
add multiple Landlock programs per Landlock hook.  They are stacked and
evaluated one after the other, starting from the most recent program, as
seccomp-bpf does with its filters.  Underneath, a hook is an abstraction over a
set of LSM hooks.


Guiding principles
==================

Unprivileged use
----------------

* Landlock helpers and context should be usable by any unprivileged and
  untrusted program while following the system security policy enforced by
  other access control mechanisms (e.g. DAC, LSM).


Landlock hook and context
-------------------------

* A Landlock hook shall be focused on access control on kernel objects instead
  of syscall filtering (i.e. syscall arguments), which is the purpose of
  seccomp-bpf.
* A Landlock context provided by a hook shall express the minimal and more
  generic interface to control an access for a kernel object.
* A hook shall guaranty that all the BPF function calls from a program are
  safe.  Thus, the related Landlock context arguments shall always be of the
  same type for a particular hook.  For example, a network hook could share
  helpers with a file hook because of UNIX socket.  However, the same helpers
  may not be compatible for a FS handle and a net handle.
* Multiple hooks may use the same context interface.


Landlock helpers
----------------

* Landlock helpers shall be as generic as possible while at the same time being
  as simple as possible and following the syscall creation principles (cf.
  *Documentation/adding-syscalls.txt*).
* The only behavior change allowed on a helper is to fix a (logical) bug to
  match the initial semantic.
* Helpers shall be reentrant, i.e. only take inputs from arguments (e.g. from
  the BPF context), to enable a hook to use a cache.  Future program options
  might change this cache behavior.
* It is quite easy to add new helpers to extend Landlock.  The main concern
  should be about the possibility to leak information from the kernel that may
  not be accessible otherwise (i.e. side-channel attack).


Questions and answers
=====================

Why not create a custom hook for each kind of action?
-----------------------------------------------------

Landlock programs can handle these checks.  Adding more exceptions to the
kernel code would lead to more code complexity.  A decision to ignore a kind of
action can and should be done at the beginning of a Landlock program.


Why a program does not return an errno or a kill code?
------------------------------------------------------

seccomp filters can return multiple kind of code, including an errno value or a
kill signal, which may be convenient for access control.  Those return codes
are hardwired in the userland ABI.  Instead, Landlock's approach is to return a
boolean to allow or deny an action, which is much simpler and more generic.
Moreover, we do not really have a choice because, unlike to seccomp, Landlock
programs are not enforced at the syscall entry point but may be executed at any
point in the kernel (through LSM hooks) where an errno return code may not make
sense.  However, with this simple ABI and with the ability to call helpers,
Landlock may gain features similar to seccomp-bpf in the future while being
compatible with previous programs.
