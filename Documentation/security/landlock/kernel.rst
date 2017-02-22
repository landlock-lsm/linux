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

An eBPF program has access to an eBPF context containing some fields including
event arguments (i.e. arg1 and arg2). These arguments can be used directly or
passed to helper functions according to their types. It is then possible to do
complex access checks without race conditions or inconsistent evaluation (i.e.
`incorrect mirroring of the OS code and state
<https://www.internetsociety.org/doc/traps-and-pitfalls-practical-problems-system-call-interposition-based-security-tools>`_).

A Landlock event describes a particular access type.  For now, there is only
one event type dedicated to filesystem related operations:
LANDLOCK_SUBTYPE_EVENT_FS.  A Landlock rule is tied to one event type.  This
makes it possible to statically check context accesses, potentially performed
by such rule, and hence prevents kernel address leaks and ensure the right use
of event arguments with eBPF functions.  Any user can add multiple Landlock
rules per Landlock event.  They are stacked and evaluated one after the other,
starting from the most recent rule, as seccomp-bpf does with its filters.
Underneath, an event is an abstraction over a set of LSM hooks.


Guiding principles
==================

Unprivileged use
----------------

* Everything potentially security sensitive which is exposed to a Landlock
  rule, through functions or context, shall have an associated ability flag to
  specify which kind of privilege a process must have to load such a rule.
* Every ability flag expresses a semantic goal (e.g. debug, process
  introspection, process modification) potentially tied to a set of
  capabilities.
* Landlock helpers and context should be usable by any unprivileged and
  untrusted rule while following the system security policy enforced by other
  access control mechanisms (e.g. DAC, LSM).


Landlock event and context
--------------------------

* A Landlock event shall be focused on access control on kernel objects instead
  of syscall filtering (i.e. syscall arguments), which is the purpose of
  seccomp-bpf.
* A Landlock context provided by an event shall express the minimal interface
  to control an access for a kernel object. This can be achieved by wrapping
  this raw object (e.g. file, inode, path, dentry) with an abstract
  representation (i.e. handle) for userland/bpfland.
* An evolution of a context's field (e.g. new flags in the status field) shall
  only be activated for a rule if the version specified by the loading thread
  imply this behavior.  This makes it possible to ensure that the rule code
  make sense (e.g.  only watch flags which may be activated).
* An event type shall guaranty that all the BPF function calls from a rule are
  safe.  Thus, the related Landlock context arguments shall always be of the
  same type for a particular event type.  For example, a network event could
  share helpers with a file event because of UNIX socket.  However, the same
  helpers may not be compatible for a FS handle and a net handle.
* Multiple event types may use the same context interface.


Landlock helpers
----------------

* Landlock helpers shall be as generic as possible (i.e. using handles) while
  at the same time being as simple as possible and following the syscall
  creation principles (cf.  *Documentation/adding-syscalls.txt*).
* The only behavior change allowed on a helper is to fix a (logical) bug to
  match the initial semantic.
* Helpers shall be reentrant, i.e. only take inputs from arguments (e.g. from
  the BPF context) or from the current thread, to allow an event type to use a
  cache.  Future rule options might change this cache behavior (e.g. invalidate
  cache after some time).
* It is quite easy to add new helpers to extend Landlock.  The main concern
  should be about the possibility to leak information from a landlocked process
  to another (e.g. through maps) to not reproduce the same security sensitive
  behavior as ptrace(2).


Rule addition and propagation
=============================

See :ref:`Documentation/security/landlock/user <inherited_rules>` for the
intended goal of rule propagation.

Structure definitions
---------------------

.. kernel-doc:: include/linux/landlock.h


Functions for rule addition
---------------------------

.. kernel-doc:: security/landlock/manager.c


Questions and answers
=====================

Why not create a custom event type for each kind of action?
-----------------------------------------------------------

Landlock rules can handle these checks.  Adding more exceptions to the kernel
code would lead to more code complexity.  A decision to ignore a kind of action
can and should be done at the beginning of a Landlock rule.


Why a rule does not return an errno code?
-----------------------------------------

seccomp filters can return multiple kind of code, including an errno value,
which may be convenient for access control.  Those return codes are hardwired
in the userland ABI.  Instead, Landlock approach is to return a boolean to
allow or deny an action, which is much simpler and more generic.  Moreover, we
do not really have a choice because, unlike to seccomp, Landlock rules are not
enforced at the syscall entry point but may be executed at any point in the
kernel (through LSM hooks) where an errno return code may not make sense.
However, with this simple ABI and with the ability to call helpers, Landlock
may gain features similar to seccomp-bpf in the future while being compatible
with previous rules.

