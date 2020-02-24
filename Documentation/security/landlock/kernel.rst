==============================
Landlock: kernel documentation
==============================

Landlock's goal is to create scoped access-control (i.e. sandboxing).  To
harden a whole system, this feature should be available to any process,
including unprivileged ones.  Because such process may be compromised or
backdoored (i.e. untrusted), Landlock's features must be safe to use from the
kernel and other processes point of view.  Landlock's interface must therefore
expose a minimal attack surface.

Landlock is designed to be usable by unprivileged processes while following the
system security policy enforced by other access control mechanisms (e.g. DAC,
LSM).  Indeed, a Landlock rule shall not interfere with other access-controls
enforced on the system, only add more restrictions.

Any user can enforce Landlock rulesets on their processes.  They are merged and
evaluated according to the inherited ones in a way that ensure that only more
constraints can be added.


Guiding principles for safe access controls
===========================================

* A Landlock rule shall be focused on access control on kernel objects instead
  of syscall filtering (i.e. syscall arguments), which is the purpose of
  seccomp-bpf.
* To avoid multiple kind of side-channel attacks (e.g. leak of security
  policies, CPU-based attacks), Landlock rules shall not be able to
  programmatically communicate with user space.
* Kernel access check shall not slow down access request from unsandboxed
  processes.
* Computation related to Landlock operations (e.g. enforce a ruleset) shall
  only impact the processes requesting them.


Landlock rulesets and domains
=============================

A domain is a read-only ruleset tied to a set of subjects (i.e. tasks).  A
domain can transition to a new one which is the intersection of the constraints
from the current and a new ruleset.  The definition of a subject is implicit
for a task sandboxing itself, which makes the reasoning much easier and helps
avoid pitfalls.
