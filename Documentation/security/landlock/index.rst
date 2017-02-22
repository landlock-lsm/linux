============
Landlock LSM
============

Landlock is a stackable Linux Security Module (LSM) that makes it possible to
create security sandboxes.  This kind of sandbox is expected to help mitigate
the security impact of bugs or unexpected/malicious behaviors in user-space
applications.  The current version allows only a process with the global
CAP_SYS_ADMIN capability to create such sandboxes but the ultimate goal of
Landlock is to empower any process, including unprivileged ones, to securely
restrict themselves.  Landlock is inspired by seccomp-bpf but instead of
filtering syscalls and their raw arguments, a Landlock rule can inspect the use
of kernel objects like files and hence make a decision according to the kernel
semantic.

.. toctree::

    user
    kernel
