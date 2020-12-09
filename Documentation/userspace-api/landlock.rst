.. SPDX-License-Identifier: GPL-2.0
.. Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
.. Copyright © 2019-2020 ANSSI

=====================================
Landlock: unprivileged access control
=====================================

:Author: Mickaël Salaün
:Date: December 2020

The goal of Landlock is to enable to restrict ambient rights (e.g. global
filesystem access) for a set of processes.  Because Landlock is a stackable
LSM, it makes possible to create safe security sandboxes as new security layers
in addition to the existing system-wide access-controls. This kind of sandbox
is expected to help mitigate the security impact of bugs or
unexpected/malicious behaviors in user space applications.  Landlock empowers
any process, including unprivileged ones, to securely restrict themselves.

Landlock rules
==============

A Landlock rule describes an action on an object.  An object is currently a
file hierarchy, and the related filesystem actions are defined in `Access
rights`_.  A set of rules is aggregated in a ruleset, which can then restrict
the thread enforcing it, and its future children.

Defining and enforcing a security policy
----------------------------------------

We first need to create the ruleset that will contain our rules.  For this
example, the ruleset will contain rules which only allow read actions, but
write actions will be denied.  The ruleset then needs to handle both of these
kind of actions.

.. code-block:: c

    int ruleset_fd;
    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs =
            LANDLOCK_ACCESS_FS_EXECUTE |
            LANDLOCK_ACCESS_FS_WRITE_FILE |
            LANDLOCK_ACCESS_FS_READ_FILE |
            LANDLOCK_ACCESS_FS_READ_DIR |
            LANDLOCK_ACCESS_FS_REMOVE_DIR |
            LANDLOCK_ACCESS_FS_REMOVE_FILE |
            LANDLOCK_ACCESS_FS_MAKE_CHAR |
            LANDLOCK_ACCESS_FS_MAKE_DIR |
            LANDLOCK_ACCESS_FS_MAKE_REG |
            LANDLOCK_ACCESS_FS_MAKE_SOCK |
            LANDLOCK_ACCESS_FS_MAKE_FIFO |
            LANDLOCK_ACCESS_FS_MAKE_BLOCK |
            LANDLOCK_ACCESS_FS_MAKE_SYM,
    };

    ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        perror("Failed to create a ruleset");
        return 1;
    }

We can now add a new rule to this ruleset thanks to the returned file
descriptor referring to this ruleset.  The rule will only allow reading the
file hierarchy ``/usr``.  Without another rule, write actions would then be
denied by the ruleset.  To add ``/usr`` to the ruleset, we open it with the
``O_PATH`` flag and fill the &struct landlock_path_beneath_attr with this file
descriptor.

.. code-block:: c

    int err;
    struct landlock_path_beneath_attr path_beneath = {
        .allowed_access =
            LANDLOCK_ACCESS_FS_EXECUTE |
            LANDLOCK_ACCESS_FS_READ_FILE |
            LANDLOCK_ACCESS_FS_READ_DIR,
    };

    path_beneath.parent_fd = open("/usr", O_PATH | O_CLOEXEC);
    if (path_beneath.parent_fd < 0) {
        perror("Failed to open file");
        close(ruleset_fd);
        return 1;
    }
    err = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                            &path_beneath, 0);
    close(path_beneath.parent_fd);
    if (err) {
        perror("Failed to update ruleset");
        close(ruleset_fd);
        return 1;
    }

We now have a ruleset with one rule allowing read access to ``/usr`` while
denying all other handled accesses for the filesystem.  The next step is to
restrict the current thread from gaining more privileges (e.g. thanks to a SUID
binary).

.. code-block:: c

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("Failed to restrict privileges");
        close(ruleset_fd);
        return 1;
    }

The current thread is now ready to sandbox itself with the ruleset.

.. code-block:: c

    if (landlock_enforce_ruleset_current(ruleset_fd, 0)) {
        perror("Failed to enforce ruleset");
        close(ruleset_fd);
        return 1;
    }
    close(ruleset_fd);

If the `landlock_enforce_ruleset_current` system call succeeds, the current
thread is now restricted and this policy will be enforced on all its
subsequently created children as well.  Once a thread is landlocked, there is
no way to remove its security policy; only adding more restrictions is allowed.
These threads are now in a new Landlock domain, merge of their parent one (if
any) with the new ruleset.

Full working code can be found in `samples/landlock/sandboxer.c`_.

Inheritance
-----------

Every new thread resulting from a :manpage:`clone(2)` inherits Landlock domain
restrictions from its parent.  This is similar to the seccomp inheritance (cf.
:doc:`/userspace-api/seccomp_filter`) or any other LSM dealing with task's
:manpage:`credentials(7)`.  For instance, one process's thread may apply
Landlock rules to itself, but they will not be automatically applied to other
sibling threads (unlike POSIX thread credential changes, cf.
:manpage:`nptl(7)`).

When a thread sandboxes itself, we have the guarantee that the related security
policy will stay enforced on all this thread's descendants.  This allows
creating standalone and modular security policies per application, which will
automatically be composed between themselves according to their runtime parent
policies.

A sandboxed thread can add more constraints to itself with a new enforced
ruleset.  This complementary policy inherits from the previous enforced
rulesets.  Access to a file path is granted if, for each policy layer, at least
one rule encountered on the path (from the file to the root) grants the access.

Ptrace restrictions
-------------------

A sandboxed process has less privileges than a non-sandboxed process and must
then be subject to additional restrictions when manipulating another process.
To be allowed to use :manpage:`ptrace(2)` and related syscalls on a target
process, a sandboxed process should have a subset of the target process rules,
which means the tracee must be in a sub-domain of the tracer.

Kernel interface
================

Access rights
-------------

.. kernel-doc:: include/uapi/linux/landlock.h
    :identifiers: fs_access

Creating a new ruleset
----------------------

.. kernel-doc:: security/landlock/syscall.c
    :identifiers: sys_landlock_create_ruleset

.. kernel-doc:: include/uapi/linux/landlock.h
    :identifiers: landlock_ruleset_attr

Extending a ruleset
-------------------

.. kernel-doc:: security/landlock/syscall.c
    :identifiers: sys_landlock_add_rule

.. kernel-doc:: include/uapi/linux/landlock.h
    :identifiers: landlock_rule_type landlock_path_beneath_attr

Enforcing a ruleset
-------------------

.. kernel-doc:: security/landlock/syscall.c
    :identifiers: sys_landlock_enforce_ruleset_current

Current limitations
===================

Ruleset layers
--------------

There is a limit of 64 layers of stacked rulesets.  This can be an issue for a
task willing to enforce a new ruleset in complement to its 64 inherited
rulesets.  Once this limit is reached, sys_landlock_enforce_ruleset_current()
returns E2BIG.  It is then strongly suggested to carefully build rulesets once
in the life of a thread, especially for applications able to launch other
applications which may also want to sandbox themselves (e.g. shells, container
managers, etc.).

Memory usage
------------

Kernel memory allocated to create rulesets is accounted and can be restricted
by the :doc:`/admin-guide/cgroup-v1/memory`.

File renaming and linking
-------------------------

Because Landlock targets unprivileged access controls, it is needed to properly
handle composition of rules.  Such property also implies rules nesting.
Properly handling multiple layers of ruleset, each one of them able to restrict
access to files, also implies to inherit the ruleset restrictions from a parent
to its hierarchy.  Because files are identified and restricted by their
hierarchy, moving or linking a file from one directory to another imply to
propagate the hierarchy constraints.  To protect against privilege escalations
through renaming or linking, and for the sack of simplicity, Landlock currently
limits linking and renaming to the same directory.  Future Landlock evolutions
will enable more flexibility for renaming and linking, with dedicated ruleset
flags.

OverlayFS
---------

An OverlayFS mount point consists of upper and lower layers.  It is currently
not possible to reliably infer which underlying file hierarchy matches an
OverlayFS path composed of such layers.  It is then not currently possible to
track the source of an indirect access request, and then not possible to
properly identify and allow an unified OverlayFS hierarchy.  Restricting files
in an OverlayFS mount point works, but files allowed in one layer may not be
allowed in a related OverlayFS mount point.  A future Landlock evolution will
make possible to properly work with OverlayFS, according to a dedicated ruleset
flag.


Special filesystems
-------------------

Access to regular files and directories can be restricted by Landlock,
according to the handled accesses of a ruleset.  However, files which do not
come from a user-visible filesystem (e.g. pipe, socket), but can still be
accessed through /proc/self/fd/, cannot currently be restricted.  Likewise,
some special kernel filesystems such as nsfs which can be accessed through
/proc/self/ns/, cannot currently be restricted.  For now, these kind of special
paths are then always allowed.  Future Landlock evolutions will enable to
restrict such paths, with dedicated ruleset flags.

Questions and answers
=====================

What about user space sandbox managers?
---------------------------------------

Using user space process to enforce restrictions on kernel resources can lead
to race conditions or inconsistent evaluations (i.e. `Incorrect mirroring of
the OS code and state
<https://www.ndss-symposium.org/ndss2003/traps-and-pitfalls-practical-problems-system-call-interposition-based-security-tools/>`_).

What about namespaces and containers?
-------------------------------------

Namespaces can help create sandboxes but they are not designed for
access-control and then miss useful features for such use case (e.g. no
fine-grained restrictions).  Moreover, their complexity can lead to security
issues, especially when untrusted processes can manipulate them (cf.
`Controlling access to user namespaces <https://lwn.net/Articles/673597/>`_).

Additional documentation
========================

* :doc:`/security/landlock`
* https://landlock.io

.. Links
.. _samples/landlock/sandboxer.c:
   https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/samples/landlock/sandboxer.c
