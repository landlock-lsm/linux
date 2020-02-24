=================================
Landlock: userspace documentation
=================================

Landlock rules
==============

A Landlock rule enables to describe an action on an object.  An object is
currently a file hierarchy, and the related filesystem actions are defined in
`Access rights`_.  A set of rules are aggregated in a ruleset, which can then
restricts the thread enforcing it, and its future children.


Defining and enforcing a security policy
----------------------------------------

Before defining a security policy, an application should first probe for the
features supported by the running kernel, which is important to be compatible
with older kernels.  This can be done thanks to the `landlock` syscall (cf.
:ref:`syscall`).

.. code-block:: c

    struct landlock_attr_features attr_features;

    if (landlock(LANDLOCK_CMD_GET_FEATURES, LANDLOCK_OPT_GET_FEATURES,
            sizeof(attr_features), &attr_features)) {
        perror("Failed to probe the Landlock supported features");
        return 1;
    }

Then, we need to create the ruleset that will contains our rules.  For this
example, the ruleset will contains rules which only allow read actions, but
write actions will be denied.  The ruleset then needs to handle both of these
kind of actions.  To have a backward compatibility, these actions should be
ANDed with the supported ones.

.. code-block:: c

    int ruleset_fd;
    struct landlock_attr_ruleset ruleset = {
        .handled_access_fs =
            LANDLOCK_ACCESS_FS_READ |
            LANDLOCK_ACCESS_FS_READDIR |
            LANDLOCK_ACCESS_FS_EXECUTE |
            LANDLOCK_ACCESS_FS_WRITE |
            LANDLOCK_ACCESS_FS_TRUNCATE |
            LANDLOCK_ACCESS_FS_CHMOD |
            LANDLOCK_ACCESS_FS_CHOWN |
            LANDLOCK_ACCESS_FS_CHGRP |
            LANDLOCK_ACCESS_FS_LINK_TO |
            LANDLOCK_ACCESS_FS_RENAME_FROM |
            LANDLOCK_ACCESS_FS_RENAME_TO |
            LANDLOCK_ACCESS_FS_RMDIR |
            LANDLOCK_ACCESS_FS_UNLINK |
            LANDLOCK_ACCESS_FS_MAKE_CHAR |
            LANDLOCK_ACCESS_FS_MAKE_DIR |
            LANDLOCK_ACCESS_FS_MAKE_REG |
            LANDLOCK_ACCESS_FS_MAKE_SOCK |
            LANDLOCK_ACCESS_FS_MAKE_FIFO |
            LANDLOCK_ACCESS_FS_MAKE_BLOCK |
            LANDLOCK_ACCESS_FS_MAKE_SYM,
    };

    ruleset.handled_access_fs &= attr_features.access_fs;
    ruleset_fd = landlock(LANDLOCK_CMD_CREATE_RULESET,
                    LANDLOCK_OPT_CREATE_RULESET, sizeof(ruleset), &ruleset);
    if (ruleset_fd < 0) {
        perror("Failed to create a ruleset");
        return 1;
    }

We can now add a new rule to this ruleset thanks to the returned file
descriptor referring to this ruleset.  The rule will only enable to read the
file hierarchy ``/usr``.  Without other rule, write actions would then be
denied by the ruleset.  To add ``/usr`` to the ruleset, we open it with the
``O_PATH`` flag and fill the &struct landlock_attr_path_beneath with this file
descriptor.

.. code-block:: c

    int err;
    struct landlock_attr_path_beneath path_beneath = {
        .ruleset_fd = ruleset_fd,
        .allowed_access =
            LANDLOCK_ACCESS_FS_READ |
            LANDLOCK_ACCESS_FS_READDIR |
            LANDLOCK_ACCESS_FS_EXECUTE,
    };

    path_beneath.allowed_access &= attr_features.access_fs;
    path_beneath.parent_fd = open("/usr", O_PATH | O_CLOEXEC);
    if (path_beneath.parent_fd < 0) {
        perror("Failed to open file");
        close(ruleset_fd);
        return 1;
    }
    err = landlock(LANDLOCK_CMD_ADD_RULE, LANDLOCK_OPT_ADD_RULE_PATH_BENEATH,
            sizeof(path_beneath), &path_beneath);
    close(path_beneath.parent_fd);
    if (err) {
        perror("Failed to update ruleset");
        close(ruleset_fd);
        return 1;
    }

We now have a ruleset with one rule allowing read access to ``/usr`` while
denying all accesses featured in ``attr_features.access_fs`` to everything else
on the filesystem.  The next step is to restrict the current thread from
gaining more privileges (e.g. thanks to a SUID binary).

.. code-block:: c

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("Failed to restrict privileges");
        close(ruleset_fd);
        return 1;
    }

The current thread is now ready to sandbox itself with the ruleset.

.. code-block:: c

    struct landlock_attr_enforce attr_enforce = {
        .ruleset_fd = ruleset_fd,
    };

    if (landlock(LANDLOCK_CMD_ENFORCE_RULESET, LANDLOCK_OPT_ENFORCE_RULESET,
            sizeof(attr_enforce), &attr_enforce)) {
        perror("Failed to enforce ruleset");
        close(ruleset_fd);
        return 1;
    }
    close(ruleset_fd);

If this last system call succeeds, the current thread is now restricted and
this policy will be enforced on all its subsequently created children as well.
Once a thread is landlocked, there is no way to remove its security policy,
only adding more restrictions is allowed.  These threads are now in a new
Landlock domain, merge of their parent one (if any) with the new ruleset.

A full working code can be found in `samples/landlock/sandboxer.c`_.


Inheritance
-----------

Every new thread resulting from a :manpage:`clone(2)` inherits Landlock program
restrictions from its parent.  This is similar to the seccomp inheritance (cf.
:doc:`/userspace-api/seccomp_filter`) or any other LSM dealing with task's
:manpage:`credentials(7)`.  For instance, one process' thread may apply
Landlock rules to itself, but they will not be automatically applied to other
sibling threads (unlike POSIX thread credential changes, cf.
:manpage:`nptl(7)`).


Ptrace restrictions
-------------------

A sandboxed process has less privileges than a non-sandboxed process and must
then be subject to additional restrictions when manipulating another process.
To be allowed to use :manpage:`ptrace(2)` and related syscalls on a target
process, a sandboxed process should have a subset of the target process rules,
which means the tracee must be in a sub-domain of the tracer.


.. _syscall:

The `landlock` syscall and its arguments
========================================

.. kernel-doc:: security/landlock/syscall.c
    :functions: sys_landlock

Commands
--------

.. kernel-doc:: include/uapi/linux/landlock.h
    :functions: landlock_cmd

Options
-------

.. kernel-doc:: include/uapi/linux/landlock.h
    :functions: options_intro
                options_get_features options_create_ruleset
                options_add_rule options_enforce_ruleset

Attributes
----------

.. kernel-doc:: include/uapi/linux/landlock.h
    :functions: landlock_attr_features landlock_attr_ruleset
                landlock_attr_path_beneath landlock_attr_enforce

Access rights
-------------

.. kernel-doc:: include/uapi/linux/landlock.h
    :functions: fs_access


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

See https://landlock.io


.. Links
.. _samples/landlock/sandboxer.c: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/samples/landlock/sandboxer.c
.. _tools/testing/selftests/landlock/: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/tools/testing/selftests/landlock/
.. _tools/testing/selftests/landlock/test_ptrace.c: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/tools/testing/selftests/landlock/test_ptrace.c
