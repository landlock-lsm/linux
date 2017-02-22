================================
Landlock: userland documentation
================================

Landlock rules
==============

eBPF programs are used to create security rules.  They are contained and can
call only a whitelist of dedicated functions. Moreover, they cannot loop, which
protects from denial of service.  More information on BPF can be found in
*Documentation/networking/filter.txt*.


Writing a rule
--------------

To enforce a security policy, a thread first needs to create a Landlock rule.
The easiest way to write an eBPF program depicting a security rule is to write
it in the C language.  As described in *samples/bpf/README.rst*, LLVM can
compile such programs.  Files *samples/bpf/landlock1_kern.c* and those in
*tools/testing/selftests/landlock/rules/* can be used as examples.  The
following example is a simple rule to forbid file creation, whatever syscall
may be used (e.g. open, mkdir, link...).

.. code-block:: c

    static int deny_file_creation(struct landlock_context *ctx)
    {
        if (ctx->arg2 & LANDLOCK_ACTION_FS_NEW)
            return 1;
        return 0;
    }

Once the eBPF program is created, the next step is to create the metadata
describing the Landlock rule.  This metadata includes a subtype which contains
the version of Landlock, the event to which the rule is tied, and optional
Landlock rule abilities.

.. code-block:: c

    static union bpf_prog_subtype subtype = {
        .landlock_rule = {
            .version = 1,
            .event = LANDLOCK_SUBTYPE_EVENT_FS,
        }
    };

The Landlock version is important to inform the kernel which features or
behavior the rule can handle.  The user-space thread should set the lowest
possible version to be as compatible as possible with older kernels.  For the
list of features provided by version, see :ref:`features`.

A Landlock event describes the kind of kernel object for which a rule will be
triggered to allow or deny an action.  For example, the event
LANDLOCK_SUBTYPE_EVENT_FS is triggered every time a landlocked thread performs
an action related to the filesystem (e.g. open, read, write, mount...).

The Landlock rule abilities should only be used if the rule needs a specific
feature such as debugging.  This should be avoided if not strictly necessary.

The next step is to fill a :c:type:`union bpf_attr <bpf_attr>` with
BPF_PROG_TYPE_LANDLOCK, the previously created subtype and other BPF program
metadata.  This bpf_attr must then be passed to the bpf(2) syscall alongside
the BPF_PROG_LOAD command.  If everything is deemed correct by the kernel, the
thread gets a file descriptor referring to this rule.

In the following code, the *insn* variable is an array of BPF instructions
which can be extracted from an ELF file as is done in bpf_load_file() from
*samples/bpf/bpf_load.c*.

.. code-block:: c

    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_LANDLOCK,
        .insn_cnt = sizeof(insn) / sizeof(struct bpf_insn),
        .insns = (__u64) (unsigned long) insn,
        .license = (__u64) (unsigned long) "GPL",
        .prog_subtype = &subtype,
    };
    int rule = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (rule == -1)
        exit(1);


Enforcing a rule
----------------

Once the Landlock rule has been created or received (e.g. through a UNIX
socket), the thread willing to sandbox itself (and its future children) needs
to perform two steps to properly enforce a rule.

The thread must first request to never be allowed to get new privileges with a
call to prctl(2) and the PR_SET_NO_NEW_PRIVS option.  More information can be
found in *Documentation/prctl/no_new_privs.txt*.

.. code-block:: c

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, NULL, 0, 0))
        exit(1);

A thread can apply a rule to itself by using the seccomp(2) syscall.  The
operation is SECCOMP_ADD_LANDLOCK_RULE, the flags must be empty and the *args*
argument must point to a valid Landlock rule file descriptor.

.. code-block:: c

    if (seccomp(SECCOMP_ADD_LANDLOCK_RULE, 0, &rule))
        exit(1);

If the syscall succeeds, the rule is now enforced on the calling thread and
will be enforced on all its subsequently created children of the thread as
well.  Once a thread is landlocked, there is no way to remove this security
policy, only stacking more restrictions is allowed.


.. _inherited_rules:

Inherited rules
---------------

Every new thread resulting from a clone(2) inherits Landlock rule restrictions
from its parent.  This is comparable to the seccomp inheritance as described in
*Documentation/prctl/seccomp_filter.txt*, but differs for rules addition.

If a thread adds a rule for a particular event, then all its future children
and their progeny will inherit all the rules from the same event, whether any
of those rules were added before or after the fork.  This allows a thread to
share its security policy with its children and further restrict them over
time.  If a thread wants its future rules to be propagated, it must then create
at least one rule tied to the same event before any fork.


.. _features:

Landlock features
=================

In order to support new features over time without changing a rule behavior,
every context field, flag or helpers has a minimal Landlock version in which
they are available.  A thread needs to specify this minimal version number in
the subtype :c:type:`struct landlock_rule <landlock_rule>` defined in
*include/uapi/linux/bpf.h*.


Context
-------

The arch and syscall_nr fields may be useful to tighten an access control, but
care must be taken to avoid pitfalls as explain in
*Documentation/prctl/seccomp_filter.txt*.

.. kernel-doc:: include/uapi/linux/bpf.h
    :functions: landlock_context


Landlock event types
--------------------

.. kernel-doc:: include/uapi/linux/bpf.h
    :functions: landlock_subtype_event

.. flat-table:: Event types availability

    * - flags
      - since

    * - LANDLOCK_SUBTYPE_EVENT_FS
      - v1


File system access request
--------------------------

Optional arguments from :c:type:`struct landlock_context <landlock_context>`:

* arg1: filesystem handle
* arg2: action type


File system action types
------------------------

Flags are used to express actions.  This makes it possible to compose actions
and leaves room for future improvements to add more fine-grained action types.

.. kernel-doc:: include/uapi/linux/bpf.h
    :doc: landlock_action_fs

.. flat-table:: FS action types availability

    * - flags
      - since

    * - LANDLOCK_ACTION_FS_EXEC
      - v1

    * - LANDLOCK_ACTION_FS_WRITE
      - v1

    * - LANDLOCK_ACTION_FS_READ
      - v1

    * - LANDLOCK_ACTION_FS_NEW
      - v1

    * - LANDLOCK_ACTION_FS_GET
      - v1

    * - LANDLOCK_ACTION_FS_REMOVE
      - v1

    * - LANDLOCK_ACTION_FS_IOCTL
      - v1

    * - LANDLOCK_ACTION_FS_LOCK
      - v1

    * - LANDLOCK_ACTION_FS_FCNTL
      - v1


Ability types
-------------

The ability of a Landlock rule describes the available features (i.e. context
fields and helpers).  This is useful to abstract user-space privileges for
Landlock rules, which may not need all abilities (e.g. debug).  Only the
minimal set of abilities should be used (e.g. disable debug once in
production).


.. kernel-doc:: include/uapi/linux/bpf.h
    :doc: landlock_subtype_ability

.. flat-table:: Ability types availability

    * - flags
      - since
      - capability

    * - LANDLOCK_SUBTYPE_ABILITY_WRITE
      - v1
      - CAP_SYS_ADMIN

    * - LANDLOCK_SUBTYPE_ABILITY_DEBUG
      - v1
      - CAP_SYS_ADMIN


Helper functions
----------------

See *include/uapi/linux/bpf.h* for functions documentation.

.. flat-table:: Generic functions availability

    * - helper
      - since
      - ability

    * - bpf_map_lookup_elem
      - v1
      - (none)

    * - bpf_map_delete_elem
      - v1
      - LANDLOCK_SUBTYPE_ABILITY_WRITE

    * - bpf_map_update_elem
      - v1
      - LANDLOCK_SUBTYPE_ABILITY_WRITE

    * - bpf_get_current_comm
      - v1
      - LANDLOCK_SUBTYPE_ABILITY_DEBUG

    * - bpf_get_current_pid_tgid
      - v1
      - LANDLOCK_SUBTYPE_ABILITY_DEBUG

    * - bpf_get_current_uid_gid
      - v1
      - LANDLOCK_SUBTYPE_ABILITY_DEBUG

    * - bpf_get_trace_printk
      - v1
      - LANDLOCK_SUBTYPE_ABILITY_DEBUG

.. flat-table:: File system functions availability

    * - helper
      - since
      - ability

    * - bpf_handle_fs_get_mode
      - v1
      - (none)

