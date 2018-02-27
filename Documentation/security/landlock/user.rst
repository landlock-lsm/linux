================================
Landlock: userland documentation
================================

Landlock programs
=================

eBPF programs are used to create security programs.  They are contained and can
call only a whitelist of dedicated functions. Moreover, they cannot loop, which
protects from denial of service.  More information on BPF can be found in
*Documentation/networking/filter.txt*.


Writing a program
-----------------

To enforce a security policy, a thread first needs to create a Landlock program.
The easiest way to write an eBPF program depicting a security program is to write
it in the C language.  As described in *samples/bpf/README.rst*, LLVM can
compile such programs.  Files *samples/bpf/landlock1_kern.c* and those in
*tools/testing/selftests/landlock/* can be used as examples.

Once the eBPF program is created, the next step is to create the metadata
describing the Landlock program.  This metadata includes a subtype which
contains the hook type to which the program is tied and some options.

.. code-block:: c

    union bpf_prog_subtype subtype = {
        .landlock_hook = {
            .type = LANDLOCK_HOOK_FS_PICK,
            .triggers = LANDLOCK_TRIGGER_FS_PICK_OPEN,
        }
    };

A Landlock hook describes the kind of kernel object for which a program will be
triggered to allow or deny an action.  For example, the hook
LANDLOCK_HOOK_FS_PICK can be triggered every time a landlocked thread performs
a set of action related to the filesystem (e.g. open, read, write, mount...).
This actions are identified by the `triggers` bitfield.

The next step is to fill a :c:type:`union bpf_attr <bpf_attr>` with
BPF_PROG_TYPE_LANDLOCK_HOOK, the previously created subtype and other BPF
program metadata.  This bpf_attr must then be passed to the :manpage:`bpf(2)`
syscall alongside the BPF_PROG_LOAD command.  If everything is deemed correct
by the kernel, the thread gets a file descriptor referring to this program.

In the following code, the *insn* variable is an array of BPF instructions
which can be extracted from an ELF file as is done in bpf_load_file() from
*samples/bpf/bpf_load.c*.

.. code-block:: c

    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_LANDLOCK_HOOK,
        .insn_cnt = sizeof(insn) / sizeof(struct bpf_insn),
        .insns = (__u64) (unsigned long) insn,
        .license = (__u64) (unsigned long) "GPL",
        .prog_subtype = &subtype,
        .prog_subtype_size = sizeof(subtype),
    };
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd == -1)
        exit(1);


Enforcing a program
-------------------

Once the Landlock program has been created or received (e.g. through a UNIX
socket), the thread willing to sandbox itself (and its future children) should
perform the following two steps.

The thread should first request to never be allowed to get new privileges with a
call to :manpage:`prctl(2)` and the PR_SET_NO_NEW_PRIVS option.  More
information can be found in *Documentation/prctl/no_new_privs.txt*.

.. code-block:: c

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, NULL, 0, 0))
        exit(1);

A thread can apply a program to itself by using the :manpage:`seccomp(2)` syscall.
The operation is SECCOMP_PREPEND_LANDLOCK_PROG, the flags must be empty and the
*args* argument must point to a valid Landlock program file descriptor.

.. code-block:: c

    if (seccomp(SECCOMP_PREPEND_LANDLOCK_PROG, 0, &fd))
        exit(1);

If the syscall succeeds, the program is now enforced on the calling thread and
will be enforced on all its subsequently created children of the thread as
well.  Once a thread is landlocked, there is no way to remove this security
policy, only stacking more restrictions is allowed.  The program evaluation is
performed from the newest to the oldest.

When a syscall ask for an action on a kernel object, if this action is denied,
then an EACCES errno code is returned through the syscall.


.. _inherited_programs:

Inherited programs
------------------

Every new thread resulting from a :manpage:`clone(2)` inherits Landlock program
restrictions from its parent.  This is similar to the seccomp inheritance as
described in *Documentation/prctl/seccomp_filter.txt*.


Ptrace restrictions
-------------------

A landlocked process has less privileges than a non-landlocked process and must
then be subject to additional restrictions when manipulating another process.
To be allowed to use :manpage:`ptrace(2)` and related syscalls on a target
process, a landlocked process must have a subset of the target process programs.


Chained programs
================

Landlock programs can be chained according to the hook they are tied to.  This
enable to keep a state between multiple program evaluation for an object access
check (e.g. walking through a file path).  The *cookie* field from the context
can be used as a temporary storage shared between a chain of programs.

The following graph is an example of the chain of programs used in
*samples/bpf/landlock1_kern.c*.  The fs_walk program evaluate if a file is
beneath a set of file hierarchy.  The first fs_pick program may be called when
there is a read-like action (i.e. trigger for open, chdir, getattr...).  The
second fs_pick program may be called for write-like actions.  And finally, the
fs_get program is called to tag a file when it is open, receive or when the
current task changes directory.  This tagging is needed to be able to keep the
state of this file evaluation for a next one involving the same opened file.

::

    .---------.
    | fs_walk |
    '---------'
         |
         v
    .---------.
    | fs_pick |  open, chdir, getattr...
    '---------'
         |
         v
    .---------.
    | fs_pick |  create, write, link...
    '---------'
         |
         v
    .--------.
    | fs_get |
    '--------'


Landlock structures and constants
=================================

Hook types
----------

.. kernel-doc:: include/uapi/linux/landlock.h
    :functions: landlock_hook_type


Contexts
--------

.. kernel-doc:: include/uapi/linux/landlock.h
    :functions: landlock_ctx_fs_pick landlock_ctx_fs_walk landlock_ctx_fs_get


Triggers for fs_pick
--------------------

.. kernel-doc:: include/uapi/linux/landlock.h
    :functions: landlock_triggers


Helper functions
----------------

::

    u64 bpf_inode_get_tag(inode, chain)
        @inode: pointer to struct inode
        @chain: pointer to struct landlock_chain
        Return: tag tied to this inode and chain, or zero if none

    int bpf_landlock_set_tag(tag_obj, chain, value)
        @tag_obj: pointer pointing to a taggable object (e.g. inode)
        @chain: pointer to struct landlock_chain
        @value: value of the tag
        Return: 0 on success or negative error code

See *include/uapi/linux/bpf.h* for other functions documentation.


Additional documentation
========================

See https://landlock.io
