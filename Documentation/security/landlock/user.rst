================================
Landlock: userland documentation
================================

Landlock programs
=================

eBPF programs are used to create security programs.  They are contained and can
call only a whitelist of dedicated functions. Moreover, they can only loop
under strict conditions, which protects from denial of service.  More
information on BPF can be found in *Documentation/networking/filter.txt*.


Writing a program
-----------------

To enforce a security policy, a thread first needs to create a Landlock
program.  The easiest way to write an eBPF program depicting a security program
is to write it in the C language.  As described in *samples/bpf/README.rst*,
LLVM can compile such programs.  A simple eBPF program can also be written by
hand has done in *tools/testing/selftests/landlock/*.

Once the eBPF program is created, the next step is to create the metadata
describing the Landlock program.  This metadata includes an expected attach
type which contains the hook type to which the program is tied.

A hook is a policy decision point which exposes the same context type for
each program evaluation.

A Landlock hook describes the kind of kernel object for which a program will be
triggered to allow or deny an action.  For example, the hook
``BPF_LANDLOCK_PTRACE`` can be triggered every time a landlocked thread
performs a set of action related to debugging (cf. :manpage:`ptrace(2)`) or if
the kernel needs to know if a process manipulation requested by something else
is legitimate.

The next step is to fill a :c:type:`struct bpf_load_program_attr
<bpf_load_program_attr>` with ``BPF_PROG_TYPE_LANDLOCK_HOOK``, the expected
attach type and other BPF program metadata.  This bpf_attr must then be passed
to the :manpage:`bpf(2)` syscall alongside the ``BPF_PROG_LOAD`` command.  If
everything is deemed correct by the kernel, the thread gets a file descriptor
referring to this program.

In the following code, the *insn* variable is an array of BPF instructions
which can be extracted from an ELF file as is done in bpf_load_file() from
*samples/bpf/bpf_load.c*.

.. code-block:: c

    int prog_fd;
    struct bpf_load_program_attr load_attr;

    memset(&load_attr, 0, sizeof(struct bpf_load_program_attr));
    load_attr.prog_type = BPF_PROG_TYPE_LANDLOCK_HOOK;
    load_attr.expected_attach_type = BPF_LANDLOCK_PTRACE;
    load_attr.insns = insns;
    load_attr.insns_cnt = sizeof(insn) / sizeof(struct bpf_insn);
    load_attr.license = "GPL";

    prog_fd = bpf_load_program_xattr(&load_attr, log_buf, log_buf_sz);
    if (prog_fd == -1)
        exit(1);


Enforcing a program
-------------------

Once the Landlock program has been created or received (e.g. through a UNIX
socket), the thread willing to sandbox itself (and its future children) should
perform the following two steps.

The thread should first request to never be allowed to get new privileges with a
call to :manpage:`prctl(2)` and the ``PR_SET_NO_NEW_PRIVS`` option.  More
information can be found in *Documentation/prctl/no_new_privs.txt*.

.. code-block:: c

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, NULL, 0, 0))
        exit(1);

A thread can apply a program to itself by using the :manpage:`seccomp(2)` syscall.
The operation is ``SECCOMP_PREPEND_LANDLOCK_PROG``, the flags must be empty and
the *args* argument must point to a valid Landlock program file descriptor.

.. code-block:: c

    if (seccomp(SECCOMP_PREPEND_LANDLOCK_PROG, 0, &fd))
        exit(1);

If the syscall succeeds, the program is now enforced on the calling thread and
will be enforced on all its subsequently created children of the thread as
well.  Once a thread is landlocked, there is no way to remove this security
policy, only stacking more restrictions is allowed.  The program evaluation is
performed from the newest to the oldest.

When a syscall ask for an action on a kernel object, if this action is denied,
then an ``EACCES`` errno code is returned through the syscall.


.. _inherited_programs:

Inherited programs
------------------

Every new thread resulting from a :manpage:`clone(2)` inherits Landlock program
restrictions from its parent.  This is similar to the seccomp inheritance as
described in *Documentation/prctl/seccomp_filter.txt* or any other LSM dealing
with task's :manpage:`credentials(7)`.


Ptrace restrictions
-------------------

A sandboxed process has less privileges than a non-sandboxed process and must
then be subject to additional restrictions when manipulating another process.
To be allowed to use :manpage:`ptrace(2)` and related syscalls on a target
process, a sandboxed process should have a subset of the target process
programs.  This security policy can easily be implemented like in
*tools/testing/selftests/landlock/test_ptrace.c*.


Landlock structures and constants
=================================

Contexts
--------

.. kernel-doc:: include/uapi/linux/landlock.h
    :functions: landlock_context_ptrace


Return types
------------

.. kernel-doc:: include/uapi/linux/landlock.h
    :functions: landlock_ret


Additional documentation
========================

See https://landlock.io
