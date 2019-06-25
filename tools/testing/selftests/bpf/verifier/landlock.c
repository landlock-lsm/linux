{
	"landlock/fs_pick: always accept",
	.insns = {
		BPF_MOV32_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_LANDLOCK_HOOK,
	.has_prog_subtype = true,
	.prog_subtype = {
		.landlock_hook = {
			.type = LANDLOCK_HOOK_FS_PICK,
			.triggers = LANDLOCK_TRIGGER_FS_PICK_READ,
		}
	},
},
{
	"landlock/fs_pick: read context",
	.insns = {
		BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
		BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_6,
			offsetof(struct landlock_ctx_fs_pick, inode)),
		BPF_MOV32_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_LANDLOCK_HOOK,
	.has_prog_subtype = true,
	.prog_subtype = {
		.landlock_hook = {
			.type = LANDLOCK_HOOK_FS_PICK,
			.triggers = LANDLOCK_TRIGGER_FS_PICK_READ,
		}
	},
},
