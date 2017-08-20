# Catch defined but unused hooks, e.g. error out if a HOOK_NEW_FS(foo) is not
# used with a HOOK_INIT_FS(foo) in the struct security_hook_list
# landlock_hooks.
ccflags-$(CONFIG_SECURITY_LANDLOCK) += -Werror=unused-function

obj-$(CONFIG_SECURITY_LANDLOCK) := landlock.o

landlock-y := init.o providers.o hooks.o hooks_ptrace.o hooks_fs.o
