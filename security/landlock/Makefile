ccflags-$(CONFIG_SECURITY_LANDLOCK) += -Werror=unused-function

obj-$(CONFIG_SECURITY_LANDLOCK) := landlock.o

landlock-y := init.o providers.o hooks.o hooks_fs.o hooks_ptrace.o
