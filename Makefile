EXTRACT := $(M)/extract_symbol.sh
SYSCALL_TBL = 0x$(shell $(EXTRACT) sys_call_table)
DO_FORK = 0x$(shell $(EXTRACT) _do_fork)
DO_EXIT = 0x$(shell $(EXTRACT) do_exit)
DO_GROUP_EXIT = 0x$(shell $(EXTRACT) do_group_exit)
SYS_CLONE = 0x$(shell $(EXTRACT) sys_clone)

obj-m := systblhook.o
systblhook-objs := main_linux.o
ccflags-y := -O2 -Wno-format -Wno-declaration-after-statement -Wno-unused-function -std=gnu99
ccflags-y += -DSYSCALL_TBL=$(SYSCALL_TBL) -DDO_FORK=$(DO_FORK) -DDO_EXIT=$(DO_EXIT) -DDO_GROUP_EXIT=$(DO_GROUP_EXIT) -DSYS_CLONE=$(SYS_CLONE)

BIN := systblhook.ko
KVERSION := $(shell uname -r)
KDIR := /lib/modules/$(KVERSION)
KBUILD := $(KDIR)/build
PWD := $(shell pwd)
MAKEFLAGS += --no-print-directory

all:
	@make -C $(KBUILD) M=$(PWD) modules

clean:
	@make -C $(KBUILD) M=$(PWD) clean

show_sym:
	@echo "$(DO_FORK) $(DO_EXIT)"

load:
	@echo Loading $(BIN)
	@insmod $(BIN)

unload:
	@echo Unloading $(BIN)
	@rmmod $(BIN)

