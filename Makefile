PROJECT    := epk
MODULE_DIR := $(PWD)
KERNEL_DIR := /lib/modules/$(shell uname -r)/build
MOD_EXISTS := $(shell lsmod | grep -o $(PROJECT))
obj-m += $(PROJECT).o

all:
	@make -C $(KERNEL_DIR) M=$(MODULE_DIR) modules

clean:
	@make -C $(KERNEL_DIR) M=$(MODULE_DIR) clean

test:
	@if [ ! -z "$(MOD_EXISTS)" ]; then \
		sudo rmmod $(PROJECT); \
	fi
	@sudo insmod $(PROJECT).ko
	@sudo chmod 0666 /sys/kernel/epk/verify
