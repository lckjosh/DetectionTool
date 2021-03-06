ifneq ($(KERNELRELEASE),)
	obj-m := detectiontool.o
	detectiontool-objs := src/main.o src/hook_syscalls.o src/hook_fops.o src/hook_networks.o src/detectmodules.o
	HEADERS := $(PWD)/include
	ccflags-y += -I$(HEADERS)

else
	KERNELDIR ?=/lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

python_version_full := $(wordlist 2,4,$(subst ., ,$(shell python3 --version 2>&1)))
python_version_major := $(word 1,${python_version_full})
python_version_minor := $(word 2,${python_version_full})

all: kernel client

kernel:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

client: detectiontool.ko
	gcc -fPIC src/client.c $$(python$(python_version_major).$(python_version_minor)-config --cflags) $$(python$(python_version_major).$(python_version_minor)-config --ldflags) -o client
endif

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	rm -rf *.ko *.mod.* *.o *.order *.symvers client