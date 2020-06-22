

ifneq ($(KERNELRELEASE),)
	obj-m := detectiontool.o

else

define ANNOUNCE_BODY_1
--------------------------------------------------------------------------
Please execute next command "make client" to create the userspace tool. 
--------------------------------------------------------------------------
endef

define ANNOUNCE_BODY_2
--------------------------------------------------------------------------
Use the command "insmod detectiontool.ko" to load the kernel module.
--------------------------------------------------------------------------
endef

export ANNOUNCE_BODY
	python_version_full := $(wordlist 2,4,$(subst ., ,$(shell python3 --version 2>&1)))
	python_version_major := $(word 1,${python_version_full})
	python_version_minor := $(word 2,${python_version_full})
	KERNELDIR ?=/lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

kernel:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	@echo "$$ANNOUNCE_BODY_1"
client: detectiontool.ko
	gcc -fPIC client.c $$(python$(python_version_major).$(python_version_minor)-config --cflags) $$(python$(python_version_major).$(python_version_minor)-config --ldflags) -o client
	@echo "$$ANNOUNCE_BODY_2"
endif


clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	rm -rf *.ko *.mod.* *.o *.order *.symvers client 
