KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel clean

.PHONY: all modules clean
