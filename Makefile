KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

CC = x86_64-linux-gnu-gcc

PROXY_SRC = userspace/pciem_uproxy.c
PROXY_BIN = userspace/pciem_uproxy

all: modules proxy

modules:
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel modules

proxy: $(PROXY_SRC)
	$(CC) -o $(PROXY_BIN) $(PROXY_SRC) -Wall -O2

clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel clean
	rm -f $(PROXY_BIN)

.PHONY: all modules proxy clean