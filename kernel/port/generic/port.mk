
PORT          ?= /dev/ttyUSB1
DRIVE         ?= /dev/null # If user doesn't specify, burn /dev/null instead of anything potentially important

include port/generic/port_$(CONFIG_CPU).mk

.PHONY: _port_on_config
_port_on_config: _cpu_on_config
	git submodule update --init lib/limine
	git submodule update --init lib/uacpi

image: build $(OUTPUT)/image.hdd

burn: image
	sudo dd if=$(OUTPUT)/image.hdd of=$(DRIVE) bs=1M oflag=sync conv=nocreat

.PHONY: monitor
monitor:
	echo -e "\033[1mType ^A^X to exit.\033[0m"
	picocom -q -b 115200 '$(PORT)' \
	| ../tools/address-filter.py -A $(CROSS_COMPILE)addr2line '$(OUTPUT)/badger-os.elf'; echo -e '\033[0m'
