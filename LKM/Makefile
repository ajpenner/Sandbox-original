obj-m += usblcd.o usbqmm.o cdc-qmm.o #usb-serial.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
