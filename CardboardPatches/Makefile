CC=arm-none-eabi-gcc
CFLAGS=-fPIE -fno-zero-initialized-in-bss -std=gnu99 -mcpu=mpcore -fshort-wchar -Os
ASFLAGS=-nostartfiles -nostdlib
LD=arm-none-eabi-gcc
LDFLAGS=-T linker.x -nodefaultlibs -nostdlib -pie
OBJCOPY=arm-none-eabi-objcopy
OBJCOPYFLAGS=

all: recv.bin send.bin create.bin create_pre.bin reboot.bin hook_recv.dat hook_send.dat hook_create.dat

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

%.ro: %.S
	$(CC) -c -o $@ $< $(ASFLAGS)

%.elf: %.o
	$(LD) -o $@ $^ $(LDFLAGS)

%.bin: %.elf
	$(OBJCOPY) -O binary $^ $@

%.dat: %.ro
	$(OBJCOPY) -O binary $^ $@

.PHONY: clean

clean:
	rm -rf *~ *.o *.elf *.bin *.s *.dat
