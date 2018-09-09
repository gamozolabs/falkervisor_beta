all: atropos.vfd
	copy brownie.vfd y:\tftpd\fleeb.bin

bochs: all
	@"D:\emulation\bochs\bochs-20141121-msvc-src\bochs-20141121\bochs.exe" -f bochsrc.bxrc

atropos.vfd:
	nasm -f bin -o brownie.vfd srcs/boot/boot_bsp.asm

clean:
	-@del brownie.vfd

