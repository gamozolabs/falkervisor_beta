[org  0x7C00]
[bits 16]

%define PXE

%include "srcs/defines.asm"

; boot_bsp
;
; Summary:
;
; This is where the BIOS initially passes over execution. Here we just ensure
; interrupts are disabled and segments are zeroed out. After this we quickly
; go into rmland to continue our real mode needs.
;
; Optimization:
;
; Readability
;
boot_bsp:
	; Disable interrupts until we need them
	cli
	cld

	; Clear all segments
	xor ax, ax
	mov es, ax
	mov ds, ax
	mov fs, ax
	mov gs, ax
	mov ss, ax

	; Set up the stack
	mov sp, 0x7000

	; Ensure cs is zero
	jmp 0x0000:rmland

; rmland
;
; Summary:
;
; This is the BSP real-mode environment where we ensure we use everything
; we need from the BIOS, such as setting the video mode and loading other
; sectors, and then we continue on setting the A20 line and transitioning into
; protected mode.
;
; Optimization:
;
; Readability
;
rmland:
	; Go into VGA mode 3 (80x25 16-colour mode)
	mov ax, 0x0003
	int 0x10

%ifndef PXE
	; Drive reset
	xor ah, ah
	int 0x13
	jc  short .halt

	xor cx, cx
	mov es, cx       ; Store es for the segment we read to
	mov ax, 0x0212   ; Read 18 sectors
	mov cx, 0x0001   ; Read from track 0, sector 1
	xor dh, dh       ; Read from head 0 on the drive booted from
	mov bx, 0x7C00   ; Read to 0000:7C00
	int 0x13         ; Read the sectors
	cli              ; Hyper-V... what the fuck are you doing m8?
	jc  short .halt

	xor cx, cx
	mov es, cx       ; Store es for the segment we read to
	mov ax, 0x0212   ; Read 18 sectors
	mov cx, 0x0001   ; Read from track 0, sector 1
	mov dh, 1        ; Read from head 1 on the drive booted from
	mov bx, 0xA000   ; Read to 0000:A000
	int 0x13         ; Read the sectors
	cli              ; Hyper-V... what the fuck are you doing m8?
	jc  short .halt
%endif

	; Blindly set the A20 line
	in    al, 0x92
	or    al, 2
	out 0x92, al

	; Get the e820 memory map
	call gen_memory_map

	; Load the gdt (for 32-bit proteted mode)
	lgdt [gdt]

	; Set the protection bit
	mov eax, cr0
	or   al, (1 << 0)
	mov cr0, eax

	; We go to protected land now!
	jmp 0x0008:pmland

.halt:
	hlt
	jmp short .halt

%define CONFIG_PORT 0x2e

%define INDEX_PORT 0x2e
%define DATA_PORT  0x2f

%define START_CONFIG_KEY 0x55
%define END_CONFIG_KEY   0xaa

%define RUNTIME_REGS_IO_PORT 0x400

gen_memory_map:
	; Set the entry count to 0
	mov word [MEMORY_MAP_LOC], 0

	mov  di, MEMORY_MAP_LOC + 0x20
	xor ebx, ebx

get_e820:
	; Update the count
	inc word [MEMORY_MAP_LOC]

	mov eax, 0x0000E820
	mov ecx, 0x20
	mov edx, 0x534D4150
	int 0x15
	jc  e820_end

	cmp eax, 0x534D4150
	jne e820_end

	add  di, 0x20
	cmp ebx, 0
	jne get_e820

e820_end:
	ret

; -----------------------------------------------------------------------

; 32-bit protected mode GDT

align 8
gdt_base:
	dq 0x0000000000000000
	dq 0x00CF9A000000FFFF
	dq 0x00CF92000000FFFF

gdt:
	dw (gdt - gdt_base) - 1
	dd gdt_base

; -----------------------------------------------------------------------

[bits 32]

; pmland
;
; Summary:
;
; This is our BSP protected mode landing point. Here we set up data selectors,
; enable the IO APIC, and send INIT-SIPI-SIPI to all other APs.
;
; Optimization:
;
; Readability
;
pmland:
	; Set up all data selectors
	mov ax, 0x10
	mov es, ax
	mov ds, ax
	mov fs, ax
	mov ss, ax
	mov gs, ax

	; Zero out the page table
	mov edi, 0x00100000
	mov cr3, edi
	mov ecx, (0x0010b000 - 0x00100000)
	xor eax, eax
	rep stosb

	; Identity map
	;
	; 0x00100000 - 0x00101000 - PML4T (512 GB pages)
	; 0x00101000 - 0x00102000 - PDPT  (  1 GB pages)

	; cephys (Cache enabled physical)
	;
	; 0x00102000 - 0x00103000 - PDPT  (  1 GB pages)

	; Set up PML4T
	mov edi, cr3
	mov dword [edi + 0x00], 0x00101003 ; Identity map
	mov dword [edi + 0x04], 0x00000000 ; Identity map
	mov dword [edi + 0x08], 0x00102003 ; cephys
	mov dword [edi + 0x0c], 0x00000001 ; cephys high
	mov dword [edi + 0x10], 0x00103003 ; PNM node 0
	mov dword [edi + 0x14], 0x00000001 ; PNM node 0 high
	mov dword [edi + 0x18], 0x00104003 ; PNM node 1
	mov dword [edi + 0x1c], 0x00000001 ; PNM node 1 high
	mov dword [edi + 0x20], 0x00105003 ; PNM node 2
	mov dword [edi + 0x24], 0x00000001 ; PNM node 2 high
	mov dword [edi + 0x28], 0x00106003 ; PNM node 3
	mov dword [edi + 0x2c], 0x00000001 ; PNM node 3 high
	mov dword [edi + 0x30], 0x00107003 ; PNM node 4
	mov dword [edi + 0x34], 0x00000001 ; PNM node 4 high
	mov dword [edi + 0x38], 0x00108003 ; PNM node 5
	mov dword [edi + 0x3c], 0x00000001 ; PNM node 5 high
	mov dword [edi + 0x40], 0x00109003 ; PNM node 6
	mov dword [edi + 0x44], 0x00000001 ; PNM node 6 high
	mov dword [edi + 0x48], 0x0010a003 ; PNM node 7
	mov dword [edi + 0x4c], 0x00000001 ; PNM node 7 high
	add edi, 0x1000

	; Set up the 1GB PDPTEs for the identity map
	; Present, writable, write through, cache disable, page size
	mov eax, 0x83 ; Low 32-bits
	xor edx, edx  ; High 32-bits
	mov ecx, 512
.set1Gentry:
	mov dword [edi + 0], eax ; Low bits
	mov dword [edi + 4], edx ; High bits

	add eax, (1 * 1024 * 1024 * 1024)
	adc edx, 0

	add edi, 8
	dec ecx
	jnz short .set1Gentry

	jmp ap_pmland

; Must be aligned to ensure safe to RW from multiple threads
;
; This is the only place you can legally store globals outside of the fs
; segment. When cores_reloc == num_cores these all become invalid and illegal
; to operate on! We relocate entirely and thus globals are forbidden after all
; cores have relocated! You can access the values read only by using the rel
; prefix as they have been relocated properly
align 8
proc_id:     dq 0
cores_reloc: dq 0
num_cores:   dq NUM_CORES

times 510-($-$$) db 0
dw 0xAA55

%include "srcs/boot/irqs.asm"

times 0x1400-($-$$) db 0

%include "srcs/boot/boot_ap.asm"

times 0x2400-($-$$) db 0

%include "srcs/mm/mm.asm"
%include "srcs/io/serial.asm"
%include "srcs/disp/console.asm"
%include "srcs/time/time.asm"
%include "srcs/boot/program.asm"
%include "srcs/net/i825xx.asm"
%include "srcs/net/x540.asm"
%include "srcs/net/falktp.asm"
%include "srcs/data/pqueue.asm"
%include "srcs/disk/ide.asm"
%include "srcs/dstruc/flut.asm"
%include "srcs/os/win32.asm"
%include "srcs/emu/ide.asm"
%include "srcs/vm/snapshot.asm"
%include "srcs/fuzzers/generic.asm"
;%include "srcs/fuzzers/defender.asm"
%include "srcs/fuzzers/pdf.asm"
;%include "srcs\fuzzers\word.asm"

kern_size: equ ($-$$)

%ifndef PXE
times (1474560)-($-$$) db 0
%else
times (32 * 1024)-($-$$) db 0
%endif

