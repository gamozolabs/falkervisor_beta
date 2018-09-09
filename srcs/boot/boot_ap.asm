[bits 16]

; boot_ap
;
; Summary:
;
; This is the real mode entry point for all APs. This function sets the A20
; line, loads the GDT, and goes into protected mode.
;
; Optimization:
;
; Readability
;
boot_ap:
	cli

	; Blindly set the A20 line
	in    al, 0x92
	or    al, 2
	out 0x92, al

	; Load the gdt (for 32-bit proteted mode)
	lgdt [gdt]

	; Set the protection bit
	mov eax, cr0
	or   al, (1 << 0)
	mov cr0, eax

	; We go to protected land now!
	jmp 0x0008:ap_pmland

[bits 32]

; ap_pmland
;
; Summary:
;
; This is the protected mode entry point for all APs. This function sets up
; paging, enables long mode, and loads the 64-bit gdt.
;
; Optimization:
;
; Readability
;
ap_pmland:
	; Set up all data selectors
	mov ax, 0x10
	mov es, ax
	mov ds, ax
	mov fs, ax
	mov ss, ax
	mov gs, ax

	; Enable SSE
	mov eax, cr0
	btr eax, 2   ; Disable CR0.EM
	bts eax, 1   ; Enable  CR0.MP
	mov cr0, eax

	; Enable OSFXSR and OSXSAVE and OSXMMEXCPT
	mov eax, cr4
	bts eax, 9
	bts eax, 18
	bts eax, 10
	mov cr4, eax

	; Disable paging
	mov eax, cr0
	and eax, 0x7FFFFFFF
	mov cr0, eax

	; Set up CR3
	mov edi, 0x00100000
	mov cr3, edi

	; Enable PAE
	mov eax, cr4
	or  eax, (1 << 5)
	mov cr4, eax

	; Enable long mode
	mov ecx, 0xC0000080
	rdmsr
	or  eax, (1 << 8)
	wrmsr

	; Enable paging
	mov eax, cr0
	or  eax, (1 << 31)
	mov cr0, eax

	; Load the 64-bit GDT and jump to the long mode code
	lgdt [gdt64]
	jmp  0x08:lmland

align 8
gdt64_base:
	dq 0x0000000000000000
	dq 0x0020980000000000
	dq 0x0000900000000000

gdt64:
	.len:  dw (gdt64 - gdt64_base) - 1
	.base: dq gdt64_base

[bits 64]

init_pic:
	push rax

	; Start PIC init
	mov al, (PIC_INIT | PIC_ICW4)
	out MPIC_CTRL, al
	out SPIC_CTRL, al

	; IRQ 0-7 now based at int IRQ07_MAP (32)
	; IRQ 8-F now based at int IRQ8F_MAP (40)
	mov al, IRQ07_MAP
	out MPIC_DATA, al
	mov al, IRQ8F_MAP
	out SPIC_DATA, al

	; Inform the MPIC about the SPIC and inform the SPIC about the cascade
	mov al, 0x04
	out MPIC_DATA, al
	mov al, 0x02
	out SPIC_DATA, al

	; Set 8086 mode
	mov al, PIC_8086
	out MPIC_DATA, al
	out SPIC_DATA, al

	; Zero out the masks
	xor al, al
	out MPIC_DATA, al
	out SPIC_DATA, al

	pop rax
	ret

; copy_kern_to_pnm
;
; Summary:
;
; This function relocates the entire kernel to PNM address space
;
; Parameters:
;
; None
;
; Alignment:
;
; None
;
; Returns:
;
; None
;
; Smashes:
;
; None
;
; Optimization
;
; Readability
;
copy_kern_to_pnm:
	push rcx
	push rsi
	push rdi
	
	mov rdi, kern_size
	bamp_alloc rdi

	push rdi

	mov rcx, kern_size
	mov rsi, boot_bsp
	rep movsb

	pop rbx
	pop rdi
	pop rsi
	pop rcx
	ret

; init_pnm
;
; Summary:
;
; This function initializes the PDPTEs for the PNM
;
; Parameters:
;
; None
;
; Alignment:
;
; None
;
; Returns:
;
; None
;
; Smashes:
;
; None
;
; Optimization
;
; Readability
;
init_pnm:
	push rax
	push rbx
	push rcx
	push rdx
	push rdi
	push rbp
	push r8

	mov   rbx, MEMORY_MAP_LOC + 0x20
	movzx rcx, word [MEMORY_MAP_LOC]
.for_each_map:
	; If the mapping is not type 1, fail!
	mov eax, dword [rbx + 0x10]
	cmp rax, 1
	jne .go_next_map

	; get the base and 1GB align it
	mov rax, qword [rbx + 0x00]
	add rax,  (1 * 1024 * 1024 * 1024 - 1)
	and rax, ~(1 * 1024 * 1024 * 1024 - 1)

	; get the length of the ALIGNED remainder. This could be negative. Since
	; we do signed compares, this is fine!
	mov rdx, qword [rbx + 0x00] ; base
	add rdx, qword [rbx + 0x08] ; length
	sub rdx, rax

.while_1G_left:
	; If we don't have 1GB left, go to the next mapping
	cmp rdx, (1 * 1024 * 1024 * 1024)
	jl  short .go_next_map

	; If we're below 5GB physical, loop without alloc
	mov rbp, (5 * 1024 * 1024 * 1024)
	cmp rax, rbp
	jl  short .go_next_1gb

	mov rbp, rax
	add rbp, (1 * 1024 * 1024 * 1024 - 1)

	; rax now points to the base physical address of a 1GB aligned page
	; rbp points to the last byte available in this 1GB page

	lea rdi, [rel dram_routing_table]
	lea  r8, [rdi + 0x20 * MAX_NODES]
.find_dram:
	; Check if end_of_this_map > end_of_dram_for_node
	cmp rbp, [rdi + 0x08]
	ja  short .next_dram

	; Check if base_of_this_map < base_of_dram_for_node
	cmp rax, [rdi + 0x00]
	jb  short .next_dram

	jmp short .found_dram
	
.next_dram:
	add rdi, 0x20
	cmp rdi, r8
	jl  short .find_dram

	jmp short .go_next_1gb

.found_dram:
	; Get the next PDPTE location for this node and populate it
	mov rbp, qword [rdi + 0x18]
	mov qword [rbp], rax
	or  qword [rbp], 0x83 ; Present, writable, page size

	; Increment the PDPTE pointer
	add qword [rdi + 0x18], 8

.go_next_1gb:
	add rax, (1 * 1024 * 1024 * 1024)
	sub rdx, (1 * 1024 * 1024 * 1024)	
	jmp short .while_1G_left

.go_next_map:
	add rbx, 0x20
	dec rcx
	jnz .for_each_map
	
	pop r8
	pop rbp
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; fetch_dram_info
;
; Summary:
;
; This function populates the global table which contains DRAM routing rules.
; We use this information to set up the PNMs
;
fetch_dram_info:
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r15

	; Get the MMIO address for the processor PCIE config space
	mov ecx, 0xc0010058
	rdmsr
	shl rdx, 32
	or  rdx, rax
	and rdx, ~0x3F
	mov r15, rdx

	lea rsi, [rel dram_routing_table]
	xor ebp, ebp
.per_node:
	; Bus 0, Device 18, Function 1
	mov eax, [r15 + rbp*8 + 0x040 + ((0 << 20) | (0x18 << 15) | (0x1 << 12))]
	mov ebx, [r15 + rbp*8 + 0x044 + ((0 << 20) | (0x18 << 15) | (0x1 << 12))]
	mov ecx, [r15 + rbp*8 + 0x140 + ((0 << 20) | (0x18 << 15) | (0x1 << 12))]
	mov edx, [r15 + rbp*8 + 0x144 + ((0 << 20) | (0x18 << 15) | (0x1 << 12))]

	; eax - DRAM base low
	; ebx - DRAM limit low
	; ecx - DRAM base high
	; edx - DRAM limit high

	; Check for readable
	bt  eax, 0
	jnc short .next_node

	; Check for writable
	bt  eax, 1
	jnc short .next_node

	; Check for node interleave
	test eax, (3 << 8)
	jnz  short .interleave_warning

	; Get the node route
	mov edi, ebx
	and edi, 7
	mov qword [rsi + 0x10], rdi

	; Get the low part from DRAM base low
	and eax, 0xffff0000
	shl rax, (24 - 16)

	; Combine the high and low base parts
	mov edi, ecx
	and edi, 0xff
	shl rdi, 40
	or  rdi, rax

	mov qword [rsi + 0x00], rdi ; DRAM base

	; Get the low part from DRAM limit low
	and ebx, 0xffff0000
	shl rbx, (24 - 16)

	; Combine the high and low limit parts
	mov edi, edx
	and edi, 0xff
	shl rdi, 40
	or  rdi, rbx
	or  rdi, 0xFFFFFF

	mov qword [rsi + 0x08], rdi ; DRAM limit

.next_node:
	add rsi, 0x20
	inc ebp
	cmp ebp, MAX_NODES
	jb  .per_node

	pop r15
	pop rbp
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

.interleave_warning:
	mov  rdi, 0xb8000
	lea  rbx, [rel .ilw]
	mov  rcx, 58
	call outstr
	cli
	hlt

.ilw: db "Node interleaving is enabled, please disable from the BIOS"

align 16
dram_routing_table:
	; base, limit, node to route to, next PDPTE
	; If the limit is zero the entry is invalid
	dq 0, 0, 0, 0x100103000
	dq 0, 0, 0, 0x100104000
	dq 0, 0, 0, 0x100105000
	dq 0, 0, 0, 0x100106000
	dq 0, 0, 0, 0x100107000
	dq 0, 0, 0, 0x100108000
	dq 0, 0, 0, 0x100109000
	dq 0, 0, 0, 0x10010a000

; fetch_mmio_info
fetch_mmio_info:
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rbp
	push r10
	push r15

	; Get the MMIO address for the processor PCIE config space
	mov ecx, 0xc0010058
	rdmsr
	shl rdx, 32
	or  rdx, rax
	and rdx, ~0x3F
	mov r15, rdx

	lea rsi, [rel mmio_routing_table]
	xor ebp, ebp
.per_node:
	; Bus 0, Device 18, Function 1
	mov eax, [r15 + rbp*8 + 0x080 + ((0 << 20) | (0x18 << 15) | (0x1 << 12))]
	mov ebx, [r15 + rbp*8 + 0x084 + ((0 << 20) | (0x18 << 15) | (0x1 << 12))]
	mov ecx, [r15 + rbp*8 + 0x180 + ((0 << 20) | (0x18 << 15) | (0x1 << 12))]

	; eax - MMIO base low
	; ebx - MMIO limit low
	; ecx - MMIO base/limit high

	; Skip blank mappings
	test eax, 0x3
	jz   short .next_node

	; Get the low part from MMIO base low
	and eax, 0xffffff00
	shl rax, (16 - 8)

	; Combine the high and low base parts
	mov r10d, ecx
	and r10d, 0xff
	shl  r10, 40
	or   r10, rax

	; Save the base
	mov qword [rsi + 0], r10

	; Get the low part from MMIO limit low
	and ebx, 0xffffff00
	shl rbx, (16 - 8)

	; Combine the high and low limit parts
	bextr r10d, ecx, 0x0810
	shl    r10, 40
	or     r10, rbx
	or     r10, 0xFFFF

	; Save the limit
	mov qword [rsi + 8], r10

.next_node:
	add rsi, 0x10
	inc ebp
	cmp ebp, 12
	jb  .per_node

	pop r15
	pop r10
	pop rbp
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

align 16
mmio_routing_table:
	times (12 * 2) dq 0

; Initialize the fs segment.
init_globals:
	push rax
	push rbx
	push rcx
	push rdx

	; This is a fixed allocation. We compensate for this by properly
	; initializing bamp_addrs to not start here
	mov rbx, 0x0000010000000000

	mov   eax, ebx
	bextr rdx, rbx, 0x2020
	mov   ecx, 0xC0000100  ; FS.base MSR
	wrmsr

	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; Initialize the global values
populate_globals:
	push rbx
	push rcx
	push rdx
	push rsi

	mov rbx, 0x0000010000000000

	; Zero out the global table
	push rax
	push rcx
	push rdi
	mov  rdi, rbx
	mov  rcx, GLOBAL_STORAGE
	xor  eax, eax
	rep  stosb
	pop  rdi
	pop  rcx
	pop  rax

	mov qword [fs:globals.fs_base], rbx

	mov rbx, 0x50000000000
	mov qword [fs:globals.next_free_vaddr], rbx

	mov rbx, 0x0000010000000000 + GLOBAL_STORAGE ; Node 0 base (less globals)
	mov qword [fs:globals.bamp_addr + 0x00], rbx
	mov rbx, 0x0000018000000000                  ; Node 1 base
	mov qword [fs:globals.bamp_addr + 0x08], rbx
	mov rbx, 0x0000020000000000                  ; Node 2 base
	mov qword [fs:globals.bamp_addr + 0x10], rbx
	mov rbx, 0x0000028000000000                  ; Node 3 base
	mov qword [fs:globals.bamp_addr + 0x18], rbx
	mov rbx, 0x0000030000000000                  ; Node 4 base
	mov qword [fs:globals.bamp_addr + 0x20], rbx
	mov rbx, 0x0000038000000000                  ; Node 5 base
	mov qword [fs:globals.bamp_addr + 0x28], rbx
	mov rbx, 0x0000040000000000                  ; Node 6 base
	mov qword [fs:globals.bamp_addr + 0x30], rbx
	mov rbx, 0x0000048000000000                  ; Node 7 base
	mov qword [fs:globals.bamp_addr + 0x38], rbx

	lea rsi, [rel dram_routing_table]
	mov ecx, 0
.for_each_node:
	mov rbx, qword [rsi + 0x18]
	and rbx, 0xfff
	shl rbx, 27 ; Multiply by (1GB / 8). This gives us the number of bytes in
	            ; this nodes pool

	mov rdx, qword [fs:globals.bamp_addr + rcx*8]
	add rdx, rbx
	and rdx, ~((1024 * 1024 * 1024) - 1)
	mov qword [fs:globals.bamp_ends + rcx*8], rdx	

	add rsi, 0x20
	inc ecx
	cmp ecx, MAX_NODES
	jb  short .for_each_node

	pop rsi
	pop rdx
	pop rcx
	pop rbx
	ret

; qwait
;
; Summary:
;
; This is a shitty spinloop used for delaying execution for INIT-SIPI-SIPIs
;
qwait:
	push rcx

	mov rcx, 1000000
.lewp:
	dec rcx
	jnz short .lewp

	pop rcx
	ret

boot_aps:
	push rax
	push rbx

	; Send INIT
	mov eax, 0x000C4500
	mov ebx, 0xFEE00300
	mov dword [rbx], eax
	call qwait

	; Send SIPI #1
	mov eax, 0x000C4609
	mov dword [rbx], eax
	call qwait

	; Send SIPI #2
	mov dword [rbx], eax
	call qwait

	pop rbx
	pop rax
	ret

create_cephys:
	push rax
	push rcx
	push rdi

	mov rdi, 0x100102000

	; Set up the 1GB PDPTEs for the cephys map
	; Present, writable, page size
	mov rax, 0x83 ; Low 32-bits
	mov ecx, 512
.set1Gentry_cephys:
	mov qword [rdi + 0], rax ; Low bits

	add rax, (1 * 1024 * 1024 * 1024)
	add rdi, 8
	dec ecx
	jnz short .set1Gentry_cephys

	pop rdi
	pop rcx
	pop rax
	ret

switch_cr3:
	push rdi

	mov rdi, 0x100100000

	mov dword [rdi + 0x00], 0x00102003 ; cephys
	mov dword [rdi + 0x04], 0x00000001 ; cephys high
	mov dword [rdi + 0x08], 0x00102003 ; cephys
	mov dword [rdi + 0x0c], 0x00000001 ; cephys high
	mov dword [rdi + 0x10], 0x00103003 ; PNM node 0
	mov dword [rdi + 0x14], 0x00000001 ; PNM node 0 high
	mov dword [rdi + 0x18], 0x00104003 ; PNM node 1
	mov dword [rdi + 0x1c], 0x00000001 ; PNM node 1 high
	mov dword [rdi + 0x20], 0x00105003 ; PNM node 2
	mov dword [rdi + 0x24], 0x00000001 ; PNM node 2 high
	mov dword [rdi + 0x28], 0x00106003 ; PNM node 3
	mov dword [rdi + 0x2c], 0x00000001 ; PNM node 3 high
	mov dword [rdi + 0x30], 0x00107003 ; PNM node 4
	mov dword [rdi + 0x34], 0x00000001 ; PNM node 4 high
	mov dword [rdi + 0x38], 0x00108003 ; PNM node 5
	mov dword [rdi + 0x3c], 0x00000001 ; PNM node 5 high
	mov dword [rdi + 0x40], 0x00109003 ; PNM node 6
	mov dword [rdi + 0x44], 0x00000001 ; PNM node 6 high
	mov dword [rdi + 0x48], 0x0010a003 ; PNM node 7
	mov dword [rdi + 0x4c], 0x00000001 ; PNM node 7 high

	mov cr3, rdi
	wbinvd

	pop rdi
	ret

create_relocated_idt:
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rbp

	; Allocate room for the IDT and the entries
	mov rbx, (256 * 16) + 8 + 2
	bamp_alloc rbx
	mov rsi, rbx

	; Skip ahead past the actual IDT
	add rbx, (8 + 2)

	; Create the IDT structure
	mov  word [rbx - 0x0a], 4095 ; Limit
	mov qword [rbx - 0x08], rbx  ; Base

	; Allocate room for the dispatchers
	; 50            push rax
	; 53            push rbx
	; 48 b8 <imm64> mov  rax, <vector number>
	; 48 bb <imm64> mov  rbx, <rel relocated_handler>
	; ff e3         jmp  rbx
	mov rdx, ((1 + 1 + 10 + 10 + 2) * 256)
	bamp_alloc rdx

	; Install exception handlers, [0, 32)
	lea rax, [rel relocated_handler]
	xor ecx, ecx
.install_exception_handlers:
	; Create the dispatcher
	mov  word [rdx + 0x00 + 0], 0x5350
	mov  word [rdx + 0x00 + 2], 0xb848
	mov qword [rdx + 0x02 + 2], rcx
	mov  word [rdx + 0x0a + 2], 0xbb48
	mov qword [rdx + 0x0c + 2], rax
	mov  word [rdx + 0x14 + 2], 0xe3ff

	mov word [rbx + 0], dx     ; offset 15..0
	mov word [rbx + 2], 0x0008 ; Segment selector
	mov byte [rbx + 4], 0x00   ; ist
	mov byte [rbx + 5], 0x8E   ; type

	bextr rbp, rdx, 0x1010
	mov word [rbx + 6], bp ; offset 31..16

	bextr rbp, rdx, 0x2020
	mov dword [rbx + 0x8], ebp ; offset 63..32
	mov dword [rbx + 0xc], 0   ; reserved
	
	add rdx, (1 + 1 + 10 + 10 + 2)
	add rbx, 16
	inc ecx
	cmp ecx, 32
	jl  short .install_exception_handlers

	; Install interrupt handlers, [32, 256)
	mov rcx, 32
.install_interrupt_handlers:
	imul rbx, rcx, 16

	lea   rdx, [rel user_handler]
	mov    word [rsi + (8 + 2) + rbx + 0x0], dx
	mov    word [rsi + (8 + 2) + rbx + 0x2], 0x0008
	mov    byte [rsi + (8 + 2) + rbx + 0x4], 0x00
	mov    byte [rsi + (8 + 2) + rbx + 0x5], 0x8E
	bextr rbp, rdx, 0x1010
	mov    word [rsi + (8 + 2) + rbx + 0x6], bp
	bextr rbp, rdx, 0x2020
	mov   dword [rsi + (8 + 2) + rbx + 0x8], ebp
	mov   dword [rsi + (8 + 2) + rbx + 0xc], 0

	inc ecx
	cmp ecx, 256
	jl  short .install_interrupt_handlers

	; Install the node local IBS handler
	lea   rdx, [rel ibs_handler]
	mov    word [rsi + (8 + 2) + (16 * 0x2) + 0x0], dx
	mov    word [rsi + (8 + 2) + (16 * 0x2) + 0x2], 0x0008
	mov    byte [rsi + (8 + 2) + (16 * 0x2) + 0x4], 0x00
	mov    byte [rsi + (8 + 2) + (16 * 0x2) + 0x5], 0x8E
	bextr rbp, rdx, 0x1010
	mov    word [rsi + (8 + 2) + (16 * 0x2) + 0x6], bp
	bextr rbp, rdx, 0x2020
	mov   dword [rsi + (8 + 2) + (16 * 0x2) + 0x8], ebp
	mov   dword [rsi + (8 + 2) + (16 * 0x2) + 0xc], 0

	; Program the IBS APIC vector to deliver NMIs
	mov eax, 0xFEE00500
	mov dword [eax], (4 << 8)

	lidt [rsi]

	pop rbp
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; rdx <- MMIO address for processor PCIE config space
amd_fam15h_fetch_pcie_mmio:
	push rax
	push rcx

	; Get the MMIO address for the processor PCIE config space
	mov ecx, 0xc0010058
	rdmsr
	shl rdx, 32
	or  rdx, rax
	and rdx, ~0x3F

	pop rcx
	pop rax
	ret

falkrand:
	movdqu xmm15, [gs:thread_local.xs_seed]
	aesenc xmm15, xmm15
	movdqu [gs:thread_local.xs_seed], xmm15
	ret

; rcx -> Lower bound
; rdx -> Upper bound
; rax <- Random number in range [lower, upper]
randexp:
	push rdx

	call randuni

	mov  rdx, rax
	call randuni

	pop rdx
	ret

; rcx -> Lower bound
; rdx -> Upper bound
; rax <- Random number in range [lower, upper]
randuni:
	push rdx
	push rbp
	push rsi
	push r15

	; Default to returning the lower bound
	mov rax, rcx

	; If the lower bound is greater than or equal to the upper bound, either
	; there is no range, or the range is invalid, return the lower bound.
	cmp rcx, rdx
	jae short .done

	; rbp <- Range
	mov rbp, rdx
	sub rbp, rcx
	inc rbp

	; Get the number of set bits in range. If only one bit is set, use a mask,
	; otherwise, use a div.
	popcnt rsi, rbp
	cmp    rsi, 1
	jne    short .use_div

.use_mask:
	dec  rbp ; Create mask
	call xorshift64
	and  r15, rbp
	lea  rax, [rcx + r15]
	jmp  short .done

.use_div:
	call xorshift64
	xor  rdx, rdx
	mov  rax, r15
	div  rbp
	lea  rax, [rcx + rdx]

.done:
	pop r15
	pop rsi
	pop rbp
	pop rdx
	ret

xorshift64:
	XMMPUSH xmm15

	call falkrand
	movq r15, xmm15

	XMMPOP xmm15
	ret

falkseed:
	push rax
	push rdx

	XMMPUSH xmm15

	pinsrq xmm15, rsp, 0

	rdtsc
	shl rdx, 32
	or  rdx, rax
	bts rdx, 63
	btr rdx, 62
	pinsrq xmm15, rdx, 1

	aesenc xmm15, xmm15
	aesenc xmm15, xmm15
	aesenc xmm15, xmm15
	aesenc xmm15, xmm15

	movdqu [gs:thread_local.xs_seed], xmm15

	XMMPOP xmm15

	pop rdx
	pop rax
	ret

init_lwp:
	push rax
	push rcx
	push rdx

	; Set up xcr0 to save all state (FPU, MMX, SSE, AVX, and LWP)
	mov edx, 0x40000000
	mov eax, 0x00000007
	xor ecx, ecx
	xsetbv

	; Get the LWP features
	mov eax, 0x8000001c
	cpuid

	; Write the LWP features to the LWP_CFG MSR
	mov rax, rdx
	xor rdx, rdx
	mov ecx, 0xc0000105
	wrmsr

	pop rdx
	pop rcx
	pop rax
	ret

lmland:
	cli

	xor ax, ax
	mov es, ax
	mov ds, ax
	mov gs, ax
	mov ss, ax
	mov fs, ax

	lidt [idt]

	; Enable the IO APIC
	mov ebx, 0xFEE000F0 ; Spurious Interrupt Vector Register
	mov eax, dword [rbx]
	or  eax, 0x100
	mov dword [rbx], eax

	; Get a unique core ID
	mov  rax, 1
	lock xadd qword [proc_id], rax

	; Each core gets it's own quarter-line on the screen, obviously this would
	; cause problems if there are more than 100 cores
	imul rdi, rax, (40)
	add  rdi, 0xb8000

	; Each core gets a unique 64kB stack
	imul rsp, rax, 0x10000 ; 64kB stack per core
	add  rsp, 0x00504000

	test rax, rax
	jnz  short .not_bsp

	; We've entered LM as the BSP, we need to set up the PNM and start the
	; APs
	call create_cephys
	call fetch_dram_info
	call fetch_mmio_info
	call init_pnm
	call init_globals
	call populate_globals

	; Get the rdtsc increment frequency in MHz and store it
	push rax
	call amd_fam15h_sw_p0_freq
	mov  qword [fs:globals.rdtsc_freq], rax
	pop  rax

	call i825xx_init
	call x540_init

	; Initialize the per_node_kern_code struct
	mov qword [fs:globals.per_node_kern_code + node_struct.orig_data], boot_bsp
	mov qword [fs:globals.per_node_kern_code + node_struct.data_len],  kern_size

	call boot_aps

.not_bsp:
	; Set up the FS segment for this core
	call init_globals
	call init_per_core_storage
	call init_lwp

	push rax

	; Get a copy of the kernel on this node
	mov  rbx, [fs:globals.fs_base]
	lea  rbx, [rbx + globals.per_node_kern_code]
	mov  rbx, [rbx + node_struct.orig_data]

	pop rax

	; Jump to the kernel code
	add rbx, (.cores_init_bamp - boot_bsp)
	jmp rbx

.cores_init_bamp:
	; At this point we are relocated

	; Allocate a 32MB stack from the BAMP
	mov rbx, (1024 * 1024 * 32)
	bamp_alloc rbx
	add rbx, (1024 * 1024 * 32)
	mov rsp, rbx

	mov rbx, cr0
	btr rbx, 30 ; Enable cache
	btr rbx, 29 ; Enable write through
	bts rbx, 5  ; Enable numeric error
	mov cr0, rbx

	; Increment the counter of number of cores up and relocated
	mov  rbx, 1
	lock xadd qword [cores_reloc], rbx

	; Wait for all cores to relocate
	mov rbx, qword [num_cores]
.wait_for_reloc:
	pause
	cmp rbx, qword [cores_reloc]
	jne short .wait_for_reloc

	call switch_cr3

	; Relocate the GDT
	lea  rbx, [rel gdt64]
	lea  rcx, [rel gdt64_base]
	mov  [rbx + 2], rcx
	lgdt [rbx]

.next:
	call falkseed
	call x540_init_local_rx
	call x540_init_local_tx
	call i825xx_init_thread_local
	call create_relocated_idt

	; Jump to the actual program to run!
	jmp program

