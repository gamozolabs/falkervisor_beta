[bits 64]

; This is called in a raw vm state. You must save the actual GPRs here.
save_vm_snapshot:
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	push rax
	push rbx

	; Use the old snapshot memory
	mov  rbx, qword [fs:globals.vm_snapshot]
	test rbx, rbx
	jnz  short .create_snapshot

	; Allocate room in virtual memory space for the biggest possible snapshot
	mov  rbx, VM_MEMORY_SIZE + (VM_MAX_PAGES * 8) + vm_snapshot_size
	add  rbx,  0xFFF
	and  rbx, ~0xFFF
	lock xadd qword [fs:globals.next_free_vaddr], rbx
	mov  qword [fs:globals.vm_snapshot_mem], rbx

	; Allocate room for our vm snapshot
	mov rbx, vm_snapshot_size
	bamp_alloc rbx
	mov qword [fs:globals.vm_snapshot], rbx

.create_snapshot:
	mov [rbx + vm_snapshot.rcx], rcx
	mov [rbx + vm_snapshot.rdx], rdx
	mov [rbx + vm_snapshot.rsi], rsi
	mov [rbx + vm_snapshot.rdi], rdi
	mov [rbx + vm_snapshot.rbp], rbp
	mov [rbx + vm_snapshot.r8],  r8
	mov [rbx + vm_snapshot.r9],  r9
	mov [rbx + vm_snapshot.r10], r10
	mov [rbx + vm_snapshot.r11], r11
	mov [rbx + vm_snapshot.r12], r12
	mov [rbx + vm_snapshot.r13], r13
	mov [rbx + vm_snapshot.r14], r14
	mov [rbx + vm_snapshot.r15], r15

	mov rcx, rbx
	pop rbx

	; rcx now points to the vm_snapshot
	mov [rcx + vm_snapshot.rbx], rbx
	mov rbx, cr8
	mov [rcx + vm_snapshot.cr8], rbx
	
	; Save off xcr0
	push rcx
	mov  ecx, 0
	xgetbv
	pop  rcx
	shl  rdx, 32
	or   rdx, rax
	mov  [rcx + vm_snapshot.xcr0], rdx

	; Save off debug registers
	mov rbx, dr0
	mov [rcx + vm_snapshot.dr0], rbx
	mov rbx, dr1
	mov [rcx + vm_snapshot.dr1], rbx
	mov rbx, dr2
	mov [rcx + vm_snapshot.dr2], rbx
	mov rbx, dr3
	mov [rcx + vm_snapshot.dr3], rbx

	; Save off the physical memory size of this system
	mov rbx, VM_MEMORY_SIZE
	mov qword [rcx + vm_snapshot.pmem_size], rbx

	; Set up xcr0 to save all state (FPU, MMX, SSE, AVX, and LWP)
	mov   edx, 0x40000000
	mov   eax, 0x00000007
	push  rcx
	mov   ecx, 0
	xsetbv
	pop   rcx
	xsave [rcx + vm_snapshot.xsave]

	pop rax ; Restore vmcb

	; Save off vmcb
	push rcx
	mov  rsi, rax
	lea  rdi, [rcx + vm_snapshot.vmcb]
	mov  rcx, 4096 / 8
	rep  movsq
	pop  rcx

	; Map vm_snapshot_mem[0:0x3000] -> vm_snapshot[0:0x3000]
	push rax
	lea  rbx, [rcx + 0x0000]
	call bamp_get_phys
	lea  rbp, [rax + 3]
	mov  rbx, qword [fs:globals.vm_snapshot_mem]
	lea  rbx, [rbx + 0x0000]
	mov  rdx, cr3
	call mm_map_4k

	lea  rbx, [rcx + 0x1000]
	call bamp_get_phys
	lea  rbp, [rax + 3]
	mov  rbx, qword [fs:globals.vm_snapshot_mem]
	lea  rbx, [rbx + 0x1000]
	mov  rdx, cr3
	call mm_map_4k

	lea  rbx, [rcx + 0x2000]
	call bamp_get_phys
	lea  rbp, [rax + 3]
	mov  rbx, qword [fs:globals.vm_snapshot_mem]
	lea  rbx, [rbx + 0x2000]
	mov  rdx, cr3
	call mm_map_4k
	pop  rax

	; Allocate the zero page we return for MMIO addresses
	push rax
	call alloc_zero_4k
	mov  r11, rax
	pop  rax

	mov rbx, 0
	mov r10, VM_MEMORY_SIZE
.lewp:
	call probe_memory_dest
	test rdx, rdx
	jz   short .is_ram

	push rbx
	lea  rbp, [r11 + 3]
	add  rbx, qword [fs:globals.vm_snapshot_mem]
	add  rbx, 0x3000
	mov  rdx, cr3
	call mm_map_4k
	pop  rbx

	jmp short .next_page

.is_ram:
	push rax
	push rbx
	mov  rdx, [rax + VMCB.n_cr3]
	call mm_get_phys

	lea  rbp, [rax + 3]
	add  rbx, qword [fs:globals.vm_snapshot_mem]
	add  rbx, 0x3000
	mov  rdx, cr3
	call mm_map_4k
	pop  rbx
	pop  rax

.next_page:
	add rbx, 4096
	cmp rbx, r10
	jb  short .lewp

	mov  r10, qword [fs:globals.vm_snapshot_mem]
	mov  r11, (vm_snapshot_size + VM_MEMORY_SIZE)
	call falktp_send

.resume:
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax

	jmp launch_svm.inject_debug

