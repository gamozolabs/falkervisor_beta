; rsi -> VM snapshot
apply_fileio_breakpoint:
	push rax
	push rcx
	push rdx
	push rdi
	push rsi

	lea  rdi, [rsi + vm_snapshot.physical_memory + 0x820]
	lea  rsi, [rel .fileio_sig]
	mov  rcx, 64
	mov  rdx, VM_MEMORY_SIZE
	call memmem
	test rax, rax ; not found
	jz   panic

	mov byte [rax + 0], 0xcc ; int3
	mov byte [rax + 1], 0xc3 ; ret

	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rax
	ret

.fileio_sig:
db 0x48, 0x89, 0x5C, 0x24, 0x18, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 
db 0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05, 0xC2, 0x47, 0x03, 0x00, 0x48, 0x33, 
db 0xC4, 0x48, 0x89, 0x44, 0x24, 0x78, 0x48, 0x8B, 0x59, 0x40, 0x48, 0x8B, 0xBA, 0xB8, 0x00, 0x00, 
db 0x00, 0x4C, 0x8B, 0xF2, 0x4C, 0x8B, 0x63, 0x10, 0x44, 0x8B, 0x7F, 0x08, 0x48, 0x8B, 0xE9, 0xF0,
.fileio_sig_size: equ ($ - .fileio_sig)

handle_fileio:
	push rbx
	push rcx
	push rdi
	push rsi
	push rbp
	push r8
	push r9

	; We expect SystemBuffer to be NULL
	push rdx
	lea  rdx, [rdx + 0x18] ; IRP->AssociatedIrp.SystemBuffer
	call mm_read_guest_qword
	test rdx, rdx
	jnz  panic
	pop  rdx

	; We expect UserBuffer to be NULL
	push rdx
	lea  rdx, [rdx + 0x70] ; IRP->UserBuffer
	call mm_read_guest_qword
	test rdx, rdx
	jnz  panic
	pop  rdx

	; Get IRP->MdlAddress->MappedSystemVa
	push rdx
	lea  rdx, [rdx + 0x08] ; IRP->MdlAddress
	call mm_read_guest_qword
	test rdx, rdx
	jz   panic

	lea  rdx, [rdx + 0x18] ; MdlAddress->MappedSystemVa
	call mm_read_guest_qword
	mov  rdi, rdx
	test rdx, rdx
	jz   panic
	pop  rdx

	; Get the IrpSp
	push rdx
	lea  rdx, [rdx + 0xb8] ; IRP->Tail.CurrentStackLocation
	call mm_read_guest_qword
	mov  rbp, rdx
	test rdx, rdx
	pop  rdx
	jz   panic

	; rdi - Guest virtual address to read sectors into
	; rbp - Address of the IrpSp

	; Get the IrpSp->MajorFunction and make sure this is an IRP_MJ_READ
	push rdx
	lea  rdx, [rbp + 0x00] ; IrpSp->MajorFunction
	call mm_read_guest_qword
	cmp  dl, 0x3 ; IRP_MJ_READ
	jne  panic
	pop  rdx

	; Get IrpSp->Parameters.Read.ByteOffset
	push rdx
	lea  rdx, [rbp + 0x18] ; IrpSp->Parameters.Read.ByteOffset
	call mm_read_guest_qword
	mov  rbx, rdx
	pop  rdx

	; Get IrpSp->Parameters.Read.Length
	push rdx
	lea  rdx, [rbp + 0x08] ; IrpSp->Parameters.Read.Length
	call mm_read_guest_qword
	mov  rcx, rdx
	pop  rdx

	; rbx - Disk byte offset to file
	; rcx - Length to read from disk (in bytes)
	; rdi - Guest virtual address to read sectors into
	; rbp - Address of the IrpSp
	
	; Offset and size must be 512-byte aligned
	test rbx, 0x1ff
	jnz  panic
	test rcx, 0x1ff
	jnz  panic

	; Divide down offset and size to now be sector counts
	shr rbx, 9
	mov  r9, rcx
	shr  r9, 9

	; r9 - Length to read in sectors

	; If there are no sectors to read, skip the reading
	test r9, r9
	jz   short .nothing_to_do

	push rcx
	sub  rsp, 512
.lewp:
	; Read the sector
	mov  rcx, 1
	mov   r8, rsp
	;call ide_pio_read_sectors

	; Copy the sector into VM memory
	mov  rsi, rsp
	mov  rcx, 512
	;call mm_copy_to_guest_vm_vmcb
	
	add  rdi, 512
	inc  rbx
	dec  r9
	jnz  short .lewp
	add  rsp, 512
	pop  rcx

.nothing_to_do:
	; IRP->IoStatus.Status = STATUS_SUCCESS
	push rdx
	xor  rbx, rbx
	lea  rdx, [rdx + 0x30]
	call mm_write_guest_qword
	pop  rdx

	; IRP->IoStatus.Information = Number of bytes read
	push rdx
	mov  rbx, rcx
	lea  rdx, [rdx + 0x38]
	call mm_write_guest_qword
	pop  rdx
	
	mov qword [rax + VMCB.rax], 0 ; STATUS_SUCCESS
	
	pop r9
	pop r8
	pop rbp
	pop rsi
	pop rdi
	pop rcx
	pop rbx

	; IoCompleteRequest(irp, IO_NO_INCREMENT);
	mov rcx, 0xfffff80107935d44
	add qword [rax + VMCB.rip], rcx
	mov rcx, rdx ; rcx = IRP
	mov rdx, 0   ; rdx = IO_NO_INCREMENT
	ret

