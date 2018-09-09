[bits 64]

struc modlist
	; module is loaded at [base, end]
	.base: resq 1
	.end:  resq 1

	.hash: resq 1

	.namelen: resq 1   ; Name length in bytes
	.name:    resb 512 ; utf16 name of module
endstruc

win32_construct_modlist:
	push rax
	push rbx
	push rcx
	push rdx
	push rdi
	push rsi
	push rbp

	; If we have already initialized the modlist, do nothing
	cmp qword [gs:thread_local.modlist_count], 0
	jne .end

	; Deref teb->ProcessEnvironmentBlock
	mov  rdx, [rax + VMCB.gs_base]
	add  rdx, 0x60
	call mm_read_guest_qword

	; Deref peb->Ldr (struct _PEB_LDR_DATA)
	add  rdx, 0x18
	call mm_read_guest_qword

	; Deref ldr->InLoadOrderLinks (struct _LDR_DATA_TABLE_ENTRY)
	add rdx, 0x10

	; Fetch the blink and store it, we stop iterating when we hit this
	push rdx
	add  rdx, 8
	call mm_read_guest_qword
	mov  rbp, rdx
	pop  rdx

.for_each_module:
	; Deref the _LDR_DATA_TABLE_ENTRY to move to the next entry.
	call mm_read_guest_qword

	; Test if it's the end of the list
	test rdx, rdx
	jz   .end
	cmp  rdx, rbp
	je   .end

	; Allocate a new modlist entry
	mov rbx, modlist_size
	bamp_alloc rbx

	; Lookup the base address
	push rdx
	add  rdx, 0x30
	call mm_read_guest_qword
	test rdx, rdx
	jz   .for_each_module
	mov  [rbx + modlist.base], rdx
	mov  [rbx + modlist.end],  rdx
	pop  rdx

	; Look up the image size
	push rdx
	add  rdx, 0x40
	call mm_read_guest_qword
	test rdx, rdx
	jz   .for_each_module
	add  qword [rbx + modlist.end], rdx
	dec  qword [rbx + modlist.end]
	pop  rdx

	; Look up the image dll name size
	push rdx
	add  rdx, 0x58
	call mm_read_guest_qword
	and  edx, 0xffff
	cmp  edx, 512
	ja   .for_each_module
	mov  [rbx + modlist.namelen], rdx
	pop  rdx

	; Fetch the image dll name
	push rdx
	add  rdx, 0x60
	call mm_read_guest_qword
	mov  rsi, rdx
	lea  rdi, [rbx + modlist.name]
	mov  rcx, [rbx + modlist.namelen]
	call mm_copy_from_guest_vm_vmcb
	pop  rdx

	; Fetch the BaseNameHashValue
	push rdx
	add  rdx, 0x108
	call mm_read_guest_qword

	; Since this value is a dword, shift it left by 32. We then use the bottom
	; 32-bit (which are now zero) to add our relative offset to calculate our
	; relative hash.
	shl  rdx, 32
	mov  [rbx + modlist.hash], rdx
	pop  rdx

	; Add this new DLL to the modlist
	mov rdi, qword [gs:thread_local.modlist_count]
	mov rsi, qword [gs:thread_local.gs_base]
	lea rsi, [rsi + thread_local.modlist + rdi*8]
	mov qword [rsi], rbx
	inc qword [gs:thread_local.modlist_count]

	jmp .for_each_module

.end:
	pop rbp
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; rbx  -> RIP to resolve
; xmm5 <- Symhash to use
win32_symhash:
	push rdi
	push rsi
	push rbp

	call win32_resolve_symbol
	test rbp, rbp
	jz   short .trash

	mov rbp, qword [rbp + modlist.hash]

	pinsrq xmm5, rbp, 0
	pinsrq xmm5, rbx, 1
	aesenc xmm5, xmm5
	aesenc xmm5, xmm5
	aesenc xmm5, xmm5
	aesenc xmm5, xmm5

	jmp short .end

.trash:
	xorps xmm5, xmm5
.end:
	pop rbp
	pop rsi
	pop rdi
	ret

; rbx -> RIP to resolve
; rbx <- Module offset or original RIP
; rbp <- Pointer to modlist entry. If this is zero, symbol could not be
;        resolved and thus rbx is left unchanged.
win32_resolve_symbol:
	push rcx
	push rdx

	cmp qword [gs:thread_local.modlist_count], 0
	je  short .end

	xor rcx, rcx
	mov rdx, qword [gs:thread_local.gs_base]
	lea rdx, [rdx + thread_local.modlist]
.lewp:
	mov rbp, qword [rdx + rcx*8]

	cmp rbx, qword [rbp + modlist.base]
	jb  short .next
	
	cmp rbx, qword [rbp + modlist.end]
	ja  short .next

	; We resolved the symbol!
	sub rbx, qword [rbp + modlist.base]
	jmp short .end_found

.next:
	inc rcx
	cmp rcx, qword [gs:thread_local.modlist_count]
	jb  short .lewp

.end:
	xor rbp, rbp
.end_found:
	pop rdx
	pop rcx
	ret

