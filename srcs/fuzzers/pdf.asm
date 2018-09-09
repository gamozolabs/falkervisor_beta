[bits 64]

corrupt_pdf:
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

	XMMPUSH xmm5

	call start_log

	; Pick a random base PDF input
	call rand_pdf
	mov  [gs:thread_local.fuzz_input_len], rcx

	mov  rdi, [gs:thread_local.fuzz_maps]
	mov  rsi, rsi
	mov  rcx, [gs:thread_local.fuzz_input_len]
	rep  movsb

	mov  rdi, [gs:thread_local.fuzz_input]
	mov  rsi, rbx
	mov  rcx, [gs:thread_local.fuzz_input_len]
	rep  movsb

	call xorshift64
	test r15, 0x7
	jz   .create_new_fuzz

%ifdef ENABLE_COVERAGE_FEEDBACK
.use_coverage:
	mov r10, -1
	mov r11, 0
	mov r12, 8
.try_another:
	dec r12
	jz  short .do_the_copy

	; Pick a random covearge entry
	mov  rcx, qword [fs:globals.coverage_fht]
	call fht_random
	test rax, rax
	jz   .try_another

	; If this entry is not more rare, try another entry
	cmp qword [rax + bb_struc.count], r10
	jae short .try_another

	; Save off this rare entry
	mov r10, qword [rax + bb_struc.count]
	mov r11, rax
	jmp short .try_another

.do_the_copy:
	; If we didn't find any entries, start a new fuzz
	test r11, r11
	jz   .create_new_fuzz

	; Fetch the input associated with this coverage entry
	movdqu xmm5, [r11 + bb_struc.input_hash]
	call   input_entry_from_hash

	; Copy the coverage entry to the fuzz_input
	mov rsi, [rdx + input_entry.input]
	mov rdi, [gs:thread_local.fuzz_input]
	mov rcx, [rdx + input_entry.len]
	rep movsb

	; Copy the coverage entry maps to fuzz_maps
	mov rsi, [rdx + input_entry.maps]
	mov rdi, [gs:thread_local.fuzz_maps]
	mov rcx, [rdx + input_entry.len]
	rep movsb
	
	; Set the new fuzz input length
	mov rcx, qword [rdx + input_entry.len]
	mov [gs:thread_local.fuzz_input_len], rcx

	jmp .create_new_fuzz
%endif

.create_new_fuzz:
%ifdef ENABLE_FUZZING
	call xorshift64
	mov  r14, r15
	and  r14, 0xf
	inc  r14

.corrupt_stuff:
	mov  r8, [gs:thread_local.fuzz_input]
	mov  r9, [gs:thread_local.fuzz_input_len]
	mov r10, [gs:thread_local.fuzz_maps]

	call xorshift64
	xor  rdx, rdx
	mov  rax, r15
	div  r9

	mov   r11, rdx
	movzx edi, byte [r10 + r11]

	mov rbp, 100
.find_match:
	call rand_pdf
	call xorshift64
	xor  rdx, rdx
	mov  rax, r15
	div  rcx

	mov r12, rdx

	movzx ecx, byte [rsi + r12]
	cmp   edi, ecx
	je    short .match

	dec rbp
	jnz .find_match
	jmp .no_match

.match:
	xor r15, r15
	lea rbp, [rsi + r12]
.lewp:
	cmp r15, 0x100
	jae short .end
	cmp dil, byte [rbp + r15]
	jne short .end
	inc r15
	jmp short .lewp
.end:
	mov  rbp, r15
	call xorshift64
	xor  rdx, rdx
	mov  rax, r15
	div  rbp
	inc  rdx

	push rsi
	push rdi
	push rcx
	lea  rsi, [r8 + r11]
	lea  rdi, [r8 + r11]
	add  rdi, rdx
	mov  rcx, r9
	sub  rcx, r11
	call memcpy
	pop  rcx
	pop  rdi
	pop  rsi

	push rsi
	push rdi
	push rcx
	lea  rsi, [r10 + r11]
	lea  rdi, [r10 + r11]
	add  rdi, rdx
	mov  rcx, r9
	sub  rcx, r11
	call memcpy
	pop  rcx
	pop  rdi
	pop  rsi

	add qword [gs:thread_local.fuzz_input_len], rdx

	lea rsi, [rbx + r12] ; source
	lea rcx, [ r8 + r11] ; destination in the input
	lea rbp, [r10 + r11] ; destination in the map
.hax:
	mov al, [rsi]
	mov [rcx], al
	mov [rbp], dil

	inc rbp
	inc rsi
	inc rcx
	dec rdx
	jnz short .hax
.no_match:

	dec r14
	jnz .corrupt_stuff

	mov  rcx, 8
	lea  rbp, [rel corrupt_from_corpus]
	call invoke_random

	mov  rcx, 8
	lea  rbp, [rel corpymem]
	call invoke_random
%endif

.done:
	call stop_log
	add  qword [gs:thread_local.time_corrupt], rdx

	XMMPOP xmm5

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
	ret

inject_pdf:
	push rcx
	push rdi
	push rsi

	; rdx - PDF buffer base
	; r8  - PDF length

	mov  rdi, rdx
	mov  rsi, qword [gs:thread_local.fuzz_input]
	mov  rcx, qword [gs:thread_local.fuzz_input_len]
	call mm_copy_to_guest_vm_vmcb

	mov r8, qword [gs:thread_local.fuzz_input_len]

	pop rsi
	pop rdi
	pop rcx
	ret

; rbx <- Pointer to random entry in dict
; rcx <- Size of random entry
; rsi <- Fuzz map
rand_pdf:
	push rax
	push rdx
	push rbp
	push r15
	
	mov  rbx, [fs:globals.fs_base]
	lea  rbx, [rbx + globals.per_node_pdfs]
	call per_node_data
	mov  rbp, rax

	mov  rbx, [fs:globals.fs_base]
	lea  rbx, [rbx + globals.per_node_pdfmaps]
	call per_node_data
	mov  rsi, rax

.try_another:
	; Pick a random entry in the dict
	call xorshift64
	xor  rdx, rdx
	mov  rax, r15
	div  qword [rbp]

	imul rdx, 0x10
	add  rdx, 8

	mov rbx, [rbp + rdx + 0] ; File offset
	mov rcx, [rbp + rdx + 8] ; File size

	test rcx, rcx
	jz   short .try_another

	lea rsi, [rsi + rbx]
	lea rbx, [rbp + rbx]

	pop r15
	pop rbp
	pop rdx
	pop rax
	ret

