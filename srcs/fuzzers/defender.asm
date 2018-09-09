[bits 64]

corrupt_quantum:
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

	call rand_dict_entry
	mov  rsi, rbx
	mov  rdi, qword [gs:thread_local.rtf_fuzz]
	mov  rcx, qword [fs:globals.per_node_rtf + node_struct.data_len]
	rep  movsb

%ifndef ENABLE_FUZZING
	jmp .done
%endif

	call xorshift64
	test r15, 0x3
	jz   .create_new_fuzz

.use_coverage:
	mov r10, -1
	mov r11, 0
	mov r12, 64
.try_another:
	dec r12
	jz  short .do_the_copy

	mov  rcx, qword [fs:globals.coverage_fht]
	call fht_random
	test rax, rax
	jz   .try_another

	cmp qword [rax + bb_struc.count], r10
	jae short .try_another

	mov r10, qword [rax + bb_struc.count]
	mov r11, rax
	jmp short .try_another

.do_the_copy:
	test r11, r11
	jz   .create_new_fuzz

	movdqu xmm5, [r11 + bb_struc.input_hash]
	call   input_entry_from_hash

	mov rsi, rdx
	mov rdi, qword [gs:thread_local.rtf_fuzz]
	mov rcx, qword [fs:globals.per_node_rtf + node_struct.data_len]
	rep movsb

.create_new_fuzz:
%if 0
	mov rdi, qword [gs:thread_local.rtf_fuzz]

	call xorshift64
	mov  rcx, r15
	and  rcx, 0xff
	test rcx, rcx
	jz   short .no_byte_corrupt
.lewp:
	call xorshift64
	xor  rdx, rdx
	mov  rax, r15
	div  qword [fs:globals.per_node_rtf + node_struct.data_len]

	call xorshift64
	mov  byte [rdi + rdx], r15b

	dec rcx
	jnz short .lewp
.no_byte_corrupt:
%endif

%if 0
	call xorshift64
	mov  rcx, r15
	and  rcx, 0xf
	test rcx, rcx
	jz   short .no_corp_corrupt
.cc_corrupt:
	call corrupt_from_corpus
	dec  rcx
	jnz  short .cc_corrupt
.no_corp_corrupt:
%endif

%if 1
	call corpymem
	call corpymem
	call corpymem
	call corpymem
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

inject_corrupt_bytes:
	push rcx
	push rdx
	push rdi
	push rsi
	push r10
	push r11

	; Hook 1 - UfsIoCache::Read()
	; hook at mpengine+0x????

	; r10  - Offset
	; r11  - Buffer
	; r12d - Bytes read
	;
	; [rsp + 0x78 + 0x10] - int64_t   off
	; [rsp + 0x78 + 0x18] - void     *buf

	; Get the offset
	mov  rdx, [rax + VMCB.rsp]
	add  rdx, 0x78 + 0x10
	call mm_read_guest_qword
	mov  r10, rdx

	; Get the buffer
	mov  rdx, [rax + VMCB.rsp]
	add  rdx, 0x78 + 0x18
	call mm_read_guest_qword
	mov  r11, rdx

	; Calculate bread + offset
	mov rsi, r12
	add rsi, r10

	; (length + offset) must not exceed file length
	cmp rsi, qword [fs:globals.per_node_rtf + node_struct.data_len]
	ja  short .dont_corrupt

	; Allocate room on the stack for the data
	sub rsp, r12

	; Read the read contents from the VM
	mov  rdi, rsp
	mov  rsi, r11
	mov  rcx, r12
	call mm_copy_from_guest_vm_vmcb

	; Check if the contents from the VM match the original input file at the
	; specified offset
	mov rdi, rsp
	mov rsi, qword [gs:thread_local.rtf_orig]
	add rsi, r10
	mov rcx, r12
	rep cmpsb
	jne short .dont_corrupt_free

	mov  rsi, qword [gs:thread_local.rtf_fuzz]
	add  rsi, r10
	mov  rdi, r11
	mov  rcx, r12
	call mm_copy_to_guest_vm_vmcb

.dont_corrupt_free:
	add rsp, r12
.dont_corrupt:
	pop r11
	pop r10
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	ret

