[bits 64]

%define CRASH_CLASS_NULL  0 ; vec #PF addr [0, 16KB)
%define CRASH_CLASS_NEG   1 ; vec #PF addr (-16KB, 0)
%define CRASH_CLASS_INVAL 2 ; vec #PF addr [16KB, -16KB)
%define CRASH_CLASS_ASCII 3 ; vec #GP
%define CRASH_CLASS_OTHER 4 ; vec !(#GP || #PF)

; rax -> VMCB
; rcx <- crash classification based on VMCB data
classify_crash:
	cmp qword [rax + VMCB.exitcode], 0x4d ; #GP
	je  short .class_gp

	cmp qword [rax + VMCB.exitcode], 0x4e ; #PF
	je  short .class_pf

	mov ecx, CRASH_CLASS_OTHER
	ret

.class_gp:
	mov ecx, CRASH_CLASS_ASCII
	ret

.class_pf:
	; rcx = abs(addr)
	mov rcx, qword [rax + VMCB.exitinfo2]
	cmp rcx, 0
	jge short .dont_neg
	neg rcx
.dont_neg:
	; if abs(addr) >= 16KB then it's an inval access
	cmp rcx, (16 * 1024)
	jge short .inval

	; if addr < 0 then it's a neg else it's a null
	cmp qword [rax + VMCB.exitinfo2], 0
	jl  short .neg
	
	mov ecx, CRASH_CLASS_NULL
	ret

.neg:
	mov ecx, CRASH_CLASS_NEG
	ret

.inval:
	mov rcx, CRASH_CLASS_INVAL
	ret

; rcx -> Maximum number of times to invoke (inclusive)
; rbp -> Function to invoke (no parameters)
invoke_random:
	push rax
	push rcx
	push rdx
	push r15

	inc rcx

	call xorshift64
	xor  rdx, rdx
	mov  rax, r15
	div  rcx

	test rdx, rdx
	jz   short .done

.invoke:
	call rbp
	dec  rdx
	jnz  short .invoke
	
.done:
	pop r15
	pop rdx
	pop rcx
	pop rax
	ret

corrupt_from_corpus:
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r15

	mov  rcx, 4
	mov  rdx, 256
	call randexp
	mov  rcx, rax

	; Get a random entry in the dictionary
	push rcx
	push rsi
	call rand_pdf
	mov  rbp, rcx
	pop  rsi
	pop  rcx

	; Generate a random number [0, sizeof(dict_entry))
	call xorshift64
	xor  rdx, rdx
	mov  rax, r15
	div  rbp

	; rsi = random pointer in ftar
	; rcx = MIN(rcx, bytes_remaining_in_ftar)
	lea   rsi, [rbx + rdx]
	sub   rbp, rdx
	cmp   rcx, rbp
	cmova rcx, rbp

	; Get the fuzz image pointer
	mov rdi, qword [gs:thread_local.fuzz_input]

	; Generate a random number [0, sizeof(fuzz_image))
	call xorshift64
	xor  rdx, rdx
	mov  rax, r15
	mov  rbp, qword [gs:thread_local.fuzz_input_len]
	div  rbp

	; rdi = random pointer in fuzz image
	; rcx = MIN(rcx, bytes_remaining_in_fuzz_image)
	lea   rdi, [rdi + rdx]
	sub   rbp, rdx
	cmp   rcx, rbp
	cmova rcx, rbp

	; Copy from a random place in the ftar to a random place in the fuzz image
	rep movsb

	pop r15
	pop rbp
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

corpymem:
	push rax
	push rbx
	push rcx
	push rdx
	push rdi
	push rsi
	push rbp
	push r10
	push r15

	; Pick a random size
	mov  rcx, 8
	mov  rdx, 15
	call randexp
	mov  rcx, rax

	; Get the fuzz image pointer
	mov rdi, qword [gs:thread_local.fuzz_input]

	; Generate a random number [0, sizeof(fuzz_image))
	call xorshift64
	xor  rdx, rdx
	mov  rax, r15
	mov  rbp, qword [gs:thread_local.fuzz_input_len]
	div  rbp

	; rsi = random pointer in fuzz image
	; rcx = MIN(rcx, bytes_remaining_in_fuzz_image)
	lea   rsi, [rdi + rdx]
	sub   rbp, rdx
	mov   r10, rbp
	cmp   rcx, rbp
	cmova rcx, rbp
	mov   rbp, rcx

	; rsi - Random pointer in fuzz image
	; rbp - Bytes to compare
	; r10 - Number of bytes left in the fuzz image

	push rsi
	call rand_pdf
	pop  rsi
	
	call xorshift64
	xor  rdx, rdx
	mov  rax, r15
	div  rcx

	lea rbx, [rbx + rdx]
	sub rcx, rdx

	; rbx - Random pointer in dict entry
	; rcx - Bytes remaining in dict entry

	mov  rdi, rbx
	mov  rdx, rcx
	mov  rsi, rsi
	mov  rcx, rbp
	call memmem
	test rax, rax
	jz   short .no_replace

	push rax
	push rcx
	push rdx
	mov  rcx, 32
	mov  rdx, 256
	call randexp
	mov  r15, rax
	pop  rdx
	pop  rcx
	pop  rax

	cmp   r15, r10
	cmova r15, r10

	mov  rdi, rsi
	mov  rsi, rax
	mov  rcx, r15
	rep  movsb

.no_replace:
	pop r15
	pop r10
	pop rbp
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; xmm5 <- Hash of input
input_create_entry:
	push rcx
	push rdi
	push rsi

	mov  rdi, qword [gs:thread_local.fuzz_input]
	mov  rsi, qword [gs:thread_local.fuzz_input_len]
	call falkhash

	mov  rcx, qword [fs:globals.input_fht]
	call fht_fetch_or_lock
	jnc  short .already_present_input

	; This input hasn't been saved yet, save it!
	mov rdi, input_entry_size
	rand_alloc rdi

	mov rsi, qword [gs:thread_local.fuzz_input_len]
	rand_alloc rsi
	mov [rdi + input_entry.input], rsi

	mov rsi, qword [gs:thread_local.fuzz_input_len]
	rand_alloc rsi
	mov [rdi + input_entry.maps], rsi

	mov rsi, qword [gs:thread_local.fuzz_input_len]
	mov [rdi + input_entry.len], rsi

	push rcx
	push rdi
	mov  rdi, [rdi + input_entry.input]
	mov  rsi, [gs:thread_local.fuzz_input]
	mov  rcx, [gs:thread_local.fuzz_input_len]
	rep  movsb
	pop  rdi
	pop  rcx

	push rcx
	push rdi
	mov  rdi, [rdi + input_entry.maps]
	mov  rsi, [gs:thread_local.fuzz_maps]
	mov  rcx, [gs:thread_local.fuzz_input_len]
	rep  movsb
	pop  rdi
	pop  rcx

	mov qword [rcx], rdi

.already_present_input:
	pop rsi
	pop rdi
	pop rcx
	ret

; xmm5 -> Hash of input
; rdx  <- Pointer to input_entry structure
input_entry_from_hash:
	push rcx

	mov  rcx, qword [fs:globals.input_fht]
	call fht_fetch_or_lock
	jnc  short .already_present_input

	; We should NEVER hit this. Someone tried to look up a hash that is not
	; present!
	jmp panic

.already_present_input:
	mov rdx, rcx
	pop rcx
	ret

; rsi -> Page of memory
add_breakpoints:
	push rsi
	push rdi
	push rcx
	push rax

	mov rax, rsi

	lea rdi, [rel needle]
	lea rsi, [rsi + 0x452]
	mov rcx, 16
	rep cmpsb
	jne short .dont_bp

	mov dword [rax + 0x452], 0xcccccccc

.dont_bp:
	pop rax
	pop rcx
	pop rdi
	pop rsi
	ret

needle:
	db 0x8B, 0xC8, 0xBA, 0x02, 0x00, 0x00, 0x00, 0x81, 0xF9, 0x06, 0x00, 0x00
	db 0xD0, 0x74, 0x41, 0x81

; r8  -> File to munch
; r9  -> Size of file to munch
; r10 -> Prefix
; r11 -> Prefix length
; r12 -> Suffix
; r13 -> Suffix length
; rbp <- Pointer to prefix in file
; rcx <- Size of munched region (zero if no match found)
munch:
	push rax
	push rbx
	push rdx
	push rdi
	push rsi
	push r9

	; Look for the prefix in the file
	mov  rdi, r8
	mov  rdx, r9
	mov  rsi, r10
	mov  rcx, r11
	call memmem
	test rax, rax
	jz   short .prefix_not_found

	; Save off the prefix found address
	mov rbp, rax

	; Calculate the offset where the prefix was found, then the number of
	; bytes left in the file
	sub rax, r8
	sub  r9, rax

	; Look for the suffix after the prefix
	mov  rdi, rbp
	mov  rdx, r9
	mov  rsi, r12
	mov  rcx, r13
	call memmem
	test rax, rax
	jz   short .suffix_not_found

	; Jump to after the suffix
	add rax, r13

	; Calculate the size of the region to munch
	sub rax, rbp

	; Set up the return value
	mov rbp, rbp
	mov rcx, rax

	jmp short .done

.suffix_not_found:
.prefix_not_found:
	xor rbp, rbp
	xor rcx, rcx

.done:
	pop r9
	pop rsi
	pop rdi
	pop rdx
	pop rbx
	pop rax
	ret

