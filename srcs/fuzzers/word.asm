[bits 64]

; al -> Character
; ZF <- Set if allowed, else not set
rtf_cw_is_allowed_character:
	push rcx
	push rdi

	lea   rdi, [rel rtf_cw_allowed_character]
	mov   rcx, (rtf_cw_allowed_character.end - rtf_cw_allowed_character)
	repne scasb

	pop rdi
	pop rcx
	ret

rtf_cw_allowed_character:
	; Control words most be lowercase. They can be followed by a number. This
	; number can be negative, thus we also can include '-'s.
	;
	; If a space is hit, the parsing is terminated but the space is included
	; in the control word.
	;
	; When a non-allowed character is hit, the parsing is terminated and the
	; character is not stored in the control word.
	;
	db ' -abcdefghijklmnopqrstuvwxyz0123456789'
	.end:

; rbx -> Rtf file
; rbp -> Rtf file length
; r15 -> Seed
; rbx <- Pointer to control word (null if failure)
; rbp <- Length of control word
; r15 <- Updated seed
rtf_get_random_bracket:
	push rax
	push rcx
	push rdx
	push rsi
	push rdi
	push r8
	push r9

	; Find the size of the bracket database in entries
	xor rdx, rdx
	mov rax, qword [fs:globals.per_node_bktdb + node_struct.data_len]
	mov rbp, bracket_size
	div rbp
	mov rbp, rax

	; Pick a random entry in the bracket DB
	call xorshift64
	xor  rdx, rdx
	mov  rax, r15
	div  rbp
	
	; Calculate the array offset in the bracket DB
	imul rdx, rdx, bracket_size

	; Get the actual bracket db entry
	push rax
	push rbx
	mov  rbx, [fs:globals.fs_base]
	lea  rbx, [rbx + globals.per_node_bktdb]
	call per_node_data
	mov  rdi, rax
	pop  rbx
	pop  rax

	lea rdi, [rdi + rdx]

	add rbx, qword [rdi + bracket.idx]
	mov rbp, qword [rdi + bracket.len]

	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rax
	ret

word_minimize:
	push rax
	push rcx
	push rdx
	push rsi
	push rdi
	push r14
	push r15

	mov  rcx, SPINLOCK_MINIMIZE
	call acquire_spinlock

	mov rsi, qword [fs:globals.minimize_input]
	mov rdi, qword [gs:thread_local.rtf_fuzz]
	mov rcx, qword [fs:globals.per_node_rtf + node_struct.data_len]
	rep movsb
	
	mov  rcx, SPINLOCK_MINIMIZE
	call release_spinlock

	call xorshift64
	mov  r14, r15
	and  r14, 0x7
	inc  r14

	; Calculate the number of bytes left to minimize
	mov  rsi, qword [gs:thread_local.rtf_fuzz]
	mov  rcx, qword [fs:globals.per_node_rtf + node_struct.data_len]
	call trailnull
	mov  rcx, qword [fs:globals.per_node_rtf + node_struct.data_len]
	sub  rcx, rax
	mov  qword [gs:thread_local.rtf_bcrp], rcx
	test rcx, rcx
	jz   .bail

.do_more_minimize:
%if 1
	call xorshift64
	test r15, 0x7
	jnz  short .dont_minimize_bracket

	call xorshift64
	xor  rdx, rdx
	mov  rax, r15
	mov  rcx, qword [gs:thread_local.rtf_bcrp]
	div  rcx

	; Parser state. 0 - looking for {, 1 - looking for }
	xor r15, r15

	mov rsi, qword [gs:thread_local.rtf_fuzz]
	add rsi, rdx
	mov rcx, qword [fs:globals.per_node_rtf + node_struct.data_len]
	sub rcx, rdx
.fill_bracket:
	test r15, r15
	jnz  short .looking_for_end

	cmp byte [rsi], '{'
	jne short .next_byte

	mov r15, 1

.looking_for_end:
	; If we're at the end, make our length 1 so that we end after this. This
	; allows us to write over the closing bracket with a 0, and continue to
	; exit after writing it.
	cmp   byte [rsi], '}'
	cmove rcx, r15

	mov byte [rsi], 0

.next_byte:
	inc rsi
	dec rcx
	jnz short .fill_bracket

.dont_minimize_bracket:
%endif
%if 1
	; Get the offset to start to zero
	call xorshift64
	xor  rdx, rdx
	mov  rax, r15
	mov  rcx, qword [gs:thread_local.rtf_bcrp]
	div  rcx

	; Calculate pointer and length remaining
	mov rdi, qword [gs:thread_local.rtf_fuzz]
	add rdi, rdx
	mov rcx, qword [fs:globals.per_node_rtf + node_struct.data_len]
	sub rcx, rdx

	cmp rcx, 8
	jl  short .skip_zeroing

	; Get a length to start to zero
	call xorshift64
	xor  rdx, rdx
	mov  rax, r15
	mov  rcx, 8
	div  rcx

	; Zero it out
	xor eax, eax
	mov rcx, rdx
	rep stosb
%endif

.skip_zeroing:
	dec r14
	jnz .do_more_minimize

.done:
	call xorshift64
	mov  r14, r15
	and  r14, 0x1f
	inc  r14

.do_some_compress:
	; Get the offset to compress
	call xorshift64
	xor  rdx, rdx
	mov  rax, r15
	mov  rcx, qword [gs:thread_local.rtf_bcrp]
	div  rcx

	test rdx, rdx
	jz   .dont_compress

	; Calculate pointer and length remaining
	mov rdi, qword [gs:thread_local.rtf_fuzz]
	add rdi, rdx
	mov rcx, qword [fs:globals.per_node_rtf + node_struct.data_len]
	sub rcx, rdx
	mov rsi, rdi

	cmp byte [rdi - 1], 0
	jne .dont_compress

.find_first_zero:
	dec rdi
	cmp byte [rdi], 0
	je  .find_first_zero

	inc rdi
	mov rdx, rsi
	sub rdx, rdi

	; rdi now has scanned backwards to the first zero
	; rsi points to the initial random point we sampled
	; rcx is the length of the rest of the file
	rep movsb

	mov rdi, qword [gs:thread_local.rtf_fuzz]
	add rdi, qword [fs:globals.per_node_rtf + node_struct.data_len]
	sub rdi, rdx
	mov rcx, rdx
	xor eax, eax
	rep stosb

.dont_compress:
	dec r14
	jnz short .do_some_compress

.bail:
	; Calculate the number of different quadwords
	mov  rsi, qword [gs:thread_local.rtf_fuzz]
	mov  rcx, qword [fs:globals.per_node_rtf + node_struct.data_len]
	call trailnull
	mov  qword [gs:thread_local.rtf_bcrp], rax
	call nullcount
	mov  qword [gs:thread_local.rtf_null], rax

	pop r15
	pop r14
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rax
	ret

word_fuzz:
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

%ifdef ENABLE_LOGGING
	call start_log
%endif

	call xorshift64
	test r15, 0xF
	jz   .create_new_fuzz

	mov r10, -1
	mov r11, 0
	mov r12, 16
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

	jmp .create_new_fuzz

.create_new_fuzz:
	mov rbx, qword [fs:globals.per_node_rtf + node_struct.data_len]
	mov qword [gs:thread_local.fuzz_size], rbx

.do_fuzz:
%ifdef BRACKET_FUZZ
	mov rdi, qword [gs:thread_local.rtf_fuzz]
	add rdi, DONT_CORRUPT_FIRST
	mov rsi, qword [gs:thread_local.fuzz_size]
	sub rsi, DONT_CORRUPT_FIRST
	cmp rsi, 0
	jle panic

	call xorshift64
	mov  r10, r15
	and  r10, 0xff
	test r10, r10
	jz   .end_bracket_fuzz
.corrupt_bracket:
	mov  rbx, [fs:globals.fs_base]
	lea  rbx, [rbx + globals.per_node_fuzzdat]
	call per_node_data
	mov  rbx, rax

	mov  rbp, qword [fs:globals.per_node_fuzzdat + node_struct.data_len]
	call rtf_get_random_bracket
	test rbx, rbx
	jz   short .next_bracket

	; Get a random offset in the RTF
	call xorshift64
	xor rdx, rdx
	mov rax, r15
	div rsi

	; Get the number of bytes remaining in the file and make sure we have
	; room to inject this control word
	mov r8, rsi
	sub r8, rdx
	cmp r8, rbp
	jl  short .next_bracket

	; Copy the control word into the fuzz input
	push rcx
	push rsi
	push rdi
	lea  rdi, [rdi + rdx]
	mov  rsi, rbx
	mov  rcx, rbp
	rep  movsb
	pop  rdi
	pop  rsi
	pop  rcx

.next_bracket:
	dec r10
	jnz .corrupt_bracket

.end_bracket_fuzz:
%endif

%ifdef CW_FUZZ
	call xorshift64
	mov  r13, r15
	and  r13, 0xff
	test r13, r13
	jz   .end_cw_fuzz
.do_another_cw_fuzz:
	mov rcx, qword [gs:thread_local.fuzz_size]
	sub rcx, DONT_CORRUPT_FIRST
	cmp rcx, 0
	jle panic
	
	; Randomly pick a place to corrupt
	call xorshift64
	xor rdx, rdx
	mov rax, r15
	div rcx

	; Calculate the length remaining
	sub rcx, rdx

	; Calculate the pointer to corrupt
	mov rbx, [gs:thread_local.rtf_fuzz]
	add rbx, rdx
	add rbx, DONT_CORRUPT_FIRST

	; Calculate number of entries in ctrldb
	xor rdx, rdx
	mov rax, qword [fs:globals.per_node_ctrldb + node_struct.data_len]
	mov rbp, ctrl_size
	div rbp
	mov rsi, rax

	push rax
	push rbx
	mov  rbx, [fs:globals.fs_base]
	lea  rbx, [rbx + globals.per_node_fuzzdat]
	call per_node_data
	mov  rdi, rax
	pop  rbx
	pop  rax

	; rbx - Thing to fuzz
	; rcx - Room remaining to fuzz
	; rsi - Number of db entries
	; rdi - Pointer to parsed_rtf
	;  r8 - Counter
	;  r9 - Entry to fuzz around

	; Select a random entry
	call xorshift64
	xor rdx, rdx
	mov rax, r15
	div rsi
	mov  r9, rdx

	; How many control words do we want to place in a row?
	call xorshift64
	mov r8, r15
	and r8, 0xf
	inc r8
.place_control_word:
	; Select a random entry around the base entry
	call xorshift64
	mov r10, r15
	and r10, 0xff
	sub r10, 128
	add r10, r9

	; If we're OOB, stop
	cmp r10, rsi
	jge .done_fuzzing
	cmp r10, 0
	jl  .done_fuzzing

	imul r10, r10, ctrl_size

	; Get the entry
	push rax
	push rbx
	mov  rbx, [fs:globals.fs_base]
	lea  rbx, [rbx + globals.per_node_ctrldb]
	call per_node_data
	mov  r14, rax
	pop  rbx
	pop  rax
	lea  r14, [r14 + r10]

	; Make sure we have room for this entry
	mov  r11, qword [r14 + ctrl.len]
	add  r11, 256
	cmp  r11, rcx
	jge  .done_fuzzing

	call xorshift64
	test r15, 0x7
	jnz  short .dont_open

	mov byte [rbx], '{'
	inc rbx
	dec rcx

.dont_open:
	call xorshift64
	test r15, 0x7
	jnz  short .dont_close

	mov byte [rbx], '}'
	inc rbx
	dec rcx

.dont_close:

	push rcx
	push rdi
	push rsi

	mov rsi, qword [r14 + ctrl.idx]
	lea rsi, [rdi + rsi]
	mov rdi, rbx
	mov rcx, qword [r14 + ctrl.len]
	rep movsb

	pop rsi
	pop rdi
	pop rcx

	mov r11, qword [r14 + ctrl.len]
	add rbx, r11
	sub rcx, r11

	cmp qword [r14 + ctrl.num], 0
	je  short .next

	call xorshift64
	mov r10, r15
	and r10, 0x3
	inc r10
.for_each_num:
	call xorshift64
	xor rdx, rdx
	mov rax, r15
	mov rbp, 10
	div rbp
	
	add dl, 0x30
	mov byte [rbx], dl
	inc rbx
	dec rcx

	dec r10
	jnz short .for_each_num
	
.next:
	dec r8
	jnz .place_control_word

	dec r13
	jnz .do_another_cw_fuzz

.end_cw_fuzz:
%endif

.done_fuzzing:
%ifdef ENABLE_LOGGING
	call stop_log
	add  qword [gs:thread_local.time_corrupt], rdx
%endif

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

