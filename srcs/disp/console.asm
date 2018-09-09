[bits 64]

; sets rdi to point to the calling cores designated display location
per_core_screen:
	imul rdi, qword [gs:thread_local.core_id], 40
	add  rdi, 0xb8000
	ret

hexlut: db "0123456789ABCDEF"

; outhexq
;
; Summary:
;
; This function writes out hexlified value rdx to the screen (pointed to by
; rdi). rdi is incremented by 32 as `stosw` is used to write the bytes.
;
; Parameters:
;
; rdx - Number to hexlify and display
; rdi - Pointer to buffer to recieve characters (usually the screen)
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
; rdi - Incremented by 32
;
; Optimization
;
; Readability
;
outhexq:
	push rax
	push rbx
	push rcx
	; We don't need to save rdx because it's been rotated back to original

	mov cl, 16
.lewp:
	rol rdx, 4

	mov rax, rdx
	and rax, 0xF
	lea rbx, [rel hexlut]
	mov  al, byte [rbx + rax]
	mov  ah, 0x0F
	stosw

	dec cl
	jnz short .lewp

	pop rcx
	pop rbx
	pop rax
	ret

; output xmm0 to screen in hex form
; rdi  -> Screen pointer
; xmm0 -> Data to display
; rdi  <- Incremented screen pointer
outhex128:
	push rdx

	pextrq rdx, xmm0, 1
	call   outhexq
	pextrq rdx, xmm0, 0
	call   outhexq

	pop rdx
	ret

; outdecq
;
; Summary:
;
; This function writes out decimalified value rdx to the screen (pointed to by
; rdi). rdi is incremented by 40 as `stosw` is used to write the bytes.
;
; Parameters:
;
; rdx - Number to decimalify and display
; rdi - Pointer to buffer to recieve characters (usually the screen)
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
; rdi - Incremented by 40
;
; Optimization
;
; Readability
;
outdecq:
	push rax
	push rbx
	push rcx
	push rdx
	push r8
	push r9

	std
	add rdi, 38

	mov cl, 20
	mov r8, rdx
	mov r9, 10
.lewp:
	xor rdx, rdx
	mov rax, r8
	div r9
	mov r8, rax

	lea rbx, [rel hexlut]
	mov  al, byte [rbx + rdx]
	mov  ah, 0x0F
	stosw

	dec cl
	jnz short .lewp

	add rdi, 42
	cld

	pop r9
	pop r8
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; outdecqsz
;
; Summary:
;
; This function writes out decimalified value rdx to the screen (pointed to by
; rdi). rdi is incremented by (sz * 2) as `stosw` is used to write the bytes.
;
; Parameters:
;
; rcx - Number of digits to display (from right to left), 2 means 'nn'
; rdx - Number to decimalify and display
; rdi - Pointer to buffer to recieve characters (usually the screen)
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
; rdi - Incremented by (rcx * 2)
;
; Optimization
;
; Readability
;
outdecqsz:
	push rax
	push rbx
	push rcx
	push rdx
	push r8
	push r9

	std
	lea  rdi, [rdi + rcx*2 - 2]
	push rcx

	; Passed in
	;mov cl, 20
	mov r8, rdx
	mov r9, 10
.lewp:
	xor rdx, rdx
	mov rax, r8
	div r9
	mov r8, rax

	lea rbx, [rel hexlut]
	mov  al, byte [rbx + rdx]
	mov  ah, 0x0F
	stosw

	dec cl
	jnz short .lewp

	pop rcx
	lea rdi, [rdi + rcx*2 + 2]
	cld

	pop r9
	pop r8
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; outfixedb10d4
;
; Summary:
;
; This function writes out decimalified value rdx to the screen (pointed to by
; rdi). rdi is incremented by 42 as `stosw` is used to write the bytes.
; The output print will be based on a base 10 fixed point representation with
; 4 digits (n.xxxx) of fixed pointness
;
; Parameters:
;
; rdx - Number to decimalify and display
; rdi - Pointer to buffer to recieve characters (usually the screen)
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
; rdi - Incremented by 42
;
; Optimization
;
; Readability
;
outfixedb10d4:
	push rax
	push rbx
	push rcx
	push rdx
	push r8
	push r9

	std
	add rdi, 40

	mov cl, 20
	mov r8, rdx
	mov r9, 10
.lewp:
	xor rdx, rdx
	mov rax, r8
	div r9
	mov r8, rax

	lea rbx, [rel hexlut]
	mov  al, byte [rbx + rdx]
	mov  ah, 0x0F
	stosw

	cmp cl, (20 - 3)
	jne short .not_decimal_time

	mov al, '.'
	stosw

.not_decimal_time:
	dec cl
	jnz short .lewp

	add rdi, 44
	cld

	pop r9
	pop r8
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; outdecqi
;
; Summary:
;
; This function writes out decimalified value rdx to the screen (pointed to by
; rdi). rdi is incremented by 40 as `stosw` is used to write the bytes.
; This is the signed version of outdecq
;
; Parameters:
;
; rdx - Number to decimalify and display
; rdi - Pointer to buffer to recieve characters (usually the screen)
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
; rdi - Incremented by 42
;
; Optimization
;
; Readability
;
outdecqi:
	push rax
	push rbx
	push rcx
	push rdx
	push r8
	push r9
	push r10

	xor r10, r10

	bt  rdx, 63
	jnc short .positive

	bts r10, 0
	neg rdx

.positive:
	std
	add rdi, 40

	mov cl, 20
	mov r8, rdx
	mov r9, 10
.lewp:
	xor rdx, rdx
	mov rax, r8
	div r9
	mov r8, rax

	lea rbx, [rel hexlut]
	mov  al, byte [rbx + rdx]
	mov  ah, 0x0F
	stosw

	dec cl
	jnz short .lewp

	test r10, r10
	jz   short .noneg

	mov ax, 0x0F2D
	stosw

	jmp short .done
.noneg:
	mov ax, 0x0F2B
	stosw

.done:
	add rdi, 44
	cld

	pop r10
	pop r9
	pop r8
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; outdecexp
;
; Summary:
;
; This function writes out the decimal representation of the exponent style
; float. The number is input in rdx, and the exponent is input in rcx.
; rbx will specify the number of digits after the decimal
;
; TODO: This function does not support exponents >0 or does it support very
;       negative exponents
;
; Parameters:
;
; rcx - Exponent to use during displaying
; rdx - Number to decimalify and display
; rdi - Pointer to buffer to recieve characters (usually the screen)
;
; Alignment:
;
; None
;
; Retuerns:
;
; None
;
; Smashes:
;
; rdi - Incremented to point to the next element after the printed string
;
; Optimization
;
; Readability
;
outdecexp:
	push rax
	push rbx
	push rcx
	push rdx
	push r8
	push r9
	push r10
	push r11

	xor r10, r10

	bt  rdx, 63
	jnc short .positive

	bts r10, 0
	neg rdx

.positive:
	push rcx

	mov rcx, 40
	xor  al, al
	rep stosb

	pop rcx

	std

	mov r11, -1
	mov  r8, rdx
	mov  r9, 10
.lewp:
	xor rdx, rdx
	mov rax, r8
	div r9
	mov r8, rax

	lea rbx, [rel hexlut]
	mov  al, byte [rbx + rdx]
	mov  ah, 0x0F
	stosw

	cmp r11, rcx
	jne short .dont_print_dec

	mov ax, 0x0F2E
	stosw

.dont_print_dec:
	dec  r11
	test r8, r8
	jnz  short .lewp

	test r10, r10
	jz   short .noneg

	mov ax, 0x0F2D
	stosw

	jmp short .done
.noneg:
	mov ax, 0x0F2B
	stosw

.done:
	add rdi, 44
	cld

	pop r11
	pop r10
	pop r9
	pop r8
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; outdouble
;
; Summary:
;
; This function writes out the double value in xmm0 to the screen in it's
; decimal form.
;
; Parameters:
;
; xmm0 - Number to decimalify and display
; rdi  - Pointer to buffer to recieve characters (usually the screen)
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
; rdi - Incremented by 40
;
; Optimization
;
; Readability
;
outdouble:
	push rax
	push rbx
	push rcx
	push rdx
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13

	movq rdx, xmm0
	
	; rax - Mantissa
	mov rax, rdx
	mov rbx, 0xFFFFFFFFFFFFF
	and rax, rbx

	; rbx - Exponent with bias applied
	mov rbx, rdx
	shr rbx, 52
	and rbx, 0x7FF
	sub rbx, 1023

	xor r8, r8 ; decimalExponent
	mov r9, 1  ; sideMultiplicator

.for_each_exponent_pos:
	cmp rbx, 0
	jle short .done_exponent_pos

	shl r9, 1
	
	mov r10, r9
	shr r10, 30
	jz  short .no_overflow

	push rax
	push rdx
	add  r8, 3
	mov r11, 1000
	xor rdx, rdx
	mov rax, r9
	div r11
	mov r9, rax
	pop rdx
	pop rax

.no_overflow:
	dec rbx
	jmp short .for_each_exponent_pos

.done_exponent_pos:
.for_each_exponent_neg:
	cmp rbx, 0
	jge short .done_exponent_neg

	mov r11, r9
	shr r11, 30
	jz  short .no_overflow_neg

	imul r9, r9, 10
	sub  r8, 1

.no_overflow_neg:
	shr r9, 1

	inc rbx
	jmp short .for_each_exponent_neg

.done_exponent_neg:
	; rax - Mantissa
	; r8  - decimalExponent
	; r9  - sideMultiplicator
	; r10 - betweenResult
	; r11 - fraction
	; r12 - bit
	mov r10, r9
	mov r11, 2
	xor r12, r12

.frac:
	cmp r12, 52
	jge short .done_frac

	mov rcx, 51
	sub rcx, r12
	bt  rax, rcx
	jnc .cont_frac

.while_fraction:
	push rax
	push rdx
	xor rdx, rdx
	mov rax, r9
	div r11
	mov r13, rdx
	pop rdx
	pop rax

	cmp r13, 0
	jle .done_while

	mov r13, r10
	shr r13, 58
	jnz short .done_while

	imul r10, r10, 10
	imul  r9,  r9, 10
	sub   r8, 1
	jmp short .while_fraction

.done_while:
	push rax
	push rdx
	xor rdx, rdx
	mov rax, r9
	div r11
	mov r13, rax
	pop rdx
	pop rax

	add r10, r13
	
.cont_frac:
	add r12, 1
	shl r11, 1
	jmp short .frac

.done_frac:
	bt  rdx, 63
	jnc short .not_signed

	;neg r10

.not_signed:
	; now r8 contains the number and r10 contains the base-10 exponent

	; for example, if we were converting '123.3489'
	; r10 would contain: +1233488999999999998
	; r8  would contain: -16

	mov  rcx, r8
	mov  rdx, r10
	call outdecexp

	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; dump_memory_map
;
; Summary:
;
; This function dumps the 0xE820 memory map contents to the screen.
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
dump_memory_map:
	push rbx
	push rcx
	push rdx
	push rdi

	; Set cursor to top left
	mov rdi, 0xb8000

	mov   rbx, MEMORY_MAP_LOC + 0x20
	movzx rcx, word [MEMORY_MAP_LOC]
.lewp:
	; Print the base address
	mov  rdx, qword [rbx]
	call outhexq
	add  rdi, 2

	; Print the length
	mov  rdx, qword [rbx + 0x08]
	call outhexq
	add  rdi, 2

	; Print the type
	mov  edx, dword [rbx + 0x10]
	call outhexq
	add  rdi, (80 * 2) - ((16 * 2) * 3) - 4

	add rbx, 0x20
	dec rcx
	jnz short .lewp
	
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	ret

dump_mmio_map:
	push rax
	push rcx
	push rdx
	push rdi
	push rbp

	mov rdi, 0xb8000

	lea rax, [rel mmio_routing_table]
	mov rcx, 12
.lewp:
	mov rdx, qword [rax + 0] ; Base
	mov rbp, qword [rax + 8] ; Limit

	; If the limit does not exist then go to the next table
	test rbp, rbp
	jz   short .next_table

	mov  rdx, rdx
	call outhexq
	add  rdi, 2

	mov  rdx, rbp
	call outhexq
	add  rdi, (80 * 2) - ((16 * 2) * 2) - 2

.next_table:
	add rax, 0x10
	dec rcx
	jnz short .lewp

	pop rbp
	pop rdi
	pop rdx
	pop rcx
	pop rax
	ret

%macro printstr_nl 2
	push rbx
	push rcx
	jmp .%1_end
	.%1: db %2
	.%1_end:
	lea  rbx, [rel .%1]
	mov  rcx, (.%1_end - .%1)
	call outstr
	add  rdi, (80 * 2) - ((.%1_end - .%1) * 2)
	pop  rcx
	pop  rbx
%endmacro

%macro printstr 2
	push rbx
	push rcx
	jmp .%1_end
	.%1: db %2
	.%1_end:
	lea  rbx, [rel .%1]
	mov  rcx, (.%1_end - .%1)
	call outstr
	pop  rcx
	pop  rbx
%endmacro

; outstr
;
; Summary:
;
; This function prints out the string pointed to by rbx, of rcx length
;
; Parameters:
;
; rbx - Pointer to smmio_routing_tabletring
; rcx - Length of the string to print
; rdi - Location to print to (the screen)
;
; Smashes:
;
; rdi - Incremented by (2 * rcx)
;
; Optimization:
;
; Readability
;
outstr:
	push rax
	push rbx
	push rcx

	mov ah,  0x0F
.lewp:
	mov al, [rbx]
	stosw
	inc rbx
	dec rcx
	jnz short .lewp

	pop rcx
	pop rbx
	pop rax
	ret

