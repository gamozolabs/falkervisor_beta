[bits 64]

; rcx -> ID of spinlock to acquire
acquire_spinlock:
	push rbx

	; Acquire a lock
	mov  rbx, 1
	lock xadd qword [fs:globals.spinlocks_lock + rcx*8], rbx

	; Spin until we're the chosen one
.spin:
	pause
	cmp rbx, qword [fs:globals.spinlocks_release + rcx*8]
	jne short .spin

	pop rbx
	ret

; rcx -> ID of spinlock to release
release_spinlock:
	; Release the lock
	inc qword [fs:globals.spinlocks_release + rcx*8]

	ret

; rbx -> Array of pointers to sort (based on element)
; rcx -> Number of elements in the array
; rdx -> Index of 64-bit signed value to sort by in the pointer
heapsort:
	push rcx
	push rsi
	push rdi
	push r8
	push r9

	call heapify

	; end := count - 1
	dec rcx
.lewp:
	; while end > 0
	cmp rcx, 0
	jle short .end

	; swap(a[end], a[0])
	mov r8, qword [rbx + rcx*8]
	mov r9, qword [rbx]
	mov qword [rbx + rcx*8], r9
	mov qword [rbx],         r8

	dec rcx

	mov  rsi, 0
	mov  rdi, rcx
	call siftdown

	jmp short .lewp
	
.end:
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rcx
	ret

; rbx -> Array of pointers to sort (based on element)
; rcx -> Number of elements in the array
; rdx -> Byte index of 64-bit value to sort by in the pointer
heapify:
	push rsi
	push rdi

	; start <- floor((count - 2) / 2)
	mov rsi, rcx
	sub rsi, 2
	shr rsi, 1

	; end <- count - 1
	mov rdi, rcx
	dec rdi

.lewp:
	cmp rsi, 0
	jl  short .end

	call siftdown

	dec rsi
	jmp short .lewp

.end:
	pop rdi
	pop rsi
	ret

; rbx -> Array of pointers to sort (based on element)
; rdx -> Byte index of 64-bit value to sort by in the pointer
; rsi -> 'start'
; rdi -> 'end'
siftdown:
	push rsi
	push rbp
	push r8
	push r9
	push r10
	push r11

.lewp:
	; rbp := start * 2 + 1
	mov rbp, rsi
	shl rbp, 1
	add rbp, 1

	cmp rbp, rdi
	jg  short .end

	mov r10, rsi

	; rbp - child
	; rsi - root
	; r10 - swap
	; r11 - child + 1

	mov r8, qword [rbx + r10*8]
	mov r8, qword [r8  + rdx]
	mov r9, qword [rbx + rbp*8]

	; if a[swap] < a[child]
	;   swap := child
	cmp r8, qword [r9 + rdx]
	jnl short .no_chillins

	; swap := child
	mov r10, rbp

.no_chillins:
	; child + 1
	mov r11, rbp
	inc r11

	cmp r11, rdi
	jg  short .right_child_is_not_greater

	mov r8, qword [rbx + r10*8]
	mov r8, qword [r8  + rdx]
	mov r9, qword [rbx + r11*8]
	cmp r8, qword [r9 + rdx]
	jnl short .right_child_is_not_greater

	; swap := child + 1
	mov r10, r11

.right_child_is_not_greater:
	; if swap == root: return
	cmp r10, rsi
	je  short .end

	; swap(root, swap)
	mov r8, qword [rbx + rsi*8]
	mov r9, qword [rbx + r10*8]
	mov qword [rbx + rsi*8], r9
	mov qword [rbx + r10*8], r8

	; root = swap
	mov rsi, r10

	jmp short .lewp

.end:
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rsi
	ret

