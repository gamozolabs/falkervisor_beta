[bits 64]

%define FLUT_BIN_SIZE 2

; rsi <- flut vector
flut_alloc:
	push rax
	push rcx
	push rdi

	; Check if we're out of flut entries
	cmp qword [gs:thread_local.flut_pages_rem], 0
	jne short .dont_alloc_page

	; Allocate a whole page
	mov rsi, 4096
	rand_alloc rsi

	; Zero out the page
	mov rdi, rsi
	mov ecx, (4096 / 8)
	xor eax, eax
	rep stosq

	; Save the new flut pages
	mov qword [gs:thread_local.flut_pages],     rsi
	mov qword [gs:thread_local.flut_pages_rem], 4096 / ((1 << FLUT_BIN_SIZE)*8)

.dont_alloc_page:
	; Consume one flut allocation
	mov  rsi, ((1 << FLUT_BIN_SIZE) * 8)
	xadd qword [gs:thread_local.flut_pages], rsi
	dec  qword [gs:thread_local.flut_pages_rem]

	pop rdi
	pop rcx
	pop rax
	ret

; rcx  -> flut
; xmm5 -> hash
; rcx  <- flut entry or pointer to flut entry to fill
; CF   <- Set if flut needs to be filled
flut_fetch_or_lock:
	push rax
	push rbx
	push rdx
	push rsi
	push rbp

	movq rdx, xmm5

	mov rbx, (128 / FLUT_BIN_SIZE)
.for_each_bin:
	mov ebp, edx
	and ebp, ((1 << FLUT_BIN_SIZE) - 1)
	ror rdx, FLUT_BIN_SIZE

	; Check if this entry has been filled
	mov rsi, qword [rcx + rbp*8]
	cmp rsi, 2
	jae short .filled

	; The entry has not been filled, atomicially try to lock it down so we
	; can fill it!
	xor  eax, eax
	mov  esi, 1
	lock cmpxchg qword [rcx + rbp*8], rsi
	jne  short .wait_for_fill

	; We succeeded in obtaining the lock. If this is the last bin in the hash
	; we want to return to the user to fill in this last piece.
	lea rax, [rcx + rbp*8]
	cmp rbx, 1
	je  short .done_needs_fill

	; We obtained the lock and we are not at the last level, allocate another
	; array and place it in the flut.
	call flut_alloc
	
	mov qword [rcx + rbp*8], rsi
	jmp short .filled

.wait_for_fill:
	; We lost the race in locking, wait for the caller with the lock to fill
	; it in and then treat it as a filled entry.
	pause
	cmp qword [rcx + rbp*8], 1
	jbe short .wait_for_fill
	mov rsi, qword [rcx + rbp*8]

.filled:
	cmp rbx, (64 / FLUT_BIN_SIZE) + 1
	jne short .dont_grab_upper

	pextrq rdx, xmm5, 1

.dont_grab_upper:
	mov rcx, rsi
	dec rbx
	jnz short .for_each_bin

	; At this point the entry of the flut was filled in, return the value
	; in the flut and clear CF.
	mov rax, rcx

	clc
	jmp short .done
.done_needs_fill:
	stc
.done:
	mov rcx, rax
	pop rbp
	pop rsi
	pop rdx
	pop rbx
	pop rax
	ret

; rcx -> flut
; rax <- random entry from flut
global flut_random
flut_random:
	push rbx
	push rcx
	push rdx
	push rbp
	push rdi

	XMMPUSH xmm15

	call falkrand
	movq rbp, xmm15

	xor ebx, ebx
.lewp:
	mov eax, ebp
	and eax, ((1 << FLUT_BIN_SIZE) - 1)
	ror rbp, FLUT_BIN_SIZE

	mov edi, (1 << FLUT_BIN_SIZE)
.try_find_next:
	cmp qword [rcx + rax*8], 2
	jae short .found

	inc eax
	and eax, ((1 << FLUT_BIN_SIZE) - 1)
	dec edi
	jnz short .try_find_next
	jmp short .fail

.found:
	mov rcx, [rcx + rax*8]
	inc ebx
	cmp ebx, (64 / FLUT_BIN_SIZE)
	jne short .dont_get_high

	pextrq rbp, xmm15, 1

.dont_get_high:
	cmp ebx, (128 / FLUT_BIN_SIZE)
	jb  short .lewp

	mov rax, rcx
	jmp short .done
.fail:
	xor eax, eax
.done:
	XMMPOP xmm15

	pop rdi
	pop rbp
	pop rdx
	pop rcx
	pop rbx
	ret 

struc fht_table
	.entries: resq 1 ; Number of used entries in this table
	.bits:    resq 1 ; Number of bits in this table
	.table:   resq 1 ; Pointer to hash table
	.ents:    resq 1 ; Pointer to list of hashes
endstruc

struc fht_entry
	.hash: resq 2
	.data: resq 1
	.pad:  resq 1
endstruc

struc fht_list_entry
	.hash: resq 2
endstruc

; rcx -> Number of bits
; rcx <- Hash table base
fht_create:
	push rax
	push rdi
	push rbp

	; Allocate the table header
	mov rbp, fht_table_size
	rand_alloc rbp

	; Initialize the table header
	mov qword [rbp + fht_table.entries], 0
	mov qword [rbp + fht_table.bits],    rcx

	; Calculate the table size
	mov eax, 1
	shl rax, cl

	; Allocate and zerothe hash table
	imul rdi, rax, fht_entry_size
	mov  rcx, rdi
	mixed_alloc rdi
	call bzero
	mov  [rbp + fht_table.table], rdi

	; Allocate and zero the hash list table
	imul rdi, rax, fht_list_entry_size
	mov  rcx, rdi
	mixed_alloc rdi
	call bzero
	mov  [rbp + fht_table.ents], rdi

	mov rcx, rbp

	pop rbp
	pop rdi
	pop rax
	ret

; rcx -> Pointer to hash table
; rax <- Random entry (or zero if no entries are present)
fht_random:
	push rbx
	push rcx
	push rdx
	push r15

	XMMPUSH xmm5

	cmp qword [rcx + fht_table.entries], 0
	je  short .fail

	; Pick a random entry
	call xorshift64
	xor  rdx, rdx
	mov  rax, r15
	div  qword [rcx + fht_table.entries]

	; Calculate the entry offset
	mov  rbx, [rcx + fht_table.ents]
	imul rdx, fht_list_entry_size

	; Fetch the random hash. If it is zero, fail.
	movdqu xmm5, [rbx + rdx + fht_list_entry.hash]
	ptest  xmm5, xmm5
	jz     short .fail

	; Look up the hash. This will always succeed.
	call fht_fetch_or_lock
	mov  rax, rcx
	jmp  short .done

.fail:
	xor rax, rax
.done:
	XMMPOP xmm5

	pop r15
	pop rdx
	pop rcx
	pop rbx
	ret

; rcx  -> Pointer to hash table
; xmm5 -> Hash
; rcx  <- Pointer to entry or entry (depending on CF)
; CF   <- Set if this is a new entry we must populate
fht_fetch_or_lock:
	push rax
	push rbx
	push rdx
	push rdi
	push rbp

	XMMPUSH xmm4

	; Save off the hash table pointer
	mov rbp, rcx

	mov rbx, [rbp + fht_table.table]
	mov rcx, [rbp + fht_table.bits]

	; rbx now points to the start of the hash table vector
	; rcx is now the number of bits in the hash table

	; Get the low 64-bits of the hash
	movq rdx, xmm5

	; Calculate the mask
	mov eax, 1
	shl rax, cl
	dec rax

	; Mask the hash
	and rdx, rax

	; Calculate the byte offset into the hash table
	imul rdx, fht_entry_size

.next_entry:
	; Look up this entry in the table
	movdqu xmm4, [rbx + rdx + fht_entry.hash]

	; If this bin is empty, try to fill it
	ptest xmm4, xmm4
	jz    short .empty

	; If the hashes match, we have an entry!
	pxor  xmm4, xmm5
	ptest xmm4, xmm4
	jz    short .found

	; The bin was not empty, nor did our hash match. This is a collision case.
	; Go to the next entry (linear probing)
	add rdx, fht_entry_size
	and rdx, rax
	jmp short .next_entry

.empty:
	; The bin was empty, try to win the race to fill it.
	lea rdi, [rbx + rdx + fht_entry.hash]

	; We did not find an entry, try to atomicially populate this entry
	push rax
	push rbx
	push rcx
	push rdx

	; Compare part
	xor edx, edx
	xor eax, eax

	; Exchange part
	pextrq rcx, xmm5, 1
	pextrq rbx, xmm5, 0

	lock cmpxchg16b [rdi]

	; If we lost, rdx:rax is the 128-bit value that we lost to. Store this in
	; xmm4.
	pinsrq xmm4, rdx, 1
	pinsrq xmm4, rax, 0

	pop  rdx
	pop  rcx
	pop  rbx
	pop  rax
	je   short .won_race

	; We lost the race. Check if the hash matches (we could lose the race to
	; a collision case).
	pxor  xmm4, xmm5
	ptest xmm4, xmm4
	jz    short .found

	; We lost the race, and it was a collision. Go to the next entry.
	add rdx, fht_entry_size
	and rdx, rax
	jmp short .next_entry

.won_race:
	; We won the race! Return the address of the data to fill.
	lea rcx, [rbx + rdx + fht_entry.data]

	; Get this entry's ID
	mov  edi, 1
	lock xadd qword [rbp + fht_table.entries], rdi

	; Add this hash to the hash list
	mov    rbx, [rbp + fht_table.ents]
	imul   rdi, fht_list_entry_size
	movdqu [rbx + rdi + fht_list_entry.hash], xmm5

	XMMPOP xmm4

	pop rbp
	pop rdi
	pop rdx
	pop rbx
	pop rax
	stc
	ret

.found:
	; Fetch the data. If it is zero, loop until it is not.
	mov  rcx, [rbx + rdx + fht_entry.data]
	test rcx, rcx
	jz   short .found

	XMMPOP xmm4

	pop rbp
	pop rdi
	pop rdx
	pop rbx
	pop rax
	clc
	ret

