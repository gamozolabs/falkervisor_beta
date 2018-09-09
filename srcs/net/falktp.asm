%define FALKTP_REQ      0x957f977c
%define FALKTP_PUSH     0xda8fa024
%define FALKTP_DAT      0xfe004afa

%define FALKTP_TRANSMIT  0xcd9c04e7
%define FALKTP_CHUNK_REQ 0xb58dc3f7
%define FALKTP_DATA      0xcb4303e4
%define FALKTP_DATA_DONE 0x665e0643

; Must be divisible by 8
%define FALKTP_DATA_SIZE         (8192)
%define FALKTP_PACKETS_PER_CHUNK (256)
%define FALKTP_CHUNK_SIZE        (FALKTP_DATA_SIZE * FALKTP_PACKETS_PER_CHUNK)

;%define FALKTP_USE_HASHES

struc falktp_txmit
	.magic:   resq 1
	.padding: resd 1
	.req_id:  resq 1
	.size:    resq 1
	.hash:    resq 2
endstruc

struc falktp_chunk_req
	.magic:    resd 1
	.padding:  resd 1
	.req_id:   resq 1
	.chunk_id: resq 1
endstruc

struc falktp_data
	.magic:    resd 1
	.padding:  resd 1
	.req_id:   resq 1
	.chunk_id: resq 1
	.seq_id:   resq 1
	.data:     resb FALKTP_DATA_SIZE
endstruc

struc falktp_data_done
	.magic:    resd 1
	.padding:  resd 1
	.req_id:   resq 1
	.chunk_id: resq 1
endstruc

struc falktp_req
	.magic:   resd 1
	.req_id:  resq 1
	.file_id: resq 1
endstruc

struc falktp_push
	.magic:    resd 1
	.req_id:   resq 1
	.file_len: resq 1
	.hash:     resq 2 ; 128-bit falkhash
endstruc

struc falktp_dat
	.magic:  resd 1
	.req_id: resq 1
	.seq_id: resq 1
	.data:   resb FALKTP_DATA_SIZE
endstruc

; r10 -> vaddr to memory to send
; r11 -> size to send
; r15 -> request ID
; rdx -> chunk ID to send
handle_chunk_req:
	push rax
	push rcx
	push rdi
	push rsi
	push r10
	push r11
	sub  rsp, falktp_data_size

	; Initialize the packet template
	mov  dword [rsp + falktp_data.magic],    FALKTP_DATA
	mov  qword [rsp + falktp_data.req_id],   r15
	mov  qword [rsp + falktp_data.chunk_id], rdx
	mov  qword [rsp + falktp_data.seq_id],   0
	lea  rdi, [rsp + falktp_data.data]
	mov  rcx, FALKTP_DATA_SIZE
	call bzero

	; bounds check the chunk id
	imul rax, rdx, FALKTP_CHUNK_SIZE
	add  r10, rax
	cmp  rax, r11
	jae  short .fail

	; r11 = file_size - chunk_offset
	sub r11, rax

	; r11 = max(r11, FALKTP_CHUNK_SIZE)
	cmp r11, FALKTP_CHUNK_SIZE
	jbe short .dont_cap
	mov r11, FALKTP_CHUNK_SIZE
.dont_cap:

	; r10 is the pointer to the data to send
	; r11 is the size in bytes to send
.transmit_data:
	mov rcx, r11
	cmp rcx, FALKTP_DATA_SIZE
	jbe short .dont_cap_data
	mov rcx, FALKTP_DATA_SIZE
.dont_cap_data:
	mov rdx, rcx

	lea rdi, [rsp + falktp_data.data]
	mov rsi, r10
	rep movsb

	mov  rbx, rsp
	mov  rcx, falktp_data_size
	call x540_send_packet

	inc qword [rsp + falktp_data.seq_id]
	add r10, rdx
	sub r11, rdx
	jnz short .transmit_data

.fail:
	add rsp, falktp_data_size
	pop r11
	pop r10
	pop rsi
	pop rdi
	pop rcx
	pop rax
	ret

; r10 -> Vaddr to memory to send
; r11 -> Size to send
falktp_transmit:
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rbp
	push r12
	push r14
	push r15
	XMMPUSH xmm5
	sub  rsp, falktp_data

	;push rdi
	;push rsi
	;mov  rdi, r10
	;mov  rsi, r11
	;call falkhash
	;pop  rsi
	;pop  rdi

.retry:
	; Generate a random request id
	call xorshift64

	mov  dword [rsp + falktp_txmit.magic],  FALKTP_TRANSMIT
	mov  qword [rsp + falktp_txmit.req_id], r15
	mov  qword [rsp + falktp_txmit.size],   r11
	movdqu     [rsp + falktp_txmit.hash],   xmm5
	mov  rbx, rsp
	mov  rcx, falktp_txmit_size
	call x540_send_packet

	; Track how long we've waited for this push so we can timeout
	mov  rax, 5000000
	call rdtsc_future
	mov  rdx, rax
	mov  r12, 50000

	jmp .init_push

.wait_for_push:
	call x540_rx_advance
.init_push:
	; Check if there was a timeout
	call rdtsc64
	cmp  rax, rdx
	jb   short .no_timeout

	; If we timed out 100 times, retry the entire file from the start
	cmp r12, 100
	jae short .retry

	; Otherwise, send a falktp_data_done
	mov  dword [rsp + falktp_data_done.magic],    FALKTP_DATA_DONE
	mov  qword [rsp + falktp_data_done.req_id],   r15
	mov  qword [rsp + falktp_data_done.chunk_id], r14
	mov  rbx, rsp
	mov  rcx, falktp_data_done_size
	call x540_send_packet

	; Update the timeout
	mov  rax, 10000
	call rdtsc_future
	mov  rdx, rax

	; Increment the number of timeouts
	inc r12

.no_timeout:
	call x540_probe_rx_udp

	test rsi, rsi
	jz   short .init_push

	cmp rbp, falktp_chunk_req_size
	jne short .wait_for_push

	cmp dword [rsi + falktp_chunk_req.magic], FALKTP_CHUNK_REQ
	jne short .wait_for_push

	cmp qword [rsi + falktp_chunk_req.req_id], r15
	jne short .wait_for_push

	mov  rdx, [rsi + falktp_chunk_req.chunk_id]
	mov  r14, [rsi + falktp_chunk_req.chunk_id]
	call x540_rx_advance

	; Special case. If the chunk_id was leet, transfer was successful!
	mov r12, 0x1337133713371337
	cmp r12, rdx
	je  .done

	call handle_chunk_req

	; Update the timeout
	xor  r12, r12
	mov  rax, 10000
	call rdtsc_future
	mov  rdx, rax
	jmp  .init_push

.done:
	add rsp, falktp_data
	XMMPOP xmm5
	pop r15
	pop r14
	pop r12
	pop rbp
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

struc zfalktp_push
	.magic:    resq 1 ; 0x00
	.req_id:   resq 1 ; 0x08
	.file_len: resq 1 ; 0x10
	.padding:  resq 1
	.hash:     resq 2
endstruc

struc zfalktp_dat
	.magic:     resq 1 ; 0x00
	.req_id:    resq 1 ; 0x08
	.data:      resb 8192 ; 0x18
endstruc

; r10 - Snapshot
; r11 - Snapshot length
falktp_send:
	push rax
	push rbx
	push rcx
	push rdx
	push rdi
	push r8
	push r11
	push r12
	push r13
	push r14
	push r15

	XMMPUSH xmm5

	sub rsp, zfalktp_dat_size

	;mov rdi, r10
	;mov rsi, r11
	;call falkhash

	test r11, r11
	jz   .done

	call xorshift64
	mov qword [rsp + zfalktp_push.magic],    0x1A8FA024
	mov qword [rsp + zfalktp_push.req_id],   r15
	mov qword [rsp + zfalktp_push.file_len], r11
	
	mov  rbx, rsp
	mov  rcx, zfalktp_push_size
	call x540_send_packet

	xor r8, r8 ; sent
.lewp:
	cmp r8, r11
	jae .done

	; r14 = length - sent
	mov   r12, 8192
	mov   r14, r11
	sub   r14, r8
	cmp   r14, r12
	cmova r14, r12

	mov qword [rsp + zfalktp_dat.magic],  0x1E004AFA
	mov qword [rsp + zfalktp_dat.req_id], r15

	lea rdi, [rsp + zfalktp_dat.data]
	lea rsi, [r10 + r8]
	mov rcx, r14
	rep movsb

	mov  rbx, rsp
	lea  rcx, [r14 + zfalktp_dat.data]
	call x540_send_packet

	; Target ~390MB/s
	mov  ecx, 20
	call rdtsc_sleep

	add r8, r14
	jmp .lewp

.done:
	add rsp, zfalktp_dat_size
	XMMPOP xmm5
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r8
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; r13 -> File ID to request
; rsi <- Pointer to file data
; rbp <- Size of file in bytes
falktp_pull:
	push rax
	push rbx
	push rcx
	push rdx
	push rdi
	push r8
	push r11
	push r12
	push r13
	push r14
	push r15

	XMMPUSH xmm5
	XMMPUSH xmm7

	sub rsp, 4096

	; This is where we store the allocation. If we retry, we don't realloacte.
	xor r11, r11

.retry:
	call xorshift64

	; Send the request
	mov  dword [rsp + falktp_req.magic],   FALKTP_REQ
	mov  qword [rsp + falktp_req.req_id],  r15
	mov  qword [rsp + falktp_req.file_id], r13
	mov  rbx, rsp
	mov  rcx, falktp_req_size
	call x540_send_packet

	; Track how long we've waited for this push so we can timeout
	call rdtsc_uptime
	mov  rdx, rax

	jmp .init_push

.wait_for_push:
	call x540_rx_advance
.init_push:
	call rdtsc_uptime
	sub  rax, rdx
	cmp  rax, 30000000
	jge  short .retry

	call x540_probe_rx_udp

	test rsi, rsi
	jz   short .init_push

	cmp rbp, falktp_push_size
	jne short .wait_for_push

	cmp dword [rsi + falktp_push.magic], FALKTP_PUSH
	jne short .wait_for_push
	
	cmp qword [rsi + falktp_push.req_id], r15
	jne short .wait_for_push

	mov  r14, qword [rsi + falktp_push.file_len]
	test r14, r14
	jz   .wait_for_push

	movdqu xmm7, [rsi + falktp_push.hash]

	; We're done with this packet now
	call x540_rx_advance

	; Round up an integer division to determine the number of chunks we need
	xor rdx, rdx
	lea rax, [r14 + (FALKTP_DATA_SIZE - 1)]
	mov rcx, FALKTP_DATA_SIZE
	div rcx
	mov  r8, rax

	test r11, r11
	jnz  short .dont_realloc

	imul rbx, rax, FALKTP_DATA_SIZE
	bt   r13, 63
	jc   short .not_mixed
	mixed_alloc rbx
	jmp short .alloc_dec
.not_mixed:
	bamp_alloc rbx
.alloc_dec:
	mov  r11, rbx
.dont_realloc:
	mov  rbx, r11

	; Track how long we've waited for this chunk so we can timeout
	mov  rax, 5000000
	call rdtsc_future
	mov  rdx, rax

	; At this point rbx points to the destination for the recieved data
	; rax is the size of the file in chunks
	; r8  is the number of remaining chunks
	; r14 is the size of the file in bytes
	jmp .init_chunk

.wait_for_chunks:
	call x540_rx_advance
.init_chunk:
	; Timeout after 5 seconds
	call rdtsc64
	cmp  rax, rdx
	jge  .retry

	call x540_probe_rx_udp

	test rsi, rsi
	jz   short .init_chunk

	cmp rbp, falktp_dat_size
	jne short .wait_for_chunks

	cmp dword [rsi + falktp_dat.magic], FALKTP_DAT
	jne short .wait_for_chunks
	
	cmp qword [rsi + falktp_dat.req_id], r15
	jne short .wait_for_chunks

	mov  rax, 5000000
	call rdtsc_future
	mov  rdx, rax

	; Bounds check the sequence ID
	cmp qword [rsi + falktp_dat.seq_id], rax
	jae short .wait_for_chunks

	imul rdi, qword [rsi + falktp_dat.seq_id], FALKTP_DATA_SIZE
	add  rdi, rbx
	add  rsi, falktp_dat.data
	mov  rcx, (FALKTP_DATA_SIZE / 8)
	rep  movsq

	; We're done with the packet
	call x540_rx_advance

	dec r8
	jnz short .init_chunk
	
%ifdef FALKTP_USE_HASHES
	; Make sure the hashe	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r8
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop raxs match
	mov   rdi, rbx
	mov   rsi, r14
	call  falkhash
	pxor  xmm5, xmm7
	ptest xmm5, xmm5
	jnz   .retry
%endif

	mov rsi, rbx
	mov rbp, r14

.end:
	add rsp, 4096

	XMMPOP xmm7
	XMMPOP xmm5

	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r8
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; rcx -> buffer
; rdx -> length (in bytes)
; eax <- crc32c (polynomial 0x11EDC6F41)
crc32c:
	push rcx
	push rdx

	mov eax, -1

	; Calculate the CRC32 in chunks of 8 bytes at a time
.lewp_chunk:
	; If we have fewer than 8 bytes left, try to process the rest individually
	cmp rdx, 8
	jb  short .individual

	; Generate the CRC32 on an 8 byte chunk, try again!
	crc32 rax, qword [rcx]
	add   rcx, 8
	sub   rdx, 8
	jmp   short .lewp_chunk

.individual:
	test rdx, rdx
	jz   short .end

	; Finish the CRC32 byte by byte
.lewp:
	crc32 rax, byte [rcx]
	inc   rcx
	dec   rdx
	jnz   short .lewp

.end:
	; Done!
	xor eax, -1

	pop rdx
	pop rcx
	ret

; A chunk_size of 0x50 is ideal for AMD fam 15h platforms, which is what this
; was optimized and designed for. If you change this value, you have to
; manually add/remove movdqus and aesencs from the core loop.
%define FALKHASH_CHUNK_SIZE 0x50

; rdi  -> data
; rsi  -> len
; xmm5 <- 128-bit hash
falkhash:
	push rax
	push rcx
	push rdi
	push rsi
	push rbp

	XMMPUSH xmm0
	XMMPUSH xmm1
	XMMPUSH xmm2
	XMMPUSH xmm3
	XMMPUSH xmm4

	sub  rsp, FALKHASH_CHUNK_SIZE

	; Add the seed to the length
	mov rbp, rsi
	add rbp, 0x13371337

	; Place the length+seed for both the low and high 64-bits into xmm5,
	; our hash output.
	pinsrq xmm5, rbp, 0
	inc rbp
	pinsrq xmm5, rbp, 1

.lewp:
	; If we have less than a chunk, copy the partial chunk to the stack.
	cmp rsi, FALKHASH_CHUNK_SIZE
	jb  short .pad_last_chunk

.continue:
	; Read 5 pieces from memory into xmms
	movdqu xmm0, [rdi + 0x00]
	movdqu xmm1, [rdi + 0x10]
	movdqu xmm2, [rdi + 0x20]
	movdqu xmm3, [rdi + 0x30]
	movdqu xmm4, [rdi + 0x40]

	; Mix all pieces into xmm0
	aesenc xmm0, xmm1
	aesenc xmm0, xmm2
	aesenc xmm0, xmm3
	aesenc xmm0, xmm4

	; Finalize xmm0 by mixing with itself
	aesenc xmm0, xmm0

	; Mix in xmm0 to the hash
	aesenc xmm5, xmm0

	; Go to the next chunk, fall through if we're done.
	add rdi, FALKHASH_CHUNK_SIZE
	sub rsi, FALKHASH_CHUNK_SIZE
	jnz short .lewp
	jmp short .done

.pad_last_chunk:
	; Fill the stack with 0xff's, this is our padding
	push rdi
	lea  rdi, [rsp + 8]
	mov  eax, -1
	mov  ecx, FALKHASH_CHUNK_SIZE
	rep  stosb
	pop  rdi

	; Copy the remainder of data to the stack
	mov rcx, rsi
	mov rsi, rdi
	mov rdi, rsp
	rep movsb

	; Make our data now come from the stack, and set the size to one chunk.
	mov rdi, rsp
	mov rsi, FALKHASH_CHUNK_SIZE

	jmp short .continue

.done:
	; Finalize the hash. This is required at least once to pass
	; Combination 0x8000000 and Combination 0x0000001. Need more than 1 to
	; pass the Seed tests. We do 4 because they're pretty much free.
	; Maybe we should actually use the seed better? Nah, more finalizing!
	aesenc xmm5, xmm5
	aesenc xmm5, xmm5
	aesenc xmm5, xmm5
	aesenc xmm5, xmm5

	add rsp, FALKHASH_CHUNK_SIZE

	XMMPOP xmm4
	XMMPOP xmm3
	XMMPOP xmm2
	XMMPOP xmm1
	XMMPOP xmm0

	pop rbp
	pop rsi
	pop rdi
	pop rcx
	pop rax
	ret

