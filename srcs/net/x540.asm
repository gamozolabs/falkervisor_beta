[bits 64]

%define X540_BASE_PORT 1400

; x540_fetch_pci
;
; Summary:
;
; This function enumerates all PCI devices and returns the PCI request needed
; for the first device encountered with VID 8086 and DID 1528
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
; on Success: rax = PCI request on success
; on Failure: rax = 0
;
; Smashes:
;
; rax - Return value
;
; Optimization:
;
; Readability
;
x540_fetch_pci:
	push rbx
	push rdx

	sub rsp, 0x10

	; rsp + 0x00 L2 | Bus number
	; rsp + 0x02 L2 | Device number
	; rsp + 0x04 L2 | Function number

	mov word [rsp + 0x00], 0xFF
.for_bus:
	mov word [rsp + 0x02], 0x1F
.for_device:
	mov word [rsp + 0x04], 0x07
.for_func:
	; Bus
	movzx eax, byte [rsp + 0x00]
	shl   eax, 5

	; Device
	or     al, byte [rsp + 0x02]
	shl   eax, 3

	; Function
	or     al, byte [rsp + 0x04]
	shl   eax, 8

	; Enable bit
	or    eax, 0x80000000

	; Save the bus:device.func query into ebx
	mov   ebx, eax

	; Request the vendor ID and device ID
	mov  dx, 0x0CF8
	out  dx, eax
	mov  dx, 0x0CFC
	in  eax, dx

	; If the vendor ID is 0xFFFF, then this bus:device.func does not exist
	cmp ax, 0xFFFF
	je  short .next_device

	; Query register 0x00, it's the one that contains the VID and DID
	mov eax, ebx
	mov  dx, 0x0CF8
	out  dx, eax
	mov  dx, 0x0CFC
	in  eax, dx

	cmp eax, 0x15288086
	jne short .next_device

	mov eax, ebx
	jmp short .ret

.next_device:
	dec word [rsp + 0x04]
	jns short .for_func

	dec word [rsp + 0x02]
	jns short .for_device

	dec word [rsp + 0x00]
	jns short .for_bus

	xor rax, rax
.ret:
	add rsp, 0x10
	pop rdx
	pop rbx
	ret

x540_init:
	push rax
	push rcx
	push rdx

	call x540_fetch_pci
	test rax, rax
	jz   short .fail

	or  rax, 0x10   ; BAR0
	mov  dx, 0x0CF8
	out  dx, eax
	mov  dx, 0x0CFC
	in  eax, dx
	and eax, ~0xF

	mov qword [fs:globals.x540_mmio_base], rax
	mov edx, eax

	; Disable all interrupts by writing Fs to the Extended Interrupt Mask
	; Clear Register (EIMC)
	mov dword [rdx + 0x0888], 0x7fffffff

	; Do a device reset by setting RST in the CTRL register
	or  dword [rdx + 0x0000], (1 << 26)

	; Wait for the reset to complete by waiting for the RST bit to clear as
	; well as then wait 10ms after the reset is complete. According to
	; documentation this sleep is suggested for a smooth initialization
.wait_for_reset:
	test dword [rdx + 0x0000], (1 << 26)
	jnz  short .wait_for_reset
	mov  ecx, 20000
	call rdtsc_sleep

	; Disable all interrupts by writing Fs to the Extended Interrupt Mask
	; Clear Register (EIMC)
	mov dword [rdx + 0x0888], 0x7fffffff

	; Enable jumbo frames up to 9018 bytes (including CRC)
	bts dword [rdx + 0x4240], 2            ; HLREG0
	mov dword [rdx + 0x4268], (9018 << 16) ; MAXFRS

	; Enable transmit path DMA
	or  dword [rdx + 0x4a80], (1 << 0)

	; Set the RX control register
	; Enable the following:
	; UPE   - Unicast promiscuous enable
	; MPE   - Multicast promiscuous enable
	; BAM   - Accept broadcast packets
	mov dword [rdx + 0x5080], ((1 << 9) | (1 << 8) | (1 << 10))

	; Enable snooping globally to prevent cache incoherency
	or dword [rdx + 0x0018], (1 << 16)

.fail:
	pop rdx
	pop rcx
	pop rax
	ret

%define X540_NUM_RX 1024

x540_init_local_rx:
	push rax
	push rbx
	push rcx
	push rdx
	push rbp
	push r8

	; Calculate the offset for this cores filter.
	imul r8, qword [gs:thread_local.core_id], 0x4

	; Calculate the source and dest port for the filter. Bits 15:0 are the
	; source port, and bits 31:16 are the dest port. Both stored as big endian.
	mov  eax, dword [gs:thread_local.core_id]
	add  eax, X540_BASE_PORT
	xchg  al, ah  ; Byte swap
	mov  ebx, eax
	shl  ebx, 16
	or   ebx, eax ; Or the value in twice shifted 16 so both source and dest
	              ; are filled in.

	mov rdx, qword [fs:globals.x540_mmio_base]
	mov dword [rdx + 0xE000 + r8], 0x9608400a ; Source filter 10.64.8.150
	mov dword [rdx + 0xE200 + r8], 0x9808400a ; Dest   filter 10.64.8.152
	mov dword [rdx + 0xE400 + r8], ebx        ; Source/dest port filter.
	                                          ; Both source and dest are the
	                                          ; core id.

	; Set up which rx queue is associated with this filter.
	mov eax, dword [gs:thread_local.core_id]
	shl eax, 21
	mov [rdx + 0xE800 + r8], eax

	; Filter control:
	; Filter using 4 tuples (source IP, dest IP, dest port, protocol)
	; UDP protocol
	; Highest priority
	; Enable filter
	; Do not use pool field.
	mov dword [rdx + 0xE600 + r8], (1 << 0) | (7 << 2) | (1 << 31) | (1 << 30) | (1 << 27)

	; Calculate the offset for this cores ring descriptors.
	imul r8, qword [gs:thread_local.core_id], 0x40

	; Allocate ring descriptor space
	mov  rcx, (16 * X540_NUM_RX)
	call mm_alloc_contig_phys

	mov qword [gs:thread_local.x540_rx_ring_base], rax

	; rbp - Base address
	; rdx - Base address pointer
	; rcx - Counter
	mov rbp, rax
	mov rdx, rax
	xor rcx, rcx
.setup_rx:
	; Allocate 12k for each RX descriptor
	push rcx
	mov  rcx, (12 * 1024)
	call mm_alloc_contig_phys
	pop  rcx

	mov qword [rdx + 0x00], rax ; Address
	mov qword [rdx + 0x08], 0   ; Status

	add rdx, 16
	inc rcx
	cmp rcx, X540_NUM_RX
	jl  short .setup_rx

	mov rdx, qword [fs:globals.x540_mmio_base]

	; Set up the SRRCTL
	; 10KB buffer size
	; 256 byte header buffer (default)
	; Use legacy descriptor
	; Drop packets when queue is full
	mov dword [rdx + 0x01014 + r8], (10 << 0) | (4 << 8)| (1 << 28)

	; Set up the high and low parts of the address
	mov rax, rbp
	shr rax, 32
	mov dword [rdx + 0x01004 + r8], eax ; RDBAH0
	mov dword [rdx + 0x01000 + r8], ebp ; RDBAL0

	; Set up the length of the recieve ring buffer
	mov dword [rdx + 0x01008 + r8], (X540_NUM_RX * 16) ; RDLEN0

	; Store the current read position
	mov qword [gs:thread_local.x540_rx_head], 0

	; Enable the ring and poll until it becomes enabled
	or  dword [rdx + 0x01028 + r8], (1 << 25)
.lewp:
	bt  dword [rdx + 0x01028 + r8], 25
	jnc short .lewp

	; Bump the tail descriptor
	mov dword [rdx + 0x01018 + r8], (X540_NUM_RX - 1) ; RDT (tail pointer)

	; Enable RX
	mov dword [rdx + 0x3000], (1 << 0)
	
	pop r8
	pop rbp
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; This must be a power of two!
%define X540_NUM_TX 1024

x540_init_local_tx:
	push rax
	push rbx
	push rcx
	push rdx
	push rbp
	push r8

	; Calculate the offset for this cores ring descriptors.
	imul r8, qword [gs:thread_local.core_id], 0x40

	; Allocate ring descriptor space
	mov  rcx, (16 * X540_NUM_TX)
	call mm_alloc_contig_phys

	mov qword [gs:thread_local.x540_tx_ring_base], rax

	; rbp - Base address
	; rdx - Base address pointer
	; rcx - Counter
	mov rbp, rax
	mov rdx, rax
	xor rcx, rcx
.setup_tx:
	push rax

	push rcx
	mov  rcx, (12 * 1024)
	call mm_alloc_contig_phys
	pop  rcx
	
	mov qword [rdx + 0x00], rax ; Address
	mov qword [rdx + 0x08], 0   ; Status
	bts qword [rdx + 0x08], 32  ; Set DD bit in status to signify this is avail
	                            ; for use.

	pop rax

	add rdx, 16
	inc rcx
	cmp rcx, X540_NUM_TX
	jl  short .setup_tx

	mov rdx, qword [fs:globals.x540_mmio_base]

	; Set up the high and low parts of the address
	mov rax, rbp
	shr rax, 32
	mov dword [rdx + 0x6004 + r8], eax ; TDBAH0
	mov dword [rdx + 0x6000 + r8], ebp ; TDBAL0

	; Set up the length of the TX ring buffer
	mov dword [rdx + 0x6008 + r8], (X540_NUM_TX * 16) ; TDLEN0
	
	; Enable transmit queue
	or  dword [rdx + 0x6028 + r8], (1 << 25)

	; Set up the tail pointer
	mov dword [rdx + 0x6018 + r8], 0 ; Tail

	mov qword [gs:thread_local.x540_tx_tail], 0
	mov qword [gs:thread_local.cur_port],     0

	pop r8
	pop rbp
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

struc x540_tx_desc
	.address: resq 1
	.length:  resw 1
	.cso:     resb 1
	.cmd:     resb 1
	.sta:     resb 1
	.css:     resb 1
	.special: resw 1
endstruc

x540_send_packets:
	push rax
	push rbx
	push rcx
	push rdx

	; Calculate the offset for this cores ring descriptors.
	imul rdx, qword [gs:thread_local.core_id], 0x40

	mov rcx, qword [fs:globals.x540_mmio_base]

	mov eax, dword [rcx + 0x6018 + rdx]
	inc eax
	and eax, (X540_NUM_TX - 1)
	mov [rcx + 0x6018 + rdx], eax

	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; This must be initialized before we relocate and after such is read only
; and must be accessed relative
udp_template_10g:
	.eth:
	.dest:  db 0xa0, 0x36, 0x9f, 0x55, 0x00, 0x5e ; worky.fast.gl.lan
	.src:   db 0xa0, 0x36, 0x9f, 0x55, 0x04, 0x00 ; archivey.fast.gl.lan
	.type:  db 0x08, 0x00 ; IP

	.ip:
	.ver:   db 0x45
	.svc:   db 0x00
	.len:   db 0x05, 0xd0 ; 28 + payload_len
	.ident: db 0x0e, 0x5f
	.flags: db 0x00
	.frag:  db 0x00
	.ttl:   db 0x80
	.proto: db 0x11 ; UDP
	.chk:   db 0x00, 0x00
	.srcip:   db 0x0a, 0x40, 0x08, 0x98 ; 10.64.8.152
	.destip:  db 0x0a, 0x40, 0x08, 0x96 ; 10.64.8.150

	.udp:
	.src_port:  db 0x41, 0x00 ; 0x4100
	.dest_port: db 0x41, 0x00 ; 0x4100
	.ulen:      db 0x00, 0x00 ; 8 + payload_len
	.chksum:    db 0x00, 0x00
	.end:

udp_template_10g_len: equ (udp_template_10g.end - udp_template_10g)

; rbx -> Packet (virtual address)
; rcx -> Length
x540_send_packet:
	push rax
	push rbx
	push rcx
	push rdx
	push r14
	push r15

	; Fetch the next available descriptor
	push rbx
	mov  rdx, qword [gs:thread_local.x540_tx_ring_base]
	mov  rbx, 1
	xadd qword [gs:thread_local.x540_tx_tail], rbx
	and  rbx, (X540_NUM_TX - 1)
	shl  rbx, 4

	; Wait for the DD flag to be set, signifying this can be reused.
.lewp:
	test byte [rdx + rbx + x540_tx_desc.sta], 1
	jz   short .lewp

	lea rax, [rdx + rbx]
	pop rbx

	mov r14, rax
	mov r15, [r14]

	; Copy the udp header to the payload
	push rdi
	push rsi
	push rcx
	mov  rcx, udp_template_10g_len
	mov  rdi, r15
	lea  rsi, [rel udp_template_10g]
	rep  movsb
	pop  rcx
	pop  rsi
	pop  rdi

	; Copy the packet to the payload
	push rdi
	push rsi
	push rcx
	lea  rdi, [r15 + udp_template_10g_len]
	mov  rsi, rbx
	rep  movsb
	pop  rcx
	pop  rsi
	pop  rdi

	; Place in this cores port
	mov  eax, X540_BASE_PORT
	xchg  al, ah
	mov  [r15 + (udp_template_10g.dest_port - udp_template_10g)], ax

	; Place in the core ID as the source port so we can track who reported
	; what.
	mov  eax, dword [gs:thread_local.core_id]
	xchg  al, ah
	mov  [r15 + (udp_template_10g.src_port - udp_template_10g)], ax

	mov rdx, rcx ; IP len
	mov rax, rcx ; UDP len

	add  dx, 28
	xchg dl, dh ; byte swap
	mov  [r15 + (udp_template_10g.len - udp_template_10g)], dx

	add  ax, 8
	xchg al, ah ; byte swap
	mov  [r15 + (udp_template_10g.ulen - udp_template_10g)], ax

	call update_ipv4_checksum

	; Update to send the packet, and add the header length
	add rcx, udp_template_10g_len

	mov  word [r14 + x540_tx_desc.length], cx
	mov  byte [r14 + x540_tx_desc.cmd],    ((1 << 3) | 3)
	mov  byte [r14 + x540_tx_desc.sta],    0
	call x540_send_packets

	pop r15
	pop r14
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; rsi <- Packet contents (zero if packet not present)
; rbp <- Packet size
x540_probe_rx_udp:
	push rax
	push rdx

	; Get the rx entry
	mov rdx, qword [gs:thread_local.x540_rx_ring_base]
	mov eax, dword [gs:thread_local.x540_rx_head]
	shl eax, 4

	; Zero out the return value to indicate no packet.
	xor esi, esi

	; Check if there is a packet, if there isn't return immediately
	test dword [rdx + rax + 8 + 4], 1
	jz   short .done

	; Get the packet
	call x540_poll_rx_raw
	call x540_validate_udp
	jnc  short .done

	; We got a packet, but it wasn't a valid UDP packet. Return zero.
	xor esi, esi

	; Discard the packet
	call x540_rx_advance

.done:
	pop rdx
	pop rax
	ret

; rsi -> Pointer to raw packet to validate
; rbp -> Length of raw packet to validate
; rsi <- Pointer to UDP contents
; rbp <- Length of UDP contents
; CF  <- Set if the packet is not a valid UDP packet
x540_validate_udp:
	push rax

	; If this packet is < the size of a UDP packet, 
	sub ebp, udp_template_10g_len
	jb  short .invalid

	; Compute the UDP length
	movzx eax, word [rsi + (udp_template_10g.ulen - udp_template_10g)]
	xchg   al, ah

	; UDP length must be at least 8 bytes
	sub ax, 8
	jb  short .invalid

	; Make sure that the UDP payload length fits in the actual packet length
	cmp ebp, eax
	jb  short .invalid

	; Return the pointer to the packet contents
	add rsi, udp_template_10g_len

	; Return the UDP length - 8 (the actual packet length)
	mov ebp, eax

	clc
	jmp short .end

.invalid:
	stc
.end:
	pop rax
	ret

; Poll until the next valid UDP packet comes in over the network. When it does
; return a pointer to the contents of the UDP packet in rsi, and the length
; in rbp.
;
; rsi <- Pointer to UDP packet contents
; rbp <- Size of UDP packet contents in bytes
x540_poll_rx_udp:
	push rcx

	xor  ecx, ecx
	call x540_poll_rx_int

	pop rcx
	ret

; Poll until the next packet comes in over the network. Return pointer to raw
; packet in rsi and length in rbp.
;
; rsi <- Pointer to raw packet
; rbp <- Size of raw packet in bytes
x540_poll_rx_raw:
	push rcx

	mov  ecx, 1
	call x540_poll_rx_int

	pop rcx
	ret

; rcx -> If zero, poll until first UDP packet. Else poll until first packet.
;        UDP mode - Return first valid UDP packet. rsi points to the UDP
;                   contents and rbp is the length of the contents.
;        Raw mode - Return first packet. rsi points to the raw packet contents,
;                   rbp is the length of the raw packet.
; rsi <- Pointer to packet contents
; rbp <- Packet size in bytes
x540_poll_rx_int:
	push rax
	push rbx
	push rdx

	jmp short .first_try

.try_again:
	; If we're retrying, we need to put the last packet back up for use.
	call x540_rx_advance

.first_try:
	; Get the rx entry
	mov rdx, qword [gs:thread_local.x540_rx_ring_base]
	mov eax, dword [gs:thread_local.x540_rx_head]
	shl eax, 4

.lewp:
	; Wait until a packet is present here by polling the DD bit
	test dword [rdx + rax + 8 + 4], 1
	jz   short .lewp

	; Increment the number of packets this core has received
	inc qword [gs:thread_local.x540_packets_rx]

	mov   rsi, qword [rdx + rax + 0] ; pointer to packet contents
	movzx ebp,  word [rdx + rax + 8] ; packet length

%if 0
	push rdx
	push rdi
	call per_core_screen
	mov  rdx, qword [gs:thread_local.x540_packets_rx]
	call outhexq
	pop  rdi
	pop  rdx
%endif

	; Enable these next few lines to report all rxed packets over the network
	;push rbx
	;push rcx
	;mov  rbx, rsi
	;mov  rcx, rbp
	;call x540_send_packet
	;pop  rcx
	;pop  rbx

	; Check if we're in UDP or raw mode
	test rcx, rcx
	jnz  short .end

	; If we're in UDP mode, check if this is a valid UDP packet. If it is not
	; wait for another packet.
	call x540_validate_udp
	jc   short .try_again

.end:
	pop rdx
	pop rbx
	pop rax
	ret

; Increment the rx head. This will put the last packet we read back up for
; use.
x540_rx_advance:
	push rax
	push rbx
	push rdx

	; Calculate the offset for this cores ring descriptors.
	mov ebx, dword [gs:thread_local.core_id]
	shl ebx, 6

	; Get the rx entry
	mov rdx, qword [gs:thread_local.x540_rx_ring_base]
	mov eax, dword [gs:thread_local.x540_rx_head]
	shl eax, 4

	; Put the packet we just read back up for storage
	mov qword [rdx + rax + 8], 0 ; Clear out the flags and status

	mov eax, dword [gs:thread_local.x540_rx_head]
	mov rdx, qword [fs:globals.x540_mmio_base]
	mov dword [rdx + 0x01018 + rbx], eax ; Tail

	; Update our internal head
	inc eax
	and eax, (X540_NUM_RX - 1)
	mov dword [gs:thread_local.x540_rx_head], eax

	pop rdx
	pop rbx
	pop rax
	ret

