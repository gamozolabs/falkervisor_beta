[bits 64]

; i825xx_fetch_pci
;
; Summary:
;
; This function enumerates all PCI devices and returns the PCI request needed
; for the first device encountered with VID 8086 and DID 100e
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
i825xx_fetch_pci:
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

	cmp eax, 0x10d38086
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

i825xx_init:
	push rax
	push rcx
	push rdx

	call i825xx_fetch_pci
	test rax, rax
	jz   .done

	mov qword [fs:globals.i825xx_dev + i825xx_dev.pcireq], rax

	or  rax, 0x10   ; BAR1
	mov  dx, 0x0CF8
	out  dx, eax
	mov  dx, 0x0CFC
	in  eax, dx
	and eax, ~1

	mov qword [fs:globals.i825xx_dev + i825xx_dev.mmio_base], rax

	; Init procedure according to 82574l docs
	;
	; 1. Disable interrupts
	; 2. Issue global reset and do general config
	; 3. Setup the PHY and link
	; 4. Init the stat counters
	; 5. Enable RX
	; 6. Enable TX
	; 7. Enable interrupts

	; Disable all interrupts by writing all Fs to the Interrupt Mask Clear
	; Register (IMC)
	mov rdx, qword [fs:globals.i825xx_dev + i825xx_dev.mmio_base]
	mov dword [rdx + 0xD8], -1

	; Issue a full reset by setting RST in the CTRL register
	mov rdx, qword [fs:globals.i825xx_dev + i825xx_dev.mmio_base]
	or  dword [rdx + 0x00], (1 << 26)

	; Disable all interrupts by writing all Fs to the Interrupt Mask Clear
	; Register (IMC)
	mov rdx, qword [fs:globals.i825xx_dev + i825xx_dev.mmio_base]
	mov dword [rdx + 0xD8], -1

	; If we're not using XOFF flow control, zero FCAH, FCAL, and FCT
	mov rdx, qword [fs:globals.i825xx_dev + i825xx_dev.mmio_base]
	mov dword [rdx + 0x002C], 0         ; FCAH
	mov dword [rdx + 0x0028], 0         ; FCAL
	mov dword [rdx + 0x0030], 0         ; FCT
	or  dword [rdx + 0x5B00], (1 << 22) ; GCR bit 22 should be set

	; Enable the MAC and PHY to be all auto negotiated/resolved
	; Set CTRL.FRCDPLX = 0b, CTRL.FRCSPD = 0b, CTRL.ASDE = 0b, CTRL.SLU = 1b,
	; CTRL.RFCE = 1b, CTRL.TFCE = 1b
	mov rdx, qword [fs:globals.i825xx_dev + i825xx_dev.mmio_base]
	and dword [rdx + 0x00], ~((1 << 12) | (1 << 11) | (1 <<  5))
	or  dword [rdx + 0x00],  ((1 <<  6) | (1 << 27) | (1 << 28))

	; Zero out all MTA entries
	xor rcx, rcx
	mov rdx, qword [fs:globals.i825xx_dev + i825xx_dev.mmio_base]
.zero_mta:
	mov dword [rdx + 0x5200 + rcx*4], 0
	inc rcx
	cmp rcx, 128
	jl  short .zero_mta

	call i825xx_init_rx
	call i825xx_init_tx

	mov rdx, qword [fs:globals.i825xx_dev + i825xx_dev.mmio_base]
	mov dword [rdx + 0x14], (0 << 2) | 1
.wait_for_done:
	bt  dword [rdx + 0x14], 1
	jnc .wait_for_done
	mov eax, dword [rdx + 0x14]
	shr eax, 16
	mov word [fs:globals.hw_mac_address + 0], ax
	mov rdx, qword [fs:globals.i825xx_dev + i825xx_dev.mmio_base]
	mov dword [rdx + 0x14], (1 << 2) | 1
.wait_for_done1:
	bt  dword [rdx + 0x14], 1
	jnc .wait_for_done1
	mov eax, dword [rdx + 0x14]
	shr eax, 16
	mov word [fs:globals.hw_mac_address + 2], ax
	mov rdx, qword [fs:globals.i825xx_dev + i825xx_dev.mmio_base]
	mov dword [rdx + 0x14], (2 << 2) | 1
.wait_for_done2:
	bt  dword [rdx + 0x14], 1
	jnc .wait_for_done2
	mov eax, dword [rdx + 0x14]
	shr eax, 16
	mov word [fs:globals.hw_mac_address + 4], ax

.done:
	pop rdx
	pop rcx
	pop rax
	ret

%define I825XX_NUM_RX 512

i825xx_init_rx:
	push rax
	push rbx
	push rcx
	push rdx
	push rbp

	; Allocate ring descriptor space
	mov rbx, (16 * I825XX_NUM_RX)
	bamp_alloc rbx
	call bamp_get_phys

	mov qword [fs:globals.i825xx_dev + i825xx_dev.rx_ring_base], rax

	; rbp - Base address
	; rdx - Base address pointer
	; rcx - Counter
	mov rbp, rax
	mov rdx, rax
	xor rcx, rcx
.setup_rx:
	; Allocate 8k for each RX descriptor
	mov rbx, (8192 + 16)
	bamp_alloc rbx
	call bamp_get_phys

	mov qword [rdx + 0x00], rax ; Address
	mov qword [rdx + 0x08], 0   ; Status

	add rdx, 16
	inc rcx
	cmp rcx, I825XX_NUM_RX
	jl  short .setup_rx

	mov rdx, qword [fs:globals.i825xx_dev + i825xx_dev.mmio_base]

	; Set up the high and low parts of the address
	mov rax, rbp
	shr rax, 32
	mov dword [rdx + 0x02804], eax ; RDBAH0
	mov dword [rdx + 0x02800], ebp ; RDBAL0

	; Set up the length of the recieve ring buffer
	mov dword [rdx + 0x02808], (I825XX_NUM_RX * 16) ; RDLEN0

	; Set up the head and tail pointers
	mov dword [rdx + 0x02810], 0                   ; Head
	mov dword [rdx + 0x02818], (I825XX_NUM_RX - 1) ; Tail

	; Store the current read position
	mov qword [fs:globals.i825xx_dev + i825xx_dev.rx_tail], 0

	; Set the RX control register
	; Enable the following:
	; SBP   - Store bad packets (store packets with CRC errors)
	; UPE   - Unicast promiscuous enable
	; MPE   - Multicast promiscuous enable
	; LPE   - Long packet enable
	; BAM   - Accept broadcast packets
	; BSIZE - Set packet size to 8k
	; BSEX  - Needed to get packet size to 8k
	; SECRC - Strip ethernet CRC from packets
	; EN    - Enable RX!
	mov dword [rdx + 0x100], ((1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 15) | (2 << 16) | (1 << 25) | (1 << 26) | (1 << 1))
	
	pop rbp
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; This must be a power of two!
%define I825XX_NUM_TX 512

i825xx_init_tx:
	push rax
	push rbx
	push rcx
	push rdx
	push rbp

	; Allocate ring descriptor space
	mov rbx, (16 * I825XX_NUM_TX)
	bamp_alloc rbx
	call bamp_get_phys

	mov qword [fs:globals.i825xx_dev + i825xx_dev.tx_ring_base], rax

	; rbp - Base address
	; rdx - Base address pointer
	; rcx - Counter
	mov rbp, rax
	mov rdx, rax
	xor rcx, rcx
.setup_tx:
	push rax

	mov rbx, 8192
	bamp_alloc rbx
	call bamp_get_phys
	
	mov qword [rdx + 0x00], rax ; Address
	mov qword [rdx + 0x08], 0   ; Status
	bts qword [rdx + 0x08], 32  ; Set DD bit in status to signify this is avail
	                            ; for use.

	pop rax

	add rdx, 16
	inc rcx
	cmp rcx, I825XX_NUM_TX
	jl  short .setup_tx

	mov rdx, qword [fs:globals.i825xx_dev + i825xx_dev.mmio_base]

	; Set up the high and low parts of the address
	mov rax, rbp
	shr rax, 32
	mov dword [rdx + 0x03804], eax ; TDBAH0
	mov dword [rdx + 0x03800], ebp ; TDBAL0

	; Set up the length of the TX ring buffer
	mov dword [rdx + 0x03808], (I825XX_NUM_TX * 16) ; TDLEN0

	; Set up the head and tail pointers
	mov dword [rdx + 0x03810], 0 ; Head
	mov dword [rdx + 0x03818], 0 ; Tail

	; Enable the device and also pad short packets
	mov dword [rdx + 0x400], ((1 << 1) | (1 << 3))

	mov qword [fs:globals.i825xx_dev + i825xx_dev.tx_tail], 0

	pop rbp
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

struc i825xx_tx_desc
	.address: resq 1
	.length:  resw 1
	.cso:     resb 1
	.cmd:     resb 1
	.sta:     resb 1
	.css:     resb 1
	.special: resw 1
endstruc

; This must be initialized before we relocate and after such is read only
; and must be accessed relative
udp_template:
	.eth:
	.dest:  db 0x2c, 0x41, 0x38, 0xa2, 0x6c, 0xf5
	.src:   db 0x00, 0x1b, 0x21, 0x34, 0x02, 0x19
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
	.srcip:   db 0xc0, 0xa8, 0x08, 0x08 ; 192.168.8.8
	.destip:  db 0xc0, 0xa8, 0x08, 0x01 ; 192.168.8.1

	.udp:
	.src_port:  db 0x41, 0x00 ; 0x41
	.dest_port: db 0x41, 0x00 ; 0x41
	.ulen:      db 0x00, 0x00 ; 8 + payload_len
	.chksum:    db 0x00, 0x00
	.end:

udp_template_len: equ (udp_template.end - udp_template)

; r15 -> Packet
update_ipv4_checksum:
	push rax
	push rbx
	push rcx
	push rdx
	push r15

	; Zero out the checksum for calculation
	mov word [r15 + (udp_template.chk - udp_template)], 0
	
	lea rbx, [r15 + (udp_template.ip - udp_template)]
	mov rcx, 20
	xor rax, rax

.lewp:
	movzx rdx, word [rbx]
	xchg   dh, dl
	add   rax, rdx

	add rbx, 2
	sub rcx, 2
	jnz short .lewp

	mov rdx, rax
	shr rdx, 16
	add rax, rdx
	not rax

	xchg al, ah
	mov  word [r15 + (udp_template.chk - udp_template)], ax

	pop r15
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

i825xx_tx_acquire_spinlock:
	push rbx

	; Acquire a lock
	mov  rbx, 1
	lock xadd qword [fs:globals.i825xx_tx_lock], rbx

	; Spin until we're the chosen one
.spin:
	cmp rbx, qword [fs:globals.i825xx_tx_release]
	jne short .spin

	pop rbx
	ret

i825xx_tx_release_spinlock:
	; Release the lock
	inc qword [fs:globals.i825xx_tx_release]

	ret

i825xx_send_packets:
	push rax
	push rbx
	push rcx
	push rdx

	mov rdx, qword [fs:globals.i825xx_dev + i825xx_dev.tx_ring_base]
	mov rcx, qword [fs:globals.i825xx_dev + i825xx_dev.mmio_base]

	call i825xx_tx_acquire_spinlock

	mov eax, dword [rcx + 0x03818]
.lewp:
	; Check if this packet has DD set to 0, if so, send it
	mov  ebx, eax
	shl  ebx, 4
	test byte [rdx + rbx + i825xx_tx_desc.sta], 1
	jnz  short .done

	; Update tail pointer
	add eax, 1
	and eax, (I825XX_NUM_TX - 1)
	jmp .lewp

.done:
	mov dword [rcx + 0x03818], eax

	call i825xx_tx_release_spinlock
	pop  rdx
	pop  rcx
	pop  rbx
	pop  rax
	ret

; rax <- Pointer to descriptor
i825xx_get_tx_descriptor:
	push rbx
	push rdx

	; Fetch the next available descriptor
	mov  rdx, qword [fs:globals.i825xx_dev + i825xx_dev.tx_ring_base]
	mov  rbx, 1
	lock xadd qword [fs:globals.i825xx_dev + i825xx_dev.tx_tail], rbx
	and  rbx, (I825XX_NUM_TX - 1)
	shl  rbx, 4

	; Due to the size of the ring being larger than the number of cores, we
	; do not need to have a lock on descriptors at this point.

	; Wait for the DD flag to be set, signifying this can be reused.
.lewp:
	pause
	test byte [rdx + rbx + i825xx_tx_desc.sta], 1
	jz   short .lewp

	lea rax, [rdx + rbx]

	pop rdx
	pop rbx
	ret

; rbx -> Packet (virtual address)
; rcx -> Length
i825xx_send_packet:
	push rax
	push rbx
	push rcx
	push rdx
	push r14
	push r15

	call i825xx_get_tx_descriptor
	mov  r14, rax
	mov  r15, [r14]

	; Copy the udp header to the payload
	push rdi
	push rsi
	push rcx
	mov  rcx, udp_template_len
	mov  rdi, r15
	lea  rsi, [rel udp_template]
	rep  movsb
	pop  rcx
	pop  rsi
	pop  rdi

	; Copy the packet to the payload
	push rdi
	push rsi
	push rcx
	lea  rdi, [r15 + udp_template_len]
	mov  rsi, rbx
	rep  movsb
	pop  rcx
	pop  rsi
	pop  rdi

	mov rdx, rcx ; IP len
	mov rax, rcx ; UDP len

	add  dx, 28
	xchg dl, dh ; byte swap
	mov  [r15 + (udp_template.len - udp_template)], dx

	add  ax, 8
	xchg al, ah ; byte swap
	mov  [r15 + (udp_template.ulen - udp_template)], ax

	call update_ipv4_checksum

	; Update to send the packet, and add the header length
	add rcx, udp_template_len

	mov  word [r14 + i825xx_tx_desc.length], cx
	mov  byte [r14 + i825xx_tx_desc.cmd],    ((1 << 3) | 3)
	mov  byte [r14 + i825xx_tx_desc.sta],    0
	call i825xx_send_packets

	pop r15
	pop r14
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

i825xx_init_thread_local:
	push rbx
	push rcx
	push rdi
	push rsi

	; Update the template src and dest
	mov edx, dword [fs:globals.hw_mac_address]
	mov dword [rel udp_template.src], edx
	mov  dx,  word [fs:globals.hw_mac_address + 4]
	mov  word [rel udp_template.src + 4],   dx
	mov  word [rel udp_template.srcip + 2], dx

	pop rsi
	pop rdi
	pop rcx
	pop rbx
	ret

; rbx <- Buffer to read into (must be 4k)
i825xx_poll_rx:
	push rax
	push rbx
	push rcx
	push rdx
	push r15

	mov r15, rbx

	; Only one thread at a time here. Don't block if you don't get through
	mov  rax, 1
	lock xadd qword [fs:globals.i825xx_rx_poll_lock], rax
	test rax, rax
	jnz  .end

	; Get the rx entry
	mov rax, qword [fs:globals.i825xx_dev + i825xx_dev.rx_tail]
	mov rdx, qword [fs:globals.i825xx_dev + i825xx_dev.rx_ring_base]
	shl rax, 4
	mov rbx, qword [rdx + rax + 0] ; pointer

.lewp:
	mov rcx, qword [rdx + rax + 8] ; flags/status

	; Wait until a packet is present here
	bt  rcx, 32
	jnc short .lewp

	and rcx, 0xFFFF

	; rbx now holds the rxed packet
	; rcx holds the length

	inc qword [fs:globals.i825xx_dev + i825xx_dev.rxed_count]

	mov rcx, 0x1E15BAC81612B164
	cmp qword [rbx + udp_template_len], rcx
	jne short .dont_reboot

	mov al, 0xFE
	mov dx, 0x64
	out dx, al

.dont_reboot:

	; Copy the recieved packet to the caller provided buffer
	push rdi
	push rsi
	push rcx
	mov  rdi, r15
	mov  rsi, rbx
	mov  rcx, (2048 / 8)
	rep  movsq
	pop  rcx
	pop  rsi
	pop  rdi

.next_packet:
	; Update our internal head
	inc qword [fs:globals.i825xx_dev + i825xx_dev.rx_tail]
	and qword [fs:globals.i825xx_dev + i825xx_dev.rx_tail], (512 - 1)

	; Put the packet we just read back up for storage
	mov qword [rdx + rax + 8], 0 ; Clear out the flags and status

	mov eax, dword [fs:globals.i825xx_dev + i825xx_dev.rx_tail]

	mov rdx, qword [fs:globals.i825xx_dev + i825xx_dev.mmio_base]
	mov dword [rdx + 0x02818], eax ; Tail

.end:
	lock dec qword [fs:globals.i825xx_rx_poll_lock]
	pop  r15
	pop  rdx
	pop  rcx
	pop  rbx
	pop  rax
	ret

