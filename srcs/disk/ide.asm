[bits 64]

; pci_get_ide
;
; Summary:
;
; This function enumerates all PCI devices and returns the PCI request needed
; for the first IDE device encountered.
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
pci_get_ide:
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

	; Query register 0x08, it's the one that contains the class code and
	; subclass
	mov eax, ebx
	or  eax, 0x08
	mov  dx, 0x0CF8
	out  dx, eax
	mov  dx, 0x0CFC
	in  eax, dx

	; Check if it's an IDE device (class 0x01 subclass 0x01)
	shr eax, 16
	cmp  ax, 0x0101
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

; Channel 1 (primary)
%define IOADDR1_BASE 0x1f0
%define IOADDR2_BASE 0x3f6

; Channel 2 (secondary)
;%define IOADDR1_BASE 0x170
;%define IOADDR2_BASE 0x376

; Channel 3
;%define IOADDR1_BASE 0x1e8
;%define IOADDR2_BASE 0x3e6

; Channel 4
;%define IOADDR1_BASE 0x168
;%define IOADDR2_BASE 0x366

; This is the structure describing the IDE controller
hdd:
	.BAR0: dd 0
	.BAR1: dd 0
	.BAR2: dd 0
	.BAR3: dd 0
	.BAR4: dd 0
	.BAR5: dd 0

	.BUS_MASTER:     dw 0

	.CH0_DATA:       dw IOADDR1_BASE + 0 ; RW Primary
	.CH0_ERROR:      dw IOADDR1_BASE + 1 ; RO Primary
	.CH0_FEATURES:   dw IOADDR1_BASE + 1 ; WO Primary
	.CH0_SECCOUNT0:  dw IOADDR1_BASE + 2 ; RW Primary
	.CH0_SECCOUNT1:  dw IOADDR1_BASE + 2 ; RW Secondary
	.CH0_LBA0:       dw IOADDR1_BASE + 3 ; RW Primary
	.CH0_LBA3:       dw IOADDR1_BASE + 3 ; RW Secondary
	.CH0_LBA1:       dw IOADDR1_BASE + 4 ; RW Primary
	.CH0_LBA4:       dw IOADDR1_BASE + 4 ; RW Secondary
	.CH0_LBA2:       dw IOADDR1_BASE + 5 ; RW Primary
	.CH0_LBA5:       dw IOADDR1_BASE + 5 ; RW Secondary
	.CH0_HDDEVSEL:   dw IOADDR1_BASE + 6 ; RW Primary
	.CH0_COMMAND:    dw IOADDR1_BASE + 7 ; WO Primary
	.CH0_STATUS:     dw IOADDR1_BASE + 7 ; RO Primary

	.CH0_CONTROL:    dw IOADDR2_BASE ; WO
	.CH0_ALTSTATUS:  dw IOADDR2_BASE ; RO
	;.CH0_DEVADDRESS: dw 0x3F9 ; Not supported

	.CH0_MST_IDENTIFY:  times 512 db 0 ; 512-byte identify value
	.CH0_MST_BYTE_SIZE: dq 0           ; Size of the drive in bytes

; ide_wait_busy
;
; Summary:
;
; This function polls the IDE drive and blocks until it is no longer busy.
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
; Optimization:
;
; Readability
;
ide_wait_busy:
	push rax
	push rdx

	mov dx, word [rel hdd.CH0_STATUS]
.busy:
	in   al, dx
	test al, 0x80
	jnz  short .busy

	pop rdx
	pop rax
	ret

; load_hdd
;
; Summary:
;
; This function scans for the first IDE controller out of all the PCI devices
; and then loads the BARs into global struct 'hdd'.
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
; on Success: CF = 0
; on Failure: CF = 1
;
; Smashes:
;
; None
;
; Optimization:
;
; Readability
;
load_hdd:
	push rax
	push rbx
	push rcx
	push rdx

	; Scan PCI devices for an IDE controller
	call pci_get_ide
	test rax, rax
	jz   .fail

	; Cache the PCI request
	mov ebx, eax

	; Get the header type
	or  eax, 0x0C
	mov  dx, 0x0CF8
	out  dx, eax
	mov  dx, 0x0CFC
	in  eax, dx

	; Check if the header type 0x00
	shr eax, 16
	and  al, 0xFF
	jnz short .fail

	; Load BARs 0-5 into the hdd structure
	xor ecx, ecx
.fetch_bars:
	; Calculate the PCI request
	mov eax, ebx
	add eax, 0x10
	add eax, ecx

	; Request BAR[ecx]
	mov  dx, 0x0CF8
	out  dx, eax
	mov  dx, 0x0CFC
	in  eax, dx

	; Store the bar
	lea rbx, [rel hdd.BAR0]
	mov dword [rbx + rcx], eax

	add ecx, 4
	cmp ecx, 0x14
	jle short .fetch_bars

	clc
	jmp short .ret
.fail:
	stc
.ret:
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; init_hdd
;
; Summary:
;
; This function is responsible for finding IDE controllers (via load_hdd),
; populating all elements of global struct 'hdd', and preparing up the IDE
; controller for use. We currently only support the primary IDE controller,
; the secondary one is not used.
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
; on Success: CF = 0
; on Failure: CF = 1
;
; Smashes:
;
; None
;
; Optimization:
;
; Readability
;
init_hdd:
	push rax
	push rcx
	push rdx

	call load_hdd
	jc   .fail

	; Ensure that the primary IDE controller is the one we expect by checking
	; that the BARs are either 0 or 1.
	;cmp dword [rel hdd.BAR0], 0x1
	;ja  .fail
	;cmp dword [rel hdd.BAR1], 0x1
	;ja  .fail

	; Validate and save the bus master IO port
	mov  eax, dword [rel hdd.BAR4]
	test eax, 1
	jz   .fail
	and  eax, 0xFFFFFFFC
	mov  word [rel hdd.BUS_MASTER], ax

	; Disable interrupts on CH0
	mov dx, word [rel hdd.CH0_CONTROL]
	mov al, 2
	out dx, al

	; Select 'master' drive with LBA addressing mode
	mov dx, word [rel hdd.CH0_HDDEVSEL]
	mov al, 0xE0
	out dx, al

	; Send identify command
	mov dx, word [rel hdd.CH0_COMMAND]
	mov al, 0xEC
	out dx, al

	; Wait for the IDE controller to not be busy
	call ide_wait_busy

	; Load the identity data
	push rdi
	lea  rdi, [rel hdd.CH0_MST_IDENTIFY]
	mov   dx, word [rel hdd.CH0_DATA]
	mov  rcx, (512 / 4)
	rep insd
	pop  rdi

	; Ensure the device takes LBA48 addressing
	mov  edx, dword [rel hdd.CH0_MST_IDENTIFY + 164]
	test edx, (1 << 26)
	jz   short .fail

	; Get the size of the drive
	mov edx, dword [rel hdd.CH0_MST_IDENTIFY + 200]
	shl rdx, 9
	mov qword [rel hdd.CH0_MST_BYTE_SIZE], rdx

	clc
	jmp short .ret
.fail:
	stc
.ret:
	pop rdx
	pop rcx
	pop rax
	ret

; ide_pio_read_sectors
;
; Summary:
;
; This function reads cx sectors starting at sector rbx into buffer specified
; by r8. The read is performed on channel 0, master drive.
;
; Parameters:
;
; rbx - Sector to read from
;  cx - Number of sectors to read
;  r8 - Buffer to read into
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
; Optimization:
;
; Readability
;
ide_pio_read_sectors:
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi

	push rcx
	mov  rcx, SPINLOCK_DISK
	call acquire_spinlock
	pop  rcx

	mov dx, word [rel hdd.CH0_HDDEVSEL]
	mov al, 0xE0
	out dx, al

	rol rbx, 24

	; Set the sector counts and the LBA48 address
	mov dx, word [rel hdd.CH0_SECCOUNT1]
	mov al, ch
	out dx, al

	mov dx, word [rel hdd.CH0_LBA5]
	mov al, bl
	out dx, al
	rol rbx, 8

	mov dx, word [rel hdd.CH0_LBA4]
	mov al, bl
	out dx, al
	rol rbx, 8

	mov dx, word [rel hdd.CH0_LBA3]
	mov al, bl
	out dx, al
	rol rbx, 8

	mov dx, word [rel hdd.CH0_SECCOUNT0]
	mov al, cl
	out dx, al

	mov dx, word [rel hdd.CH0_LBA2]
	mov al, bl
	out dx, al
	rol rbx, 8

	mov dx, word [rel hdd.CH0_LBA1]
	mov al, bl
	out dx, al
	rol rbx, 8

	mov dx, word [rel hdd.CH0_LBA0]
	mov al, bl
	out dx, al

	mov dx, word [rel hdd.CH0_COMMAND]
	mov al, 0x24
	out dx, al

	mov rdi, r8
	mov  si, cx
.lewp:
	mov dx, word [rel hdd.CH0_STATUS]
	in  al, dx
	in  al, dx
	in  al, dx
	in  al, dx

	call ide_wait_busy

	mov  dx, word [rel hdd.CH0_STATUS]
	in   al, dx

	; ERR
	test al, 0x01
	jnz  short .err

	; DF
	test al, 0x20
	jnz  short .err

	; !DRQ
	test al, 0x08
	jz   short .err

	mov  dx, word [rel hdd.CH0_DATA]
	mov rcx, (512 / 4)
	rep insd

.continue:
	dec si
	jnz short .lewp

.err:
	push rcx
	mov  rcx, SPINLOCK_DISK
	call release_spinlock
	pop  rcx

	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

.errz:
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax

	mov  rdi, 0xb8000
	mov  rdx, 0x1337133713371337
	call outhexq

	mov  rdi, 0xb8000 + (80 * 2 * 1)
	mov  rdx, rbx
	call outhexq

	mov  rdi, 0xb8000 + (80 * 2 * 2)
	mov  rdx, r8
	call outhexq
	hlt

align 16
prd:
	.buf:   dd DMA_BUFFER_ZONE
	.size:  dw 0x0000
	.flags: dw 0x8000

ide_dma_read_sectors:
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi

	mov rdi, DMA_BUFFER_ZONE
	mov rcx, (64 * 1024)
	mov  al, 0xc0
	rep stosb

	mov dword [rel prd.buf],   DMA_BUFFER_ZONE
	mov  word [rel prd.size],  0
	mov  word [rel prd.flags], 0x8000

	; Set the address of the PRD
	mov   dx, word [rel hdd.BUS_MASTER]
	add   dx, 0x4
	lea  rbx, [rel prd]
	call bamp_get_phys
	out   dx, eax

	; Disable the device, set it to read mode
	mov dx, word [rel hdd.BUS_MASTER]
	mov al, 0x0
	out dx, al

	; Clear the status register
	mov dx, word [rel hdd.BUS_MASTER]
	add dx, 0x2
	mov al, 0x0
	out dx, al

	push rdi
	mov dx, word [rel hdd.BUS_MASTER]
	add dx, 2
	in  al, dx
	mov rdi, 0xb8000
	;movzx rdx, al
	call outhexq
	pop rdi
	cli
	hlt

	; Enable the device
	mov dx, word [rel hdd.BUS_MASTER]
	mov al, 0x1
	out dx, al

	mov cx, 128

	mov dx, word [rel hdd.CH0_HDDEVSEL]
	mov al, 0xE0
	out dx, al

	rol rbx, 24

	; Set the sector counts and the LBA48 address
	;mov dx, word [hdd.CH0_SECCOUNT1]
	;mov al, ch
	;out dx, al

	;mov dx, word [hdd.CH0_LBA5]
	;mov al, bl
	;out dx, al
	rol rbx, 8

	;mov dx, word [hdd.CH0_LBA4]
	;mov al, bl
	;out dx, al
	rol rbx, 8

	;mov dx, word [hdd.CH0_LBA3]
	;mov al, bl
	;out dx, al
	rol rbx, 8

	mov dx, word [rel hdd.CH0_SECCOUNT0]
	mov al, cl
	out dx, al

	mov dx, word [rel hdd.CH0_LBA2]
	mov al, bl
	out dx, al
	rol rbx, 8

	mov dx, word [rel hdd.CH0_LBA1]
	mov al, bl
	out dx, al
	rol rbx, 8

	mov dx, word [rel hdd.CH0_LBA0]
	mov al, bl
	out dx, al

	sti
	mov dx, word [rel hdd.CH0_COMMAND]
	mov al, 0xC8
	out dx, al

	mov rdi, DMA_BUFFER_ZONE
.lewp:
	push rdi
	mov dx, word [rel hdd.BUS_MASTER]
	add dx, 2
	in  al, dx
	mov rdi, 0xb8000
	movzx rdx, al
	call outhexq
	pop rdi

	cmp dword [rdi], 0xc0c0c0c0
	je  short .lewp

	mov dx, word [rel hdd.BUS_MASTER]
	add dx, 2
	in  al, dx

	mov dx, word [rel hdd.BUS_MASTER]
	mov al, 0x00
	out dx, al

	mov rdi, r8
	mov rsi, DMA_BUFFER_ZONE
	mov rcx, (64 * 1024) ; 64kB
	rep movsb

	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; hash_falkquot
;
; Summary:
;
; This function performs the falkquot hashing operation on data in rbx with a
; length of r11.
;
; Parameters:
;
; rbx - Pointer to data to hash
; r11 - Length of data to hash
;
; Alignment:
;
; None
;
; Returns:
;
; rax - Hash
;
; Smashes:
;
; rax - Hash
;
; Optimization:
;
; Readability (with a hint of speed)
;
hash_falkquot:
	push rbx
	push rcx
	push rdx
	push r8
	push r10
	push r11

	mov r10, 0x1337133713371337
.lewp:
	mov al, byte [rbx]
	mov dl, al

	; n
	and al, 0xF
	add al, 17

	; k
	shr dl, 4
	add dl, 13

	mov  r8, r10
	mov  cl, dl
	shl  r8, cl
	xor r10, r8  ; r10 ^= (r10 << k)

	mov  r8, r10
	mov  cl, al
	shr  r8, cl
	xor r10, r8  ; r10 ^= (r10 >> n)

	mov  r8, r10
	shl  r8, 43
	xor r10, r8  ; r10 ^= (r10 << 43)

	inc rbx
	dec r11
	jnz short .lewp

	mov rax, r10

	pop r11
	pop r10
	pop r8
	pop rdx
	pop rcx
	pop rbx
	ret

; read_via_ide_pio
;
; Summary:
;
; This function reads a FALKQUOT filesystem from IDE controller 0 master drive.
; The drive is initialized here as well.
;
; Parameters:
;
; r8 - Buffer to load file into
;
; Alignment:
;
; None
;
; Returns:
;
; on Success: CF = 0 and r11 = number of bytes loaded
; on Failure: CF = 1 and r11 = Smashed
;
; Smashes:
;
; r11 - Return value
;
; Optimization:
;
; Readability
;
read_via_ide_pio:
	push rax
	push rbx
	push rcx
	push rdx
	push r8
	push r10
	push r13

	call init_hdd
	jc   .fail

	; Read the initial sector to get the length of the falkquot
	mov   cx, 0x1
	xor  rbx, rbx
	call ide_pio_read_sectors

	; Validate the signature
	mov r10, r8
	mov r11, 0x544F55514B4C4146 ; 'FALKQUOT'
	cmp qword [r10], r11
	jne .fail

	; Size in bytes of data
	mov r11, qword [r10 + 0x08]
	mov r13, r11
	shr r13, 9
	add r13, 10

	; Read the rest of the sectors we need in 0xFFFF chunks

	; r8  - Pointer to buffer
	; r13 - Number of sectors to read
	; rbx - Sector to read
	; rcx - Number of sectors to read (max of 0xFFFF)
	lea  r8, [r10]
	mov rbx, 0
.lewp:
	; Read in 0xFFFF sector chunks (max that IDE PIO can support)
	mov rcx, 0xFF
	cmp r13, rcx
	jbe short .no_max
	jmp short .read

.no_max:
	mov rcx, r13
.read:
	call ide_pio_read_sectors

	; Add to the sector offset
	add rbx, rcx

	; Calculate number of sectors left to read
	sub r13, rcx

	; Increment our buffer
	shl rcx, 9
	add  r8, rcx

	; Print out the number of sectors remaining
	push rdx
	push rdi
	mov  rdi, 0xb8000 + (80 * 2 * 0)
	mov  rdx, r13
	call outhexq
	pop  rdi
	pop  rdx

	; Continue if we have sectors left
	test r13, r13
	jnz  short .lewp

	; Generate the hash
	lea  rbx, [r10 + 0x18]
	call hash_falkquot

	; Ensure the hash matches
	cmp rax, qword [r10 + 0x10]
	jne short .fail

	clc
	jmp short .ret
.fail:
	stc
.ret:
	pop r13
	pop r10
	pop r8
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; read_via_ide_dma
;
; Summary:
;
; This function reads a FALKQUOT filesystem from IDE controller 0 master drive.
; The drive is initialized here as well.
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
; on Success: CF = 0 and r11 = number of bytes loaded
; on Failure: CF = 1 and r11 = Smashed
;
; Smashes:
;
; r11 - Return value
;
; Optimization:
;
; Readability
;
read_via_ide_dma:
	push rax
	push rbx
	push rdx
	push r8
	push r10
	push r13

	call init_hdd
	jc   .fail

	; Read the initial sector to get the length of the falkquot
	xor  rbx, rbx
	call ide_dma_read_sectors

	; Validate the signature
	mov r10, r8
	mov r11, 0x544F55514B4C4146 ; 'FALKQUOT'
	cmp qword [r10], r11
	jne .fail

	mov  rdx, 0x1234DE
	mov  rdi, 0xb8000 + (80 * 2 * 5)
	call outhexq
	cli
	hlt

	; Size in bytes of data
	mov r11, qword [r10 + 0x08]
	mov r13, r11
	shr r13, 9
	add r13, 10

	; Read the rest of the sectors we need in 0xFFFF chunks

	; r8  - Pointer to buffer
	; r13 - Number of sectors to read
	; rbx - Sector to read
	lea  r8, [r10]
	mov rbx, 0
.lewp:
	mov  cx, 128
	call ide_dma_read_sectors

	; Add to the sector offset
	add rbx, (64 * 1024) / 512

	; Calculate number of sectors left to read
	sub r13, (64 * 1024) / 512

	; Increment our buffer
	add r8, (64 * 1024)

	; Print out the number of sectors remaining
	push rdx
	push rdi
	mov  rdx, r13
	call outhexq
	pop rdi
	pop rdx

	; Continue if we have sectors left
	cmp r13, 0
	jg  short .lewp

	; Generate the hash
	lea  rbx, [r10 + 0x18]
	call hash_falkquot

	; Ensure the hash matches
	cmp rax, qword [r10 + 0x10]
	jne short .fail

	clc
	jmp short .ret
.fail:
	stc
.ret:
	pop r13
	pop r10
	pop r8
	pop rdx
	pop rbx
	pop rax
	ret

