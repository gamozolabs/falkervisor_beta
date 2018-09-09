[bits 64]

init_pit:
	push rax

	; Set the PIT mode, timer 0, square wave gen, hex
	mov   al, 0x34
	out 0x43, al

	; Lower bits
	mov   al, 0xFF
	out 0x40, al

	; Upper bits
	mov   al, 0xFF
	out 0x40, al

	pop rax
	ret

; ecx -> Hardware P-state [0, 7] (not checked for validity!)
; rax <- Frequency of the corresponding P-state in MHz
amd_fam15h_hw_freq:
	push rcx
	push rdx

	; Compute the P-state MSR which corresponds to this hardware P-state
	add ecx, 0xc0010064
	rdmsr
	bextr ecx, eax, 0x0306 ; CpuDid, divisor ID
	and   eax, 0x3f        ; CpuFid, frequency multiplier

	; CoreCOF in MHz = ((CpuFid + 0x10) / (2^CpuDid)) * 100

	; Compute CpuFid in MHz
	add  eax, 0x10
	imul rax, 100

	; Divide by CpuDid
	shr rax, cl

	pop rdx
	pop rcx
	ret

; rax <- Current frequency in MHz
amd_fam15h_cur_freq:
	push rcx
	push rdx

	; Get the COFVID status, which contains the current hardware P-state
	mov ecx, 0xc0010071
	rdmsr
	bextr ecx, eax, 0x0310

	call amd_fam15h_hw_freq

	pop rdx
	pop rcx
	ret

; rax <- Software P0 frequency in MHz
amd_fam15h_sw_p0_freq:
	push rcx

	call amd_fam15h_fetch_pcie_mmio

	; Bus 0, Device 18, Function 4
	; Get the number of boost states, this will be the hardware P-state that
	; corresponds to hardware P0
	bextr ecx, [rdx + 0x15c + ((0 << 20) | (0x18 << 15) | (0x4 << 12))], 0x0302

	call amd_fam15h_hw_freq

	pop rcx
	ret

rdtsc64:
	push rdx

	rdtsc
	shl rdx, 32
	or  rax, rdx

	pop rdx
	ret

; We use this function to calculate what the value of rdtsc will be x
; microseconds in the future. This way we don't have to do a rdtsc and div
; by calling rdtsc_uptime, we just rdtsc.
; rax -> Target number of microseconds to wait
; rax <- Value rdtsc will be upon specified milliseconds
rdtsc_future:
	push rcx
	push rdx

	; Get number of cycles in n microseconds
	xor rdx, rdx
	mul qword [fs:globals.rdtsc_freq]
	mov rcx, rax

	; Get current time
	rdtsc
	shl rdx, 32
	or  rdx, rax

	; Add the current time and the delay together
	lea rax, [rcx + rdx]

	pop rdx
	pop rcx
	ret

; rax <- Number of microseconds since rdtsc init
rdtsc_uptime:
	push rdx

	rdtsc
	shl rdx, 32
	or  rax, rdx

	xor rdx, rdx
	div qword [fs:globals.rdtsc_freq]

	pop rdx
	ret

; rcx -> Number of microseconds to sleep
rdtsc_sleep:
	push rax
	push rcx
	push rdx

	; Get number of timestamp ticks that correspeonds to this request
	imul rcx, qword [fs:globals.rdtsc_freq]

	; Get the target timestamp counter that we're done sleeping at
	rdtsc
	shl rdx, 32
	or  rdx, rax
	add rcx, rdx

.wait_rdtsc:
	rdtsc
	shl rdx, 32
	or  rdx, rax
	cmp rdx, rcx
	jb  short .wait_rdtsc

	pop rdx
	pop rcx
	pop rax
	ret

