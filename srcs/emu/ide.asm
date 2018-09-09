[bits 64]

struc ide_emu_state
	.length:   resq 0 ; in sectors
	.sector:   resq 0
	.cylinder: resq 0
endstruc

ide_handle:
	; out handler, in handler
	dq ide_unhandled, ide_unhandled ; 0x1f0
	dq ide_handled,   ide_unhandled ; 0x1f1
	dq ide_1f2_out,   ide_unhandled ; 0x1f2
	dq ide_1f3_out,   ide_unhandled ; 0x1f3
	dq ide_1f4_out,   ide_unhandled ; 0x1f4
	dq ide_1f5_out,   ide_unhandled ; 0x1f5
	dq ide_1f6_out,   ide_unhandled ; 0x1f6
	dq ide_1f7_out,   ide_1f7_in    ; 0x1f7

ide_1f7_out:
	push r10

	mov r10, (1 << 31) | (0 << 8) | 0x71
	mov qword [rax + VMCB.eventinj], r10

	pop r10
	clc
	ret

ide_1f7_in:
	push rbx

	; We require that this is an 8-bit operand
	; Since we know this is not a string, rep, or imm operation. We know for
	; sure this operation is an: 'out dx, al' and nothing else!!!
	bt  dword [rax + VMCB.exitinfo1], 4
	jnc .unhandled

	; Status byte (RDY and DRQ bits set)
	mov byte [rax + VMCB.rax], (1 << 6) | (1 << 3)

	clc
	pop rbx
	ret

.unhandled:
	stc
	pop rbx
	ret

ide_1f2_out:
	push rbx

	; We require that this is an 8-bit operand
	; Since we know this is not a string, rep, or imm operation. We know for
	; sure this operation is an: 'out dx, al' and nothing else!!!
	bt  dword [rax + VMCB.exitinfo1], 4
	jnc .unhandled

	; Sector count
	movzx ebx, byte [rax + VMCB.rax]
	mov   qword [gs:thread_local.ide_emu_state + ide_emu_state.length], rbx

	clc
	pop rbx
	ret

.unhandled:
	stc
	pop rbx
	ret

ide_1f3_out:
	push rbx

	; We require that this is an 8-bit operand
	; Since we know this is not a string, rep, or imm operation. We know for
	; sure this operation is an: 'out dx, al' and nothing else!!!
	bt  dword [rax + VMCB.exitinfo1], 4
	jnc .unhandled

	; Sector
	movzx ebx, byte [rax + VMCB.rax]
	mov   qword [gs:thread_local.ide_emu_state + ide_emu_state.sector], rbx

	clc
	pop rbx
	ret

.unhandled:
	stc
	pop rbx
	ret

ide_1f4_out:
	push rbx

	; We require that this is an 8-bit operand
	; Since we know this is not a string, rep, or imm operation. We know for
	; sure this operation is an: 'out dx, al' and nothing else!!!
	bt  dword [rax + VMCB.exitinfo1], 4
	jnc .unhandled

	; Low cylinder byte
	movzx ebx, byte [rax + VMCB.rax]
	mov   byte [gs:thread_local.ide_emu_state + ide_emu_state.cylinder], bl

	clc
	pop rbx
	ret

.unhandled:
	stc
	pop rbx
	ret

ide_1f5_out:
	push rbx

	; We require that this is an 8-bit operand
	; Since we know this is not a string, rep, or imm operation. We know for
	; sure this operation is an: 'out dx, al' and nothing else!!!
	bt  dword [rax + VMCB.exitinfo1], 4
	jnc .unhandled

	; High cylinder byte
	movzx ebx, byte [rax + VMCB.rax]
	mov   byte [gs:thread_local.ide_emu_state + ide_emu_state.cylinder + 1], bl

	clc
	pop rbx
	ret

.unhandled:
	stc
	pop rbx
	ret

ide_1f6_out:
	; We require that this is an 8-bit operand
	; Since we know this is not a string, rep, or imm operation. We know for
	; sure this operation is an: 'out dx, al' and nothing else!!!
	bt  dword [rax + VMCB.exitinfo1], 4
	jnc .unhandled

	; Reset state
	mov qword [gs:thread_local.ide_emu_state + ide_emu_state.length],   0
	mov qword [gs:thread_local.ide_emu_state + ide_emu_state.sector],   0
	mov qword [gs:thread_local.ide_emu_state + ide_emu_state.cylinder], 0

	clc
	ret

.unhandled:
	stc
	ret

; rax -> VMCB
; CF  <- Set if access unhandled, clear if handled
ide_io:
	push rbx
	push rcx

	; We currently do not support string accesses or rep accesses
	test dword [rax + VMCB.exitinfo1], (3 << 2)
	jnz  .unhandled

	; Make sure this port is an IDE port
	bextr rbx, qword [rax + VMCB.exitinfo1], 0x1010

	cmp rbx, 0xeff0
	je  .handled
	cmp rbx, 0xeff2
	je  .handled
	cmp rbx, 0xeff4
	je  .handled

	cmp rbx, 0x1f0
	jb  .unhandled
	cmp rbx, 0x1f7
	ja  .unhandled

	; Fetch whether this is an in our out
	mov ecx, dword [rax + VMCB.exitinfo1]
	and ecx, 1
	shl ecx, 3 ; Multiply by 0x8

	; Dispatch this IO access
	sub  rbx, 0x1f0
	shl  rbx, 4 ; Multiply by 0x10
	call [rel ide_handle + rbx + rcx] ; XXX: Can we use rel like this?

	; Might be handled or unhandled, what we call must set/unset CF
	pop rcx
	pop rbx
	ret

.handled:
	clc
	pop rcx
	pop rbx
	ret

.unhandled:
	stc
	pop rcx
	pop rbx
	ret

ide_unhandled:
	stc
	ret

ide_handled:
	clc
	ret

