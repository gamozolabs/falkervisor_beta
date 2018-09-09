[bits 64]

idt_base:
	times (256 * 8) db 0

idt:
	.limit: dw (idt - idt_base) - 1
	.base:  dq idt_base

%define EXCEPT_REPORT_MAGIC 0x215f25d0

struc except_report
	.magic: resd 1
	.vec:   resq 1
	.rsp00: resq 1
	.rsp08: resq 1
	.rsp10: resq 1
	.rsp18: resq 1
	.kern:  resq 1
	.cr2:   resq 1
	.stack: resb 1024
endstruc

; Sends exception reports via the network. Use create_relocated_idt to set up
; your idt to use this.
relocated_handler:
	mov [gs:thread_local.vm_ctxt + vm_ctxt.vec], rax
	pop rbx
	pop rax

	jmp panic

user_handler:
	push rax
	push rdx

	mov dx, 0x20
	mov al, 0x20
	out dx, al

	pop rdx
	pop rax
	iretq

ibs_handler:
	iretq

