[bits 64]

; -----------------------------------------------------------------------------
; FUZZ CONFIGURATION
; -----------------------------------------------------------------------------

%define FUZZ_STATUS_MAGIC 0xdd1eba7c

%define MAX_COVERAGE 1000000

%define SAFE_CORRUPT 4096

%define ENABLE_LOGGING
%define ENABLE_IBS 50000
%define ENABLE_COVERAGE
%define ENABLE_FUZZING
%define ENABLE_LBR
%define ENABLE_FEEDBACK
;%define ENABLE_INVALIDATE_STACK_ON_TIMERS

%define MIN_FUZZ_SIZE (4 * 1024)

; @ timer of 10000 - 10k   per second
; @ timer of 1000  - 100k  per second
; @ timer of 100   - 1000k per second
%define EXHAUST_COUNT 10000

;%define ENABLE_SERVICING

%define LEAST_COMMON_TRIES 64

; Number of bytes at the start of the RTF to leave alone
%define DONT_CORRUPT_FIRST 64

%define SELECT_FUZZ

; -----------------------------------------------------------------------------
; END FUZZ CONFIGURATION
; -----------------------------------------------------------------------------

; This can be accessed by the FS segment.
struc globals
	.fs_base: resq 1 ; Virtual address of this globals block

	.bamp_addr: resq MAX_NODES
	.bamp_ends: resq MAX_NODES

	.rdtsc_freq: resq 1 ; Frequency that rdtsc increments at in MHz

	.next_free_vaddr: resq 1

	.per_node_kern_code: resb node_struct_size

	.x540_mmio_base: resq 1

	.i825xx_dev:          resb i825xx_dev_size
	.hw_mac_address:      resb 8
	.i825xx_tx_lock:      resq 1
	.i825xx_tx_release:   resq 1
	.i825xx_rx_poll_lock: resq 1

	.heapsort_lock:    resq 1
	.heapsort_release: resq 1

	.falktp_lock:    resq 1
	.falktp_release: resq 1

	.vm_snapshot:  resq 1
	.vms_fuzzing:  resq 1
	.stop_fuzzing: resq 1

	.fuzz_status: resb fuzz_status_size
	
	.per_node_fuzzdat: resb node_struct_size

	.coverage_flut: resq 1
	.input_flut:    resq 1

	.per_node_combinesvg: resb node_struct_size
endstruc

struc fuzz_status
	.magic: resd 1

	.fuzz_cases:    resq 1 ; Number of fuzz cases
	.fuzz_complete: resq 1 ; Number of fuzz cases that ran until ud2
	.fuzz_io:       resq 1 ; Number of fuzz cases ending in MMIO or IO or INTs
	.num_unique_bb: resq 1 ; Number of unique basic blocks
	.num_timers:    resq 1 ; Number of NMI timers which fired in the VM
	.num_crashes:   resq 1 ; Number of crashes

	.time_restore: resq 1 ; Number of clock cycles spent restoring VM state
	.time_corrupt: resq 1 ; Number of clock cycles spent corrupting RTFs
	.time_running: resq 1 ; Number of clock cycles spent running VM
	.time_coverag: resq 1 ; Number of clock cycles spent doing coverage

	.alloc_charge: resq 1 ; Number of bytes allocated

	.pc_fc: resq NUM_CORES ; Per core fuzz cases
endstruc

struc thread_local
	.gs_base: resq 1 ; Virtual address of this thread local block

	.node_id: resq 1 ; Actual node ID that this core resides in
	.core_id: resq 1 ; Unique ID for this core (might not match APIC ID)
	                 ; This ID is from [0, num_cores)

	.x540_tx_ring_base: resq 1 ; Base of the TX ring tail
	.x540_tx_tail:      resq 1 ; Transmit tail
	.cur_port:          resq 1 ; Next port to transmit on. We transmit around
	                           ; a ring to distribute work load.
	.x540_rx_ring_base: resq 1 ; Base of the RX ring tail
	.x540_rx_head:      resq 1 ; RX head. This points to the next packet which
	                           ; we have not processed yet.

	.xs_seed: resq 1

	.phys_4k_freelist: resq 1

	.guest_gs: resq 1
	.guest_fs: resq 1

	.os_state: resq 1
	.cur_samp: resq 1
	.vm_ctxt:  resb vm_ctxt_size

	.ioio:    resq 1
	.vm_ncr3: resq 1

	.exhaust: resq 1

	.time_log: resq 1

	.orig_svg: resq 1
	.orig_svg_len: resq 1

	.time_restore: resq 1 ; Number of clock cycles spent restoring VM state
	.time_corrupt: resq 1 ; Number of clock cycles spent corrupting RTFs
	.time_running: resq 1 ; Number of clock cycles spent running VM
	.time_coverag: resq 1 ; Number of clock cycles spent doing coverage

	.fuzz_size: resq 1 ; File size to use for fuzzing, by providing a large
	                   ; base input template, we can then fuzz various
	                   ; sizes by only corrupting the starting fuzz_size bytes
endstruc

struc vm_ctxt
	.magic: resd 1

	.vec: resq 1
	.ei1: resq 1
	.ei2: resq 1
	.eii: resq 1

	.rax:  resq 1
	.rcx:  resq 1
	.rdx:  resq 1
	.rbx:  resq 1
	.rsp:  resq 1
	.rbp:  resq 1
	.rsi:  resq 1
	.rdi:  resq 1
	.r8 :  resq 1
	.r9 :  resq 1
	.r10:  resq 1
	.r11:  resq 1
	.r12:  resq 1
	.r13:  resq 1
	.r14:  resq 1
	.r15:  resq 1
	.rip:  resq 1
	.rfl:  resq 1

	.cr0: resq 1
	.cr2: resq 1
	.cr3: resq 1
	.cr4: resq 1

	.cid:  resq 1
	.bcrp: resq 1

	.n_cr3: resq 1
endstruc

struc vm_snapshot
	; rax, rsp, rip, rfl stored in vmcb
	.rcx:  resq 1
	.rdx:  resq 1
	.rbx:  resq 1
	.rbp:  resq 1
	.rsi:  resq 1
	.rdi:  resq 1
	.r8 :  resq 1
	.r9 :  resq 1
	.r10:  resq 1
	.r11:  resq 1
	.r12:  resq 1
	.r13:  resq 1
	.r14:  resq 1
	.r15:  resq 1

	; cr0, cr2, cr3, cr4 included in vmcb
	.cr8:  resq 1
	.xcr0: resq 1

	; dr6 and dr7 included in vmcb
	.dr0: resq 1
	.dr1: resq 1
	.dr2: resq 1
	.dr3: resq 1

	alignb 4096
	.xsave: resb 0x3C0 ; This length is processor specific!!! This is designed
	                   ; for AMD fam15h00-0f CPUs

	alignb 4096
	.vmcb:  resb 4096  ; Entire VMCB after the vm exits and a vmsave occurs
	                   ; Things like n_cr3 need to be rebuilt

	alignb 4096
	.physical_memory:
	; This is the raw physical memory backing the VM. The way you rebuild the
	; vm nested page tables and physical memory is as such:
	;
	; ptr = vm_snapshot.physical_memory
	; foreach page in snapshot_pmem_size[currently static at 4GB]:
	; 	if page is in mmio_table:
	;     do not map page (mmio causes faults and end of fuzz cases)
	;     ptr += 0 (we consume nothing as we dont map mmio)
	;   else
	;     create mapping for page
	;     memcpy(new_mapping, ptr, 4096);
	;     ptr += 4096 (we consumed 4096 bytes)
endstruc

struc bb_struc
	.counter: resq 1
	.input:   resq 1
endstruc

struc input_struc
	.image:
endstruc

struc ctrl
	.idx: resq 1
	.len: resq 1
	.num: resq 1
endstruc

struc bracket
	.idx: resq 1
	.len: resq 1
endstruc

; -------------------------------------------------------------------------
; Cores initialized after this point
;
; rax  - Unique core ID (0 means BSP) (does not match APID id!)
; rdi  - Pointer to the line on the screen corresponding to the core ID
; rsp  - 1MB per stack allocated
; segs - All 0x0000 besides CS which is 0x0008
;
; IF is cleared
; DF is cleared
; all other registers undefined!
; all memory operations MUST be rip relative from this point on
; -------------------------------------------------------------------------

program:
	sub rsp, 4096

	cmp qword [gs:thread_local.core_id], 0
	jne do_thread_shit

.lewp:
	mov  r13, 1024
	call falktp_pull

	mov  rbx, rsi
	mov  rcx, rbp
	call shitsum

	mov  rdi, 0xb8000 + 80 * 2 * 15
	mov  rdx, rax
	call outhexq

	jmp short .lewp

	jmp .halt

	call init_hdd

	; Get the combinesvg.bin
	mov  ecx, 0x3578
	;call falktp_get
	mov  qword [fs:globals.per_node_combinesvg + node_struct.orig_data], rdi
	mov  qword [fs:globals.per_node_combinesvg + node_struct.data_len],  r14
	test r14, r14
	jz   .halt

	call alloc_zero_4k
	mov  qword [fs:globals.coverage_flut], rax
	call alloc_zero_4k
	mov  qword [fs:globals.input_flut], rax

	call init_launch_svm

.halt:
	cli
	hlt
	jmp short .halt

init_launch_svm:
	call init_svm
	call launch_svm
	ret

do_thread_shit:
	call init_svm
	call launch_snapshot_vm

	cli
	hlt

; rdi -> Haystack
; rsi -> Needle
; rcx -> Needle size
; rdx -> Haystack size
; rax <- Found location
memmem:
	push rcx
	push rdx
	push rdi
	push rsi

	sub rdx, rcx
	jl  short .not_found

.lewp:
	push rdi
	push rsi
	push rcx
	mov  rax, rdi
	rep  cmpsb
	pop  rcx
	pop  rsi
	pop  rdi
	je   .found

	add rdi, 0x1000
	sub rdx, 0x1000
	cmp rdx, 0
	jge short .lewp

.not_found:
	xor rax, rax

.found:
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	ret

; This enables SVM in the EFER for AMD machines
init_svm:
	push rax
	push rcx
	push rdx

	mov ecx, 0xc0000080
	rdmsr

	bts eax, 12
	wrmsr

	pop rdx
	pop rcx
	pop rax
	ret

init_seed:
	push rax
	push rcx
	push rdx
	push r15

	; Seed the seed with a constant and xor it with the core ID. Then run it
	; through 1024 rounds of xorshift to get the core ID to really change the
	; xorshift value.
	mov r15, 0x1337133713371337
	add r15, qword [gs:thread_local.core_id]
	mov qword [gs:thread_local.xs_seed], r15
 
	mov rcx, 1024
.lewp_core:
	call xorshift64

	dec rcx
	jnz short .lewp_core

	; Now randomly xorshift in some of the timestamp counter into the seed. We
	; do this a few times based on a random number. We will always do this at
	; least 1024 times.
	call xorshift64
	mov  rcx, r15
	and  rcx, 0xFFF
	add  rcx, 1024
.lewp:
	; Seed the seed with the timestamp counter
	rdtsc
	xor qword [gs:thread_local.xs_seed], rdx
	xor qword [gs:thread_local.xs_seed], rax

	call xorshift64
	
	dec rcx
	jnz short .lewp

	pop r15
	pop rdx
	pop rcx
	pop rax
	ret

xorshift64:
	push r10

	mov r15, qword [gs:thread_local.xs_seed]

	mov r10, r15
	shl r10, 13
	xor r15, r10

	mov r10, r15
	shr r10, 17
	xor r15, r10

	mov r10, r15
	shl r10, 43
	xor r15, r10

	mov qword [gs:thread_local.xs_seed], r15

	pop r10
	ret

; This is called in a raw vm state. You must save the actual GPRs here.
save_vm_snapshot:
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp

	; If we have fuzz workers, we do not start a new fuzz case.
	push rax
	push rbx

	mov qword [fs:globals.stop_fuzzing], 1

.wait_for_fuzzers_to_stop:
	pause
	xor  rax, rax
	mov  rbx, 1
	lock cmpxchg qword [fs:globals.vms_fuzzing], rbx
	jne  .wait_for_fuzzers_to_stop

	pop  rbx
	pop  rax

	push rax
	push rbx

	; Use the old snapshot memory
	mov  rbx, qword [fs:globals.vm_snapshot]
	test rbx, rbx
	jnz  short .create_snapshot

	; Allocate room for our vm snapshot
	mov rbx, vm_snapshot_size + (4 * 1024 * 1024 * 1024)
	bamp_alloc rbx

.create_snapshot:
	mov [rbx + vm_snapshot.rcx], rcx
	mov [rbx + vm_snapshot.rdx], rdx
	mov [rbx + vm_snapshot.rsi], rsi
	mov [rbx + vm_snapshot.rdi], rdi
	mov [rbx + vm_snapshot.rbp], rbp
	mov [rbx + vm_snapshot.r8],  r8
	mov [rbx + vm_snapshot.r9],  r9
	mov [rbx + vm_snapshot.r10], r10
	mov [rbx + vm_snapshot.r11], r11
	mov [rbx + vm_snapshot.r12], r12
	mov [rbx + vm_snapshot.r13], r13
	mov [rbx + vm_snapshot.r14], r14
	mov [rbx + vm_snapshot.r15], r15

	mov rcx, rbx
	pop rbx

	; rcx now points to the vm_snapshot
	mov [rcx + vm_snapshot.rbx], rbx
	mov rbx, cr8
	mov [rcx + vm_snapshot.cr8], rbx
	
	; Save off xcr0
	push rcx
	mov  ecx, 0
	xgetbv
	pop  rcx
	shl  rdx, 32
	or   rdx, rax
	mov  [rcx + vm_snapshot.xcr0], rdx

	; Save off debug registers
	mov rbx, dr0
	mov [rcx + vm_snapshot.dr0], rbx
	mov rbx, dr1
	mov [rcx + vm_snapshot.dr1], rbx
	mov rbx, dr2
	mov [rcx + vm_snapshot.dr2], rbx
	mov rbx, dr3
	mov [rcx + vm_snapshot.dr3], rbx

	; Set up xcr0 to save all state (FPU, MMX, SSE, AVX, and LWP)
	mov   edx, 0x40000000
	mov   eax, 0x00000007
	push  rcx
	mov   ecx, 0
	xsetbv
	pop   rcx
	xsave [rcx + vm_snapshot.xsave]

	pop rax ; Restore vmcb

	; Save off vmcb
	push rcx
	mov  rsi, rax
	lea  rdi, [rcx + vm_snapshot.vmcb]
	mov  rcx, 4096 / 8
	rep  movsq
	pop  rcx

	lea  r10, [rcx + vm_snapshot.physical_memory]
	push rcx

	; For each address
	mov rbx, 0
	mov rbp, (4 * 1024 * 1024 * 1024)
.lewp:
	call probe_memory_dest
	test rdx, rdx
	jnz  short .is_mmio_map

	mov rsi, rbx
	mov rdi, r10
	mov rcx, 4096 / 8
	rep movsq
	jmp short .next_map

.is_mmio_map:

.next_map:
	add r10, 4096
	add rbx, 4096
	cmp rbx, rbp
	jb  short .lewp

	pop rcx

	push rax
	push rdi
	push rsi
	push rcx
	push rdx
	lea  rdi, [rcx + vm_snapshot.physical_memory + 0x3c4]
	lea  rsi, [rel needle]
	mov  rcx, 16
	mov  rdx, (4 * 1024 * 1024 * 1024)
	call memmem
	test rax, rax
	jz   short .not_found

	mov dword [rax], 0xcccccccc

.not_found:
	pop  rdx
	pop  rcx
	pop  rsi
	pop  rdi
	pop  rax

	mov qword [fs:globals.vm_snapshot],  rcx
	mov qword [fs:globals.stop_fuzzing], 0
	mov qword [fs:globals.vms_fuzzing],  (NUM_CORES - 1)

.resume:
	pop rbp
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax

	jmp launch_svm.inject_debug

needle:
	db 0x8B, 0xC8, 0xBA, 0x02, 0x00, 0x00, 0x00, 0x81, 0xF9, 0x06, 0x00, 0x00
	db 0xD0, 0x74, 0x41, 0x81

panic:
	cli
	int3
.lewp:
	hlt
	jmp short .lewp

; Start logging timing. Takes and returns nothing.
start_log:
	push rax
	push rdx

	rdtsc
	shl rdx, 32
	or  rdx, rax

	mov qword [gs:thread_local.time_log], rdx

	pop rdx
	pop rax
	ret

; Stop logging timing
;
; rdx <- ticks occured since last call to start_log
stop_log:
	push rax

	rdtsc
	shl rdx, 32
	or  rdx, rax

	mov rax, qword [gs:thread_local.time_log]
	sub rdx, rax

	pop rax
	ret

; Boot a simple guest OS
launch_snapshot_vm:
.wait_for_vm_start:
	pause
	cmp qword [fs:globals.vms_fuzzing], (NUM_CORES - 1)
	jne short .wait_for_vm_start

	; Allocate room to hold the original svg
	mov rbx, 16 * 1024 * 1024
	bamp_alloc rbx
	mov qword [gs:thread_local.orig_svg], rbx

	; Allocate and set up the VM_HSAVE_PA MSR
	; This is where the host will store the save state for itself when
	; entering a VM as well as where it will load it back from. According to
	; the specs, this can change and/or some may be placed in in-chip memory
	; thus never rely on the state of this structure
	call alloc_zero_4k

	; Actually set the VM_HSAVE_PA MSR
	mov rdx, rax
	shr rdx, 32
	mov ecx, 0xC0010117
	wrmsr

	; Allocate room for the IOIO mask
	mov  rcx, (12 * 1024)
	call mm_alloc_contig_phys
	mov  [gs:thread_local.ioio], rax

	; Fill the IOIO mask with 1s
	mov rdi, rax
	mov rcx, (12 * 1024)
	mov  al, 0x41
	rep stosb

	; Allocate room for the 4K VMCB structure
	call alloc_zero_4k

.wait_for_vm:
	pause
	cmp qword [fs:globals.vms_fuzzing], (NUM_CORES - 1)
	jne short .wait_for_vm

	; Get the snapshot pointer
	mov rsi, qword [fs:globals.vm_snapshot]

	; -----------------------------------------------------------
	; Start loading cr3 with initial state
	; -----------------------------------------------------------

	; Create/reload cr3
	push rax
	push rsi

	; Check if we already have allocated a guest ncr3
	cmp qword [gs:thread_local.vm_ncr3], 0
	jne short .already_have_ncr3

	; Allocate a guest ncr3
	call alloc_zero_4k
	mov  r15, rax
	jmp  short .start_mapping

.already_have_ncr3:
	mov  r15, [gs:thread_local.vm_ncr3]
	mov  rdx, r15
	call mm_clean_all_pages

.start_mapping:
	mov rbx, 0
	lea rsi, [rsi + vm_snapshot.physical_memory]
	mov  r8, (4 * 1024 * 1024 * 1024)
.lewp:
	call probe_memory_dest
	test rdx, rdx
	jnz  short .is_mmio_map

	; Check if we already have allocated a guest ncr3
	cmp qword [gs:thread_local.vm_ncr3], 0
	jne short .already_have_ncr3_deep

	; Allocate a backing page
	call alloc_zero_4k
	mov  rbp, rax
	mov  rdi, rax

	or   rbp, 7
	mov  rdx, r15
	call mm_map_4k
	jmp  .perform_mem_copy

.already_have_ncr3_deep:
	mov  rdx, r15
	call mm_get_phys
	mov  rdi, rax

.perform_mem_copy:
	; Copy over the memory to this mapping
	push rcx
	push rdi
	push rsi
	mov  rcx, 4096 / 8
	rep  movsq
	pop  rsi
	pop  rdi
	pop  rcx

	jmp short .next_map

.is_mmio_map:
	; Don't map MMIO

.next_map:
	add rsi, 4096
	add rbx, 4096
	cmp rbx, r8
	jb  short .lewp
	pop rsi
	pop rax

	; Save the guest ncr3 so next time we don't allocate, we just repopulate
	mov qword [gs:thread_local.vm_ncr3], r15

	; -----------------------------------------------------------
	; End loading cr3 with initial state
	; -----------------------------------------------------------

.next_fuzz:
	mov  qword [gs:thread_local.time_restore], 0
	mov  qword [gs:thread_local.time_corrupt], 0
	mov  qword [gs:thread_local.time_running], 0
	mov  qword [gs:thread_local.time_coverag], 0

%ifdef ENABLE_LOGGING
	call start_log
%endif

	; Get the snapshot pointer
	mov rsi, qword [fs:globals.vm_snapshot]

	mov  rdx, qword [gs:thread_local.vm_ncr3]
	lea  rbp, [rel restore_page]
	call mm_for_each_dirty_4k

%ifdef ENABLE_LOGGING
	call stop_log
	add  qword [gs:thread_local.time_restore], rdx
%endif

	; Get the snapshot pointer
	mov rsi, qword [fs:globals.vm_snapshot]

	; Copy the snapshot vmcb here
	push rsi
	lea  rsi, [rsi + vm_snapshot.vmcb]
	mov  rdi, rax
	mov  rcx, 4096 / 8
	rep  movsq
	pop  rsi

	; Intercept ins and outs, all interrupts, and shutdowns
	mov dword [rax + VMCB.icpt_set_1], (1 << 27) | (1 << 31) | 0x1f

	mov dword [rax + VMCB.icpt_set_2], 1         ; Intercept VMRUN
	mov qword [rax + VMCB.vint],       (1 << 24) ; Mask all interrupts

	mov dword [rax + VMCB.except_icpt], 0xffffffff

	; Set up the IOPM field to enable capturing of all ins and outs
	mov rbx, qword [gs:thread_local.ioio]
	mov qword [rax + VMCB.iopm], rbx

	; Update the VMCB ncr3
	mov rbx, qword [gs:thread_local.vm_ncr3]
	mov qword [rax + VMCB.n_cr3], rbx

	mov rbx, [rsi + vm_snapshot.cr8]
	mov cr8, rbx

	mov rbx, [rsi + vm_snapshot.dr0]
	mov dr0, rbx
	mov rbx, [rsi + vm_snapshot.dr1]
	mov dr1, rbx
	mov rbx, [rsi + vm_snapshot.dr2]
	mov dr2, rbx
	mov rbx, [rsi + vm_snapshot.dr3]
	mov dr3, rbx

	push rax

	; Set up xcr0 to save all state (FPU, MMX, SSE, AVX, and LWP)
	mov edx, 0x40000000
	mov eax, 0x00000007
	xor ecx, ecx
	xsetbv
	xrstor [rsi + vm_snapshot.xsave]

	; Restore the snapshot xcr0 state
	mov rdx, [rsi + vm_snapshot.xcr0]
	mov eax, edx
	shr rdx, 32
	xor ecx, ecx
	xsetbv

	pop rax

%ifdef ENABLE_FUZZING
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r13
	push r14
	push r15

%ifdef ENABLE_LOGGING
	call start_log
%endif

	mov r13, rax ; VMCB
	mov r14, rsi ; vm_snapshot

	mov  rcx, [r14 + vm_snapshot.r8]
	mov  [gs:thread_local.orig_svg_len], rcx

	mov  rsi, [r14 + vm_snapshot.rdx]
	mov  rdi, [gs:thread_local.orig_svg]
	mov  rcx, [gs:thread_local.orig_svg_len]
	mov  rdx, [r13 + VMCB.cr3]
	mov  rbp, [r13 + VMCB.n_cr3]
	call mm_copy_from_guest_vm

	mov  rbx, [gs:thread_local.orig_svg]
	mov  rcx, [gs:thread_local.orig_svg_len]

%ifdef ENABLE_FEEDBACK
	; 50/50 chance of starting a fresh fuzz case
	call xorshift64
	test r15, 1
	jz   short .dont_feedback

	; Try to do coverage guided fuzzing by picking a random entry that
	; hit unique code.
	push rbx
	mov  rbx, qword [fs:globals.coverage_flut]
	call random_flut
	jc   short .no_entry

	push rcx
	push rdi
	push rsi
	mov  rdi, [gs:thread_local.orig_svg]
	mov  rsi, [rbx + bb_struc.input]
	mov  rcx, [gs:thread_local.orig_svg_len]
	rep  movsb
	pop  rsi
	pop  rdi
	pop  rcx

.no_entry:
	pop  rbx
.dont_feedback:
%endif

	; Ensure that we can corrupt up to SAFE_CORRUPT off the end of the file by
	; repotring the length is SAFE_CORRUPT shorter. Make sure we don't go
	; negative here.
	sub  rcx, SAFE_CORRUPT
	cmp  rcx, 0
	jle  .done_fuzzing

	; At this point rbx points to the host virtual memory to corrupt and
	; rcx is the maxiumum size that we can corrupt in rbx. We have already
	; ensured that rcx is nonzero, and thus we can div off of it safely.

%ifdef SELECT_FUZZ
	call xorshift64
	mov  rbp, r15
	and  rbp, 0xF
	inc  rbp
.select_fuzz:
	; Randomly pick a location in the SVG
	call xorshift64
	xor  rdx, rdx
	mov  rax, r15
	div  rcx
	and  rdx, ~1

	; rdi points to random place in input
	lea rdi, [rbx + rdx]

	; Randomly pick a location in the combinesvg
	call xorshift64
	xor  rdx, rdx
	mov  rax, r15
	mov  rsi, [fs:globals.per_node_combinesvg + node_struct.data_len]
	sub  rsi, SAFE_CORRUPT
	cmp  rsi, 0
	jle  .done_fuzzing
	div  rsi
	and  rdx, ~1

	push rax
	push rbx
	push rcx
	; rsi points to random point in combinesvg
	mov  rbx, qword [fs:globals.fs_base]
	add  rbx, globals.per_node_combinesvg
	call per_node_data

	add rdx, rax
	mov rsi, rdx

	; Randomly copy up to 4k
	call xorshift64
	mov  rcx, r15
	and  rcx, 0xFFF
	rep  movsb
	pop  rcx
	pop  rbx
	pop  rax

	dec rbp
	jnz .select_fuzz
%endif

.done_fuzzing:
	; Commit the corrupted SVG to the VM
	mov  rsi, [gs:thread_local.orig_svg]
	mov  rdi, [r14 + vm_snapshot.rdx]
	mov  rcx, [r14 + vm_snapshot.r8]
	mov  rdx, [r13 + VMCB.cr3]
	mov  rbp, [r13 + VMCB.n_cr3]
	call mm_copy_to_guest_vm

%ifdef ENABLE_LOGGING
	call stop_log
	add  qword [gs:thread_local.time_corrupt], rdx
%endif
	pop r15
	pop r14
	pop r13
	pop rbp
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
%endif ; ENABLE_FUZZING

	; ---------------------------------------------------------------------
	; No allocations allowed after this point!
	;
	; rax - VMCB
	; r8  - Dump
	; r13 - VM Context result
	; r14 - VM CR3 physical addr
	; ---------------------------------------------------------------------

	; Exhaustion counter. We get about 100k timers per second per core
	mov qword [gs:thread_local.exhaust], EXHAUST_COUNT

%ifdef ENABLE_LOGGING
	call start_log
%endif

	; Save the hosts gs and fs
	mov  rbx, [gs:thread_local.gs_base]
	push rbx
	mov  rbx, [fs:globals.fs_base]
	push rbx

	mov rcx, [rsi + vm_snapshot.rcx]
	mov rdx, [rsi + vm_snapshot.rdx]
	mov rbx, [rsi + vm_snapshot.rbx]
	mov rbp, [rsi + vm_snapshot.rbp]
	mov rdi, [rsi + vm_snapshot.rdi]
	mov  r8, [rsi + vm_snapshot.r8]
	mov  r9, [rsi + vm_snapshot.r9]
	mov r10, [rsi + vm_snapshot.r10]
	mov r11, [rsi + vm_snapshot.r11]
	mov r12, [rsi + vm_snapshot.r12]
	mov r13, [rsi + vm_snapshot.r13]
	mov r14, [rsi + vm_snapshot.r14]
	mov r15, [rsi + vm_snapshot.r15]
	mov rsi, [rsi + vm_snapshot.rsi]

%ifdef ENABLE_LBR
	; Enable LBR virtualization
	bts qword [rax + VMCB.lbr_virt_en], 0

	; Enable LBR
	bts qword [rax + VMCB.dbgctrl], 0
%endif

%ifdef ENABLE_IBS
	push rax
	push rcx
	push rdx

	mov ecx, 0xc0011033
	mov edx, 0
	mov eax, (1 << 17) | ENABLE_IBS
	wrmsr

	pop rdx
	pop rcx
	pop rax
%endif

	clgi
	vmload
	vmrun
	stgi

	jmp .vm_exit

.relaunch:
%ifdef ENABLE_LOGGING
	call start_log
%endif

	push rdx
	mov  rdx, [gs:thread_local.guest_fs]
	call set_fs_base
	mov  rdx, [gs:thread_local.guest_gs]
	call set_gs_base
	pop  rdx

%ifdef ENABLE_LBR
	; Enable LBR
	bts qword [rax + VMCB.dbgctrl], 0
%endif

%ifdef ENABLE_IBS
	push rax
	push rcx
	push rdx

	mov ecx, 0xc0011033
	mov edx, 0
	mov eax, (1 << 17) | ENABLE_IBS
	wrmsr

	pop rdx
	pop rcx
	pop rax
%endif

	clgi
	vmrun
	stgi

.vm_exit:
	push rbx
	push rdx

	call get_gs_base
	mov  rbx, rdx
	mov  rdx, [rsp + 0x18]
	call set_gs_base
	mov  [gs:thread_local.guest_gs], rbx

	call get_fs_base
	mov  rbx, rdx
	mov  rdx, [rsp + 0x10]
	call set_fs_base
	mov  [gs:thread_local.guest_fs], rbx

	pop  rdx
	pop  rbx

%ifdef ENABLE_LOGGING
	push rdx
	call stop_log
	add  qword [gs:thread_local.time_running], rdx
	pop  rdx
%endif

%ifdef ENABLE_IBS
	cmp qword [rax + VMCB.exitcode], 0x61
	jne .next_exitcode_0

	; Check if we might be stuck in a loop
	dec qword [gs:thread_local.exhaust]
	jz  .done

%ifdef ENABLE_COVERAGE
	push rbx
	push rcx
	push rdx
	push r14

%ifdef ENABLE_LOGGING
	call start_log
%endif

	; Fetch the linear address of memory associated with this sample. If the
	; linear address is not present, we will store 0.
	push rax
	xor  r14, r14
	mov  ecx, 0xc0011037
	rdmsr
	test eax, (1 << 17) ; IbsDcLinAddrValid
	jz   short .lin_addr_not_valid

	; Get the linear address from DC_IBS_LIN_ADDR
	mov ecx, 0xc0011038
	rdmsr
	mov r14, rdx
	shl r14, 32
	or  r14, rax
.lin_addr_not_valid:
	pop rax

	; Look up this RIP in our code coverage flut
	mov   rcx, qword [fs:globals.coverage_flut]
	mov   rdx, qword [rax + VMCB.br_to]
	bswap rdx
	xor   rdx, qword [rax + VMCB.br_from]
	call  flut_fetch_or_lock
	jnc   .already_present

	; Update bb counter
	mov  rdx, 1
	lock xadd qword [fs:globals.fuzz_status + fuzz_status.num_unique_bb], rdx

	; Add a record here
	mov rbx, bb_struc_size
	bamp_alloc rbx

	; Initialize the counter which keeps track of how many times this block
	; has been hit.
	mov qword [rbx + bb_struc.counter], 0
	mov rdx, rbx

	push rax
	push rbx
	push rcx
	push rdx

	mov  rbx, [gs:thread_local.orig_svg]
	mov  rcx, [gs:thread_local.orig_svg_len]
	call shitsum

	; Look up this input in the input flut
	push rdx
	mov  rcx, qword [fs:globals.input_flut]
	mov  rdx, rax
	call flut_fetch_or_lock
	pop  rdx
	jnc  .already_input

	mov rbx, [gs:thread_local.orig_svg_len]
	bamp_alloc rbx

	; Save off the record that hit this case
	push rcx
	push rdi
	push rsi
	lea  rdi, [rbx + input_struc.image]
	mov  rsi, [gs:thread_local.orig_svg]
	mov  rcx, [gs:thread_local.orig_svg_len]
	rep  movsb
	pop  rsi
	pop  rdi
	pop  rcx

	; Fill in the flut
	mov [rcx], rbx
	mov rcx, rbx

.already_input:
	mov qword [rdx + bb_struc.input], rcx
	pop rdx
	pop rcx
	pop rbx
	pop rax

	; Fill in the flut
	mov [rcx], rbx

	; Update rcx to point to the flut entry
	mov rcx, rbx

.already_present:
	lock inc qword [rcx + bb_struc.counter]

%ifdef ENABLE_LOGGING
	call stop_log
	add  qword [gs:thread_local.time_coverag], rdx
%endif

	pop r14
	pop rdx
	pop rcx
	pop rbx
%endif ; ENABLE_COVERAGE

%ifdef ENABLE_INVALIDATE_STACK_ON_TIMERS
	push rcx
	push rdx
	push rdi
	push rsi
	push rbp
	mov  esi, 0xf0
	mov  rdi, qword [rax + VMCB.rsp]
	sub  rdi, 1
	mov  rcx, (1 * 1024 * 1024 * 1024)
	mov  rdx, qword [rax + VMCB.cr3]
	mov  rbp, qword [rax + VMCB.n_cr3]
	call mm_memset_backwards
	pop  rbp
	pop  rsi
	pop  rdi
	pop  rdx
	pop  rcx
%endif

	jmp .relaunch
%endif ; ENABLE_IBS

.next_exitcode_0:
	cmp qword [rax + VMCB.exitcode], 0x41
	jne short .next_exitcode_1

	mov qword [rax + VMCB.dr6], 0
	bts qword [rax + VMCB.rfl], 16
	jmp .relaunch

.next_exitcode_1:
	; Shutdown events
	cmp qword [rax + VMCB.exitcode], 0x7f
	jne short .next_exitcode_2

	jmp .dead_fuzz

.next_exitcode_2:
	; #PF
	cmp qword [rax + VMCB.exitcode], 0x4e
	jne short .next_exitcode_3	

	push rax
	push rbx
	push rcx
	push rdx
	push rbp

	; Inject page fault into VM
	mov  rbx, qword [rax + VMCB.exitinfo1]
	shl  rbx, 32
	mov  rdx, (1 << 31) | (1 << 11) | (3 << 8) | 0xe ; #PF, valid, push error
	or   rbx, rdx
	mov  qword [rax + VMCB.eventinj], rbx

	; Store cr2
	mov  rbx, qword [rax + VMCB.exitinfo2]
	mov  cr2, rbx
	mov  qword [rax + VMCB.cr2], rbx
	
	pop  rbp
	pop  rdx
	pop  rcx
	pop  rbx
	pop  rax

	call save_vm_context

	jmp .relaunch

.next_exitcode_3:
	; #BP
	cmp qword [rax + VMCB.exitcode], 0x43
	jne short .done

	; If rip is user mode, this isn't our page fault handler, it's just a
	; normal #BP, so report it!
	bt  qword [rax + VMCB.rip], 63
	jnc .done
	
	; Store that this is a #PF, and use the #PF context saved from before
	mov qword [rax + VMCB.exitcode], 0x4e

	jmp .done_ignore_context

.done:
	call save_vm_context
.done_ignore_context:
	mov  r15, qword [gs:thread_local.time_restore]
	lock add [fs:globals.fuzz_status + fuzz_status.time_restore], r15
	mov  r15, qword [gs:thread_local.time_corrupt]
	lock add [fs:globals.fuzz_status + fuzz_status.time_corrupt], r15
	mov  r15, qword [gs:thread_local.time_running]
	lock add [fs:globals.fuzz_status + fuzz_status.time_running], r15
	mov  r15, qword [gs:thread_local.time_coverag]
	lock add [fs:globals.fuzz_status + fuzz_status.time_coverag], r15

	; Update the per core fuzz case counter
	mov  r15, qword [gs:thread_local.core_id]
	lock inc qword [fs:globals.fuzz_status + fuzz_status.pc_fc + r15*8]

	mov  r15, 1
	lock xadd qword [fs:globals.fuzz_status + fuzz_status.fuzz_cases], r15

	; Check for ud2
	cmp qword [rax + VMCB.exitcode], 0x46
	jne .next_stat_00

	; We got a ud2, record that we got success
	lock inc qword [fs:globals.fuzz_status + fuzz_status.fuzz_complete]
	jmp short .done_doing_stats

.next_stat_00:
	; NPT fault
	cmp qword [rax + VMCB.exitcode], 0x400
	je  short .hit_io

	; in/out instruction
	cmp qword [rax + VMCB.exitcode], 0x7b
	je  short .hit_io

	; interrupt
	cmp qword [rax + VMCB.exitcode], 0x60
	je  short .hit_io

%ifndef ENABLE_IBS
	; NMI
	cmp qword [rax + VMCB.exitcode], 0x61
	je  short .hit_io
%endif

	; SMI
	cmp qword [rax + VMCB.exitcode], 0x62
	je  short .hit_io

	; INIT
	cmp qword [rax + VMCB.exitcode], 0x63
	je  short .hit_io

	; Virtual interrupts
	cmp qword [rax + VMCB.exitcode], 0x64
	je  short .hit_io

	jmp short .done_doing_stats
	
.hit_io:
	lock inc qword [fs:globals.fuzz_status + fuzz_status.fuzz_io]

.done_doing_stats:
	cmp qword [rax + VMCB.exitcode], 0x40
	jb  .not_crash
	cmp qword [rax + VMCB.exitcode], 0x5f
	ja  .not_crash

	; Ignore exceptions in the kernel
	bt qword [gs:thread_local.vm_ctxt + vm_ctxt.rip], 63
	jc .not_crash

	; Ignore breakpoints
	cmp qword [rax + VMCB.exitcode], 0x41
	je  .not_crash

	; Ignore ud2s
	cmp qword [rax + VMCB.exitcode], 0x46
	je  .not_crash

	lock inc qword [fs:globals.fuzz_status + fuzz_status.num_crashes]

	; Send the context of the crash
	mov  rbx, [gs:thread_local.gs_base]
	lea  rbx, [rbx + thread_local.vm_ctxt]
	mov  rcx, vm_ctxt_size
	call i825xx_send_packet

	; Send the crashing input
	mov  r10, [gs:thread_local.orig_svg]
	mov  r11, [gs:thread_local.orig_svg_len]
	call falktp_transmit

.not_crash:
	test r15, 0xFF
	jnz  short .dont_report

	; Report the fuzz status over the network
	mov rbx, [fs:globals.fs_base]
	lea rbx, [rbx + globals.fuzz_status]
	mov dword [rbx + fuzz_status.magic], FUZZ_STATUS_MAGIC

	mov  rcx, fuzz_status_size
	call i825xx_send_packet

.dont_report:
	; Discard the saved FS and GS
	pop rbx
	pop rbx

	cmp qword [fs:globals.stop_fuzzing], 0
	je  .next_fuzz

.dead_fuzz:
	lock dec qword [fs:globals.vms_fuzzing]

	jmp .wait_for_vm

save_vm_context:
	push rbx

	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rbx], rbx
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rcx], rcx
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rdx], rdx
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rsi], rsi
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rdi], rdi
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rbp], rbp
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.r8],  r8
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.r9],  r9
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.r10], r10
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.r11], r11
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.r12], r12
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.r13], r13
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.r14], r14
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.r15], r15
	mov  rbx, [rax + VMCB.rax]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rax], rbx
	mov  rbx, [rax + VMCB.rsp]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rsp], rbx
	mov  rbx, [rax + VMCB.rip]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rip], rbx
	mov  rbx, [rax + VMCB.rfl]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rfl], rbx

	mov  rbx, [rax + VMCB.cr0]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.cr0], rbx
	mov  rbx, [rax + VMCB.cr2]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.cr2], rbx
	mov  rbx, [rax + VMCB.cr3]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.cr3], rbx
	mov  rbx, [rax + VMCB.cr4]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.cr4], rbx

	mov  dword [gs:thread_local.vm_ctxt + vm_ctxt.magic], VM_STATE_DUMP

	mov  rbx, [rax + VMCB.exitcode]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.vec], rbx
	mov  rbx, [rax + VMCB.exitinfo1]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.ei1], rbx
	mov  rbx, [rax + VMCB.exitinfo2]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.ei2], rbx
	mov  rbx, [rax + VMCB.exitintinfo]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.eii], rbx
	mov  rbx, [rax + VMCB.n_cr3]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.n_cr3], rbx

	pop rbx
	ret

; rbx -> Virtual address this page maps
; r13 -> Pointer to page entry
; rsi -> VM Snapshot
restore_page:
	push rcx
	push rsi
	push rdi

	; Get the physical address for this page
	bextr rdi, qword [r13], 0x280c
	shl   rdi, 12

	; Copy in the original page
	lea rsi, [rsi + vm_snapshot.physical_memory]
	add rsi, rbx
	mov rcx, 4096 / 8
	rep movsq

	pop rdi
	pop rsi
	pop rcx
	ret

; Boot a simple guest OS
launch_svm:
	; Allocate and set up the VM_HSAVE_PA MSR
	; This is where the host will store the save state for itself when
	; entering a VM as well as where it will load it back from. According to
	; the specs, this can change and/or some may be placed in in-chip memory
	; thus never rely on the state of this structure
	call alloc_zero_4k

	; Actually set the VM_HSAVE_PA MSR
	mov rdx, rax
	shr rdx, 32
	mov ecx, 0xC0010117
	wrmsr

	; Allocate room for the 4K VMCB structure
	call alloc_zero_4k

	; ---------------------------------------------------------------------
	; No allocations allowed after this point!
	;
	; rax - VMCB
	; r8  - Dump
	; r13 - VM Context result
	; r14 - VM CR3 physical addr
	; ---------------------------------------------------------------------

	mov rbx, 1 | (3 << 32) ; ASID 1, Flush this guest’s TLB entries
	mov qword [rax + VMCB.tlb_and_asid], rbx

	mov qword [rax + VMCB.vint], 0

	mov dword [rax + VMCB.except_icpt], (1 << 1) ; Intercept #DBs

	mov dword [rax + VMCB.icpt_set_1], (1 << 21) ; Intercept INTn
	mov dword [rax + VMCB.icpt_set_2], 1         ; Intercept VMRUN

	mov qword [rax + VMCB.cr4], 0
	mov qword [rax + VMCB.cr3], 0
	mov qword [rax + VMCB.cr2], 0
	mov qword [rax + VMCB.cr0], 0x00000010

	push rax
	call alloc_zero_4k
	mov  r15, rax

	mov rbx, 0
	mov rsi, (4 * 1024 * 1024 * 1024)
.lewp:
	; DRAM pages are cloned for a guest copy which can be modified
	; MMIO pages are identity mapped through to the host with no caching
	call probe_memory_dest
	test rdx, rdx
	jnz  short .is_mmio_map

	; Identity map this with caching enabled
	mov  rbp, rbx
	or   rbp, 7
	mov  rdx, r15
	call mm_map_4k
	jmp  short .next_map

.is_mmio_map:
	; Identity map this with caching disabled
	mov  rbp, rbx
	or   rbp, 7 | (3 << 3)
	mov  rdx, r15
	call mm_map_4k

.next_map:
	add rbx, 4096
	cmp rbx, rsi
	jb  short .lewp
	pop rax

	; Copy the first sector of the boot image to 0x7c00
	push rax
	push rsi
	push rdi
	push rcx
	mov  rbx, 0x7c00
	mov  rdx, r15
	call mm_get_phys

	mov  rbx, 0
	mov   cx, 1
	mov   r8, rax
	call ide_pio_read_sectors

	pop  rcx
	pop  rdx
	pop  rsi
	pop  rax

	mov qword [rax + VMCB.np_enable], 1
	mov qword [rax + VMCB.n_cr3],     r15

	mov  word [rax + VMCB.es_sel],    0
	mov  word [rax + VMCB.es_attrib], 0x93
	mov qword [rax + VMCB.es_base],   0
	mov dword [rax + VMCB.es_limit],  0xFFFF

	mov  word [rax + VMCB.cs_sel],    0
	mov  word [rax + VMCB.cs_attrib], 0x93
	mov qword [rax + VMCB.cs_base],   0
	mov dword [rax + VMCB.cs_limit],  0xFFFF

	mov  word [rax + VMCB.ss_sel],    0
	mov  word [rax + VMCB.ss_attrib], 0x93
	mov qword [rax + VMCB.ss_base],   0
	mov dword [rax + VMCB.ss_limit],  0xFFFF

	mov  word [rax + VMCB.ds_sel],    0
	mov  word [rax + VMCB.ds_attrib], 0x93
	mov qword [rax + VMCB.ds_base],   0
	mov dword [rax + VMCB.ds_limit],  0xFFFF

	mov  word [rax + VMCB.fs_sel],    0
	mov  word [rax + VMCB.fs_attrib], 0x93
	mov qword [rax + VMCB.fs_base],   0
	mov dword [rax + VMCB.fs_limit],  0xFFFF

	mov  word [rax + VMCB.gs_sel],    0
	mov  word [rax + VMCB.gs_attrib], 0x93
	mov qword [rax + VMCB.gs_base],   0
	mov dword [rax + VMCB.gs_limit],  0xFFFF

	mov  word [rax + VMCB.gdtr_sel],    0
	mov  word [rax + VMCB.gdtr_attrib], 0x82
	mov qword [rax + VMCB.gdtr_base],   0
	mov dword [rax + VMCB.gdtr_limit],  0xFFFF

	mov  word [rax + VMCB.ldtr_sel],    0
	mov  word [rax + VMCB.ldtr_attrib], 0x82
	mov qword [rax + VMCB.ldtr_base],   0
	mov dword [rax + VMCB.ldtr_limit],  0xFFFF

	mov  word [rax + VMCB.idtr_sel],    0
	mov  word [rax + VMCB.idtr_attrib], 0x82
	mov qword [rax + VMCB.idtr_base],   0
	mov dword [rax + VMCB.idtr_limit],  0xFFFF

	mov  word [rax + VMCB.tr_sel],    0
	mov  word [rax + VMCB.tr_attrib], 0x82
	mov qword [rax + VMCB.tr_base],   0
	mov dword [rax + VMCB.tr_limit],  0xFFFF

	mov  byte [rax + VMCB.cpl], 0

	mov qword [rax + VMCB.efer], (1 << 12)

	mov qword [rax + VMCB.dr7], 0
	mov qword [rax + VMCB.dr6], 0

	mov rbx, 0x0007040600070406
	mov qword [rax + VMCB.g_pat], rbx

	; Set up guest rfl
	mov qword [rax + VMCB.rfl], 2

	; Set up guest rip
	mov qword [rax + VMCB.rip], 0x7c00
	
	; Set up guest rsp
	mov qword [rax + VMCB.rsp], 0x7000

	; Set up guest rax
	mov qword [rax + VMCB.rax], 0

	; Save the hosts gs and fs
	mov  rbx, [gs:thread_local.gs_base]
	push rbx
	mov  rbx, [fs:globals.fs_base]
	push rbx

	mov edx, 0x80

.relaunch:
	mov  r8, [gs:thread_local.vm_ctxt + vm_ctxt.r8]
	mov  r9, [gs:thread_local.vm_ctxt + vm_ctxt.r9]
	mov r10, [gs:thread_local.vm_ctxt + vm_ctxt.r10]
	mov r11, [gs:thread_local.vm_ctxt + vm_ctxt.r11]
	mov r12, [gs:thread_local.vm_ctxt + vm_ctxt.r12]
	mov r13, [gs:thread_local.vm_ctxt + vm_ctxt.r13]
	mov r14, [gs:thread_local.vm_ctxt + vm_ctxt.r14]
	mov r15, [gs:thread_local.vm_ctxt + vm_ctxt.r15]

	push rdx
	mov  rdx, [gs:thread_local.guest_fs]
	call set_fs_base
	mov  rdx, [gs:thread_local.guest_gs]
	call set_gs_base
	pop  rdx

	clgi
	vmrun
	vmsave
	stgi

	push rbx
	push rdx

	call get_gs_base
	mov  rbx, rdx
	mov  rdx, [rsp + 0x18]
	call set_gs_base
	mov  [gs:thread_local.guest_gs], rbx

	call get_fs_base
	mov  rbx, rdx
	mov  rdx, [rsp + 0x10]
	call set_fs_base
	mov  [gs:thread_local.guest_fs], rbx

	pop  rdx
	pop  rbx

	push rbx
	push rcx
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rbx], rbx
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rcx], rcx
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rdx], rdx
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rsi], rsi
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rdi], rdi
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rbp], rbp
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.r8],  r8
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.r9],  r9
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.r10], r10
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.r11], r11
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.r12], r12
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.r13], r13
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.r14], r14
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.r15], r15
	mov  rbx, [rax + VMCB.rax]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rax], rbx
	mov  rbx, [rax + VMCB.rsp]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rsp], rbx
	mov  rbx, [rax + VMCB.rip]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rip], rbx
	mov  rbx, [rax + VMCB.rfl]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rfl], rbx

	mov  rbx, [rax + VMCB.cr0]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.cr0], rbx
	mov  rbx, [rax + VMCB.cr2]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.cr2], rbx
	mov  rbx, [rax + VMCB.cr3]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.cr3], rbx
	mov  rbx, [rax + VMCB.cr4]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.cr4], rbx

	mov  dword [gs:thread_local.vm_ctxt + vm_ctxt.magic], VM_STATE_DUMP

	mov  rbx, [rax + VMCB.exitcode]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.vec], rbx
	mov  rbx, [rax + VMCB.exitinfo1]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.ei1], rbx
	mov  rbx, [rax + VMCB.exitinfo2]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.ei2], rbx
	mov  rbx, [rax + VMCB.exitintinfo]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.eii], rbx
	pop  rcx
	pop  rbx

	cmp qword [rax + VMCB.exitcode], 0x41 ; Check for #DE
	jne .not_debug

	; Check if breakpoint #0 is enabled
	bt  qword [rax + VMCB.dr7], 0
	jnc short .inject_debug

	; Check if breakpoint #1 is enabled
	bt  qword [rax + VMCB.dr7], 2
	jnc short .inject_debug

	; Check if breakpoint #1 contains our magic number
	push r10
	push r11
	mov  r10, dr1
	mov  r11, 0x0000133713371337
	cmp  r10, r11
	pop  r11
	pop  r10
	jne  short .inject_debug

	cmp r8, 0x10000
	jne short .inject_debug

	jmp save_vm_snapshot

.inject_debug:
	; Inject valid, exception, vector #1 (#DB)
	push r10
	mov  r10, (1 << 31) | (3 << 8) | 1
	mov  qword [rax + VMCB.eventinj], r10
	pop  r10

	jmp .relaunch

.not_debug:
	cmp qword [rax + VMCB.exitcode], 0x75
	jne .ded

	; If protected mode is enabled, disable hooks
	bt qword [rax + VMCB.cr0], 0
	jc .inject_swint

	; Capture disk interrupts
	cmp qword [rax + VMCB.exitinfo1], 0x13
	je  .process_int13

	; Capture system address map shit
	cmp qword [rax + VMCB.exitinfo1], 0x15
	je  .process_int15

	; Capture timer shit
	cmp qword [rax + VMCB.exitinfo1], 0x1a
	je  .process_int1a

	jmp .inject_swint

.process_int1a:
	mov cx, word [rel .tick_counter + 2]
	mov dx, word [rel .tick_counter + 0]
	inc dword [rel .tick_counter]

	add qword [rax + VMCB.rip], 2 ; Increment rip
	jmp .relaunch

.tick_counter: dd 0

.process_int15:
	push rax
	mov  rax, [rax + VMCB.rax]
	cmp  eax, 0xE820
	pop  rax
	jne  .inject_swint

	; Bounds check our continuation
	cmp ebx, 0x4
	ja  .ded

	; Get the internal map entry
	imul r14d, ebx, 0x20
	lea   r15, [rel .int15_map]
	add   r14, r15

	; Get the address to write to
	movzx r12, word [rax + VMCB.es_sel]
	movzx r13, di
	shl   r12, 4
	add   r12, r13

	push rax
	push rbx
	push rcx
	push rdx

	; Get a mapping to the guests buffer we fill
	mov  rbx, r12
	mov  rcx, 20
	mov  rdx, [rax + VMCB.n_cr3]
	call mm_linear_map

	; Base address
	mov rbx, qword [r14 + 0x00]
	mov qword [rax], rbx
	
	; Length
	mov rbx, qword [r14 + 0x08]
	mov qword [rax + 0x8], rbx
	
	; Type
	mov ebx, dword [r14 + 0x10]
	mov dword [rax + 0x10], ebx

	pop  rdx
	pop  rcx
	pop  rbx
	pop  rax

	; Continuation
	mov ebx, dword [r14 + 0x18]

	mov ecx, 20
	mov dword [rax + VMCB.rax], 'PAMS'
	btr qword [rax + VMCB.rfl], 0 ; Zero cf to signify success
	add qword [rax + VMCB.rip], 2 ; Increment rip
	jmp .relaunch

.int15_map:
	; start, end, avail, continuation
	dq 0x00000000, 0x0009a000, 0x1, 0x1
	dq 0x00100000, 0x00600000, 0x1, 0x2
	dq 0x00d10000, 0x000f0000, 0x1, 0x3
	dq 0x00e10000, 0xd706f000, 0x1, 0x0

.process_int13:
	push rbx
	mov  rbx, qword [rax + VMCB.rax]
	cmp  bh, 0x41
	pop  rbx
	jne short .next

	; Report that we support INT 13 extensions 1.x
	mov bx, 0xAA55
	mov cx, 0x3
	btr qword [rax + VMCB.rfl], 0
	mov qword [rax + VMCB.rax], 0x0100

	add qword [rax + VMCB.rip], 2
	jmp .relaunch

.next:
	push rbx
	mov  rbx, qword [rax + VMCB.rax]
	cmp  bh, 0x02
	pop  rbx
	jne  .next2

	; Handle INT 13,2 - Read Disk Sectors
	; AH = 02
	; AL - Num sectors to read
	; CH - track (0-1023)
	; CL - Sector (1-63)
	; DH - Head number (0-15)
	; DL - Drive number
	; ES:BX buffer
	;
	; CHS -> LBA: (c * 16 + h) * 63 + (s - 1)
	;
	; Ret:
	; AH - status (0 is good)
	; AL - # sectors read
	; CF - 0 on success 1 on failure

	push rax
	mov  rax, qword [rax + VMCB.rax]

	; Calculate LBA
	bextr r10, rcx, 0x0808 ; Get CH into r10 (cylinder)
	imul  r10, 2
	bextr r11, rdx, 0x0808 ; Get DH into r11 (head)
	add   r10, r11
	imul  r10, 18
	movzx r11, cl          ; Get CL into r11 (sector)
	dec   r11
	add   r10, r11
	imul  r10, 512

	; Get the size in bytes
	movzx r11, al
	imul  r11, 512

	pop rax

	; Get the address to read to
	movzx r12, word [rax + VMCB.es_sel]
	movzx r13, bx
	shl   r12, 4
	add   r12, r13

	; r10 now contains the byte offset to read
	; r11 now contains the number of bytes to read
	; r12 now contains the guest physical address to copy to

.process_disk_read:
	push rax
	push rbx
	push rcx
	push rdx

	; Map in the number of bytes we need to copy into the guest
	mov  rbx, r12
	mov  rcx, r11
	mov  rdx, qword [rax + VMCB.n_cr3]
	call mm_linear_map

	; Convert number of bytes to sectors
	shr r10, 9
	shr r11, 9

.for_each_sector:
	mov  rbx, r10
	mov   cx, 1
	mov   r8, rax
	call ide_pio_read_sectors

	inc r10
	add rax, 512
	dec r11
	jnz short .for_each_sector

	pop  rdx
	pop  rcx
	pop  rbx
	pop  rax

	mov qword [rax + VMCB.rax], r11
	btr qword [rax + VMCB.rfl], 0   ; Zero cf to signify success
	add qword [rax + VMCB.rip], 2   ; Increment rip
	jmp .relaunch

.next2:
	push rbx
	mov  rbx, qword [rax + VMCB.rax]
	cmp  bh, 0x42
	pop  rbx
	jne  .next3

	; Handle Int 13,42 - Extended read
	; AH    - 42
	; dl    - drive number
	; ds:si - disk address packet

	; Get the address of the data packet
	movzx r12, word [rax + VMCB.ds_sel]
	movzx r13, si
	shl   r12, 4
	add   r12, r13

	; Get the size, length, and dest. Then we pass it on to the INT 0x13,2
	; internal handler
	push rax
	push rbx
	push rcx
	push rdx

	mov  rbx, r12
	mov  rcx, 0x10
	mov  rdx, qword [rax + VMCB.n_cr3]
	call mm_linear_map

	mov    r10, qword [rax + 0x08] ; Sector to read
	movzx  r11,  word [rax + 0x02] ; Number of sectors to read
	imul   r10, 512
	imul   r11, 512

	; Get the address to read to
	movzx r12, word [rax + 0x06] ; Segment
	movzx r13, word [rax + 0x04] ; Offset
	shl   r12, 4
	add   r12, r13

	pop rdx
	pop rcx
	pop rbx
	pop rax

	jmp .process_disk_read

.next3:
	push rbx
	mov  rbx, qword [rax + VMCB.rax]
	cmp  bh, 0x48
	pop  rbx
	jne  .next4

	; Handle Int 13,48 - Get drive parameters
	; ah    - 48
	; dl    - Drive
	; ds:si - Buffer to recieve drive parameters

	; Get the address of the param rx buffer
	movzx r12, word [rax + VMCB.ds_sel]
	movzx r13, si
	shl   r12, 4
	add   r12, r13

	push rax
	push rbx
	push rcx
	push rdx

	mov  rbx, r12
	mov  rcx, 0x1a
	mov  rdx, qword [rax + VMCB.n_cr3]
	call mm_linear_map

	mov  word [rax + 0x00], 0x001A   ; Size of buffer (0x1a for v1.x)
	mov  word [rax + 0x02], 0x0000   ; Information flags (CHS valid, removable)
	mov dword [rax + 0x04], 0        ; # of cylinders on drive
	mov dword [rax + 0x08], 0        ; # of heads on drive
	mov dword [rax + 0x0c], 0        ; # of sectors per track
	mov rbx, (8 * 1024 * 1024 * 1024) / 512
	mov qword [rax + 0x10], rbx      ; Total # sectors
	mov  word [rax + 0x18], 512      ; Bytes per sector

	pop rdx
	pop rcx
	pop rbx
	pop rax

	mov qword [rax + VMCB.rax], 0 ; Zero rax
	btr qword [rax + VMCB.rfl], 0 ; Zero cf to signify success
	add qword [rax + VMCB.rip], 2 ; Increment rip
	jmp .relaunch

.next4:
	push rbx
	mov  rbx, qword [rax + VMCB.rax]
	cmp  bh, 0x08
	pop  rbx
	jne  .next5

	mov qword [rax + VMCB.rax], 0
	mov ecx, 0xffff
	mov edx, 0xfe01
	mov ebx, 0x0000

	btr qword [rax + VMCB.rfl], 0 ; Zero cf to signify success
	add qword [rax + VMCB.rip], 2 ; Increment rip
	jmp .relaunch

.next5:
	push rbx
	mov  rbx, qword [rax + VMCB.rax]
	cmp  bh, 0x15
	pop  rbx
	jne  .next6

	mov qword [rax + VMCB.rax], 0x0300 ; We're a fixed disk
	mov cx, 0xfa
	mov dx, 0xc53f

	btr qword [rax + VMCB.rfl], 0 ; Zero cf to signify success
	add qword [rax + VMCB.rip], 2 ; Increment rip
	jmp .relaunch

.next6:
	push rbx
	mov  rbx, qword [rax + VMCB.rax]
	cmp  bh, 0x43
	pop  rbx
	jne  .ded

	mov qword [rax + VMCB.rax], 0 ; Zero out rax
	btr qword [rax + VMCB.rfl], 0 ; Zero cf to signify success
	add qword [rax + VMCB.rip], 2 ; Increment rip
	jmp .relaunch

.inject_swint:
	; Create a pending SW int injection with the vector we got and no error code
	push r10
	mov  r10, (1 << 31) | (4 << 8)
	or   r10, qword [rax + VMCB.exitinfo1]
	mov  qword [rax + VMCB.eventinj], r10
	pop  r10
	jmp  .relaunch

.ded:
	call dump_vm_state

	cli
	hlt

dump_vm_state:
	push rbx
	push rcx

	mov  rbx, [gs:thread_local.gs_base]
	lea  rbx, [rbx + thread_local.vm_ctxt]
	mov  rcx, vm_ctxt_size
	call i825xx_send_packet

	pop rcx
	pop rbx
	ret

; rdx -> gs base to set
set_gs_base:
	push rax
	push rbx
	push rcx
	push rdx

	mov   rbx, rdx
	mov   eax, ebx
	bextr rdx, rbx, 0x2020
	mov   ecx, 0xC0000101
	wrmsr

	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; rdx <- current gs base
get_gs_base:
	push rax
	push rbx
	push rcx

	; Save off the guest GS
	push rax
	mov  ecx, 0xC0000101
	rdmsr
	shl  rdx, 32
	or   rdx, rax
	pop  rax

	pop rcx
	pop rbx
	pop rax
	ret

; rdx -> fs base to set
set_fs_base:
	push rax
	push rbx
	push rcx
	push rdx

	mov   rbx, rdx
	mov   eax, ebx
	bextr rdx, rbx, 0x2020
	mov   ecx, 0xC0000100  ; FS.base MSR
	wrmsr

	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; rdx <- current fs base
get_fs_base:
	push rax
	push rbx
	push rcx

	; Save off the guest FS
	push rax
	mov  ecx, 0xC0000100
	rdmsr
	shl  rdx, 32
	or   rdx, rax
	pop  rax

	pop rcx
	pop rbx
	pop rax
	ret

struc VMCB
	.CR_icpt:       resd 1  ; 0x000
	.DR_icpt:       resd 1  ; 0x004
	.except_icpt:   resd 1  ; 0x008
	.icpt_set_1:    resd 1  ; 0x00c
	.icpt_set_2:    resd 1  ; 0x010
	.reserved_1:    resd 10 ; 0x014
	.pause_flt_thr: resw 1  ; 0x03c
	.pause_flt_cnt: resw 1  ; 0x03e
	.iopm:          resq 1  ; 0x040
	.msrpm:         resq 1  ; 0x048
	.tsc_offset:    resq 1  ; 0x050
	.tlb_and_asid:  resq 1  ; 0x058
	.vint:          resq 1  ; 0x060
	.int_shadow:    resq 1  ; 0x068
	.exitcode:      resq 1  ; 0x070
	.exitinfo1:     resq 1  ; 0x078
	.exitinfo2:     resq 1  ; 0x080
	.exitintinfo:   resq 1  ; 0x088
	.np_enable:     resq 1  ; 0x090
	.avic_apic:     resq 1  ; 0x098
	.reserved_2:    resd 2  ; 0x0a0
	.eventinj:      resq 1  ; 0x0a8
	.n_cr3:         resq 1  ; 0x0b0
	.lbr_virt_en:   resq 1  ; 0x0b8
	.vmcb_clean:    resq 1  ; 0x0c0
	.nrip:          resq 1  ; 0x0c8
	.guest_inst:    resq 2  ; 0x0d8
	.apic_backing:  resq 1  ; 0x0e0
	.reserved_3:    resq 1  ; 0x0e8
	.logical_table: resq 1  ; 0x0f0
	.avig_phys_tbl: resq 1  ; 0x0f8

	.reserved_4:    resb 0x300

	.es_sel:    resw 1
	.es_attrib: resw 1
	.es_limit:  resd 1
	.es_base:   resq 1

	.cs_sel:    resw 1
	.cs_attrib: resw 1
	.cs_limit:  resd 1
	.cs_base:   resq 1

	.ss_sel:    resw 1
	.ss_attrib: resw 1
	.ss_limit:  resd 1
	.ss_base:   resq 1

	.ds_sel:    resw 1
	.ds_attrib: resw 1
	.ds_limit:  resd 1
	.ds_base:   resq 1

	.fs_sel:    resw 1
	.fs_attrib: resw 1
	.fs_limit:  resd 1
	.fs_base:   resq 1

	.gs_sel:    resw 1
	.gs_attrib: resw 1
	.gs_limit:  resd 1
	.gs_base:   resq 1

	.gdtr_sel:    resw 1
	.gdtr_attrib: resw 1
	.gdtr_limit:  resd 1
	.gdtr_base:   resq 1
	
	.ldtr_sel:    resw 1
	.ldtr_attrib: resw 1
	.ldtr_limit:  resd 1
	.ldtr_base:   resq 1

	.idtr_sel:    resw 1
	.idtr_attrib: resw 1
	.idtr_limit:  resd 1
	.idtr_base:   resq 1

	.tr_sel:    resw 1
	.tr_attrib: resw 1
	.tr_limit:  resd 1
	.tr_base:   resq 1

	.reserved_5: resb 0x2b

	.cpl: resb 1

	.reserved_6: resd 1

	.efer: resq 1

	.reserved_7: resb 0x70

	.cr4: resq 1
	.cr3: resq 1
	.cr0: resq 1
	.dr7: resq 1
	.dr6: resq 1
	.rfl: resq 1
	.rip: resq 1

	.reserved_8: resb 0x58

	.rsp: resq 1

	.reserved_9: resb 0x18

	.rax: resq 1

	.star:         resq 1
	.lstar:        resq 1
	.cstar:        resq 1
	.sfmask:       resq 1
	.kern_gs_base: resq 1

	.sysenter_cs:  resq 1
	.sysenter_esp: resq 1
	.sysenter_eip: resq 1

	.cr2: resq 1

	.reserved_a: resb 0x20

	.g_pat:            resq 1
	.dbgctrl:          resq 1
	.br_from:          resq 1
	.br_to:            resq 1
	.last_except_from: resq 1
	.last_except_to:   resq 1
endstruc

