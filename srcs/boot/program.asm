[bits 64]

; -----------------------------------------------------------------------------
; FUZZ CONFIGURATION
; -----------------------------------------------------------------------------

; SNAPSHOT_MODE is defined when we want to boot into windows and take a
; snapshot. If this is not defined, then we pull a snapshot over the network
; and start fuzzing!
%define SNAPSHOT_MODE

%define VM_MEMORY_SIZE (4 * 1024 * 1024 * 1024)
%define VM_MAX_PAGES   (VM_MEMORY_SIZE / 4096)

%define FUZZ_STATUS_MAGIC 0xdd1eba7c
%define EOFC_STATE_MAGIC  0x746306fa
%define CC_MAGIC          0xabd30d5b

%define MAX_FUZZ_INPUT_SIZE (256 * 1024 * 1024)

; IBS @ 50000 takes 710175 cycles
; IBS @ 5000  takes  73070 cycles
; IBS @ 500   takes  10410 cycles
;
; ENABLE_IBS * 16                = number of cycles
; 2400000000 / (ENABLE_IBS * 16) = number of IBSes per second

; Number of microseconds to run for
%define TIMEOUT_US (1 * 1000 * 1000)

;%define ENABLE_LOGGING
%define ENABLE_IBS 1024 ; ~75k per second per core @ 1024
%define ENABLE_IBS_CC
;%define ENABLE_LWP_CC
%define ENABLE_FUZZING
%define ENABLE_COVERAGE_FEEDBACK
%define ENABLE_LBR
%define ENABLE_TIMER
%define ENABLE_CRASH_FEEDBACK
;%define ENABLE_MINIMIZE
;%define ENABLE_INVALIDATE_STACK_ON_TIMERS
;%define ENABLE_EOFC

;%define ENABLE_DISK

%define ENABLE_SINGLE_SNAPSHOT   ; Only use one snapshot image
;%define ENABLE_SINGLE_STEP       ; Single step guest instructions
;%define ENABLE_SINGLE_RUN        ; Execute one test case
;%define ENABLE_SINGLE_CORE       ; Disable all but one core
;%define ENABLE_REPORT_ALL_VMEXIT ; Every #VMEXIT gets transmit over the network

%define MIN_FUZZ_SIZE (4 * 1024)

;%define ENABLE_SERVICING

%define LEAST_COMMON_TRIES 64

; Number of bytes at the start of the RTF to leave alone
%define DONT_CORRUPT_FIRST 64

%define CW_FUZZ
%define BRACKET_FUZZ

; -----------------------------------------------------------------------------
; END FUZZ CONFIGURATION
; -----------------------------------------------------------------------------

%define SPINLOCK_MINIMIZE 0
%define SPINLOCK_FALKTP   1
%define SPINLOCK_VMINIT   2
%define SPINLOCK_DISK     3
%define SPINLOCK_VMALC    4

%define SPINLOCK_NUM 5

; This can be accessed by the FS segment.
struc globals
	.fs_base: resq 1 ; Virtual address of this globals block

	.bamp_addr: resq MAX_NODES
	.bamp_ends: resq MAX_NODES

	.rdtsc_freq: resq 1 ; Frequency that rdtsc increments at in MHz

	.next_free_vaddr: resq 1

	.per_node_kern_code: resb node_struct_size

	.x540_mmio_base: resq 1

	.per_node_snapshot: resb node_struct_size
	.per_node_pdfs:     resb node_struct_size
	.per_node_pdfmaps:  resb node_struct_size

	.i825xx_dev:          resb i825xx_dev_size
	.hw_mac_address:      resb 8
	.i825xx_tx_lock:      resq 1
	.i825xx_tx_release:   resq 1
	.i825xx_rx_poll_lock: resq 1

	.falktp_lock:    resq 1
	.falktp_release: resq 1

	.vm_snapshot:     resq 1
	.vm_snapshot_mem: resq 1

	.vms_fuzzing:  resq 1
	.stop_fuzzing: resq 1

	.fuzz_status: resb fuzz_status_size
	
	.per_node_fuzzdat: resb node_struct_size

	.crash_flut:    resq 1

	.coverage_fht: resq 1
	.input_fht:    resq 1

	.minimize_input:      resq 1
	.minimize_input_bcrp: resq 1
	.minimize_input_null: resq 1

	.spinlocks_lock:    resq SPINLOCK_NUM
	.spinlocks_release: resq SPINLOCK_NUM
endstruc

struc fuzz_status
	.magic: resd 1

	.fuzz_cases:       resq 1 ; Number of fuzz cases
	.fuzz_timeout:     resq 1 ; Number of fuzz case timeouts
	.fuzz_io:          resq 1 ; Number of fuzz cases ending in MMIO or IO or INTs
	.num_unique_bb:    resq 1 ; Number of unique basic blocks
	.num_timers:       resq 1 ; Number of NMI timers which fired in the VM
	.num_crashes:      resq 1 ; Number of crashes
	.num_uniq_crashes: resq 1 ; Number of crashes deemed 'unique'

	.time_restore: resq 1 ; Number of clock cycles spent restoring VM state
	.time_corrupt: resq 1 ; Number of clock cycles spent corrupting RTFs
	.time_running: resq 1 ; Number of clock cycles spent running VM
	.time_coverag: resq 1 ; Number of clock cycles spent doing coverage
	.time_total:   resq 1 ; Number of clock cycles spent this fuzz case

	.alloc_charge: resq 8 ; Number of bytes allocated per node

	.pc_fc: resq NUM_CORES ; Per core fuzz cases
endstruc

struc thread_local
	.gs_base: resq 1 ; Virtual address of this thread local block

	.node_id: resq 1 ; Actual node ID that this core resides in
	.core_id: resq 1 ; Unique ID for this core (might not match APIC ID)
	                 ; This ID is from [0, num_cores)

	.VMCB: resq 1

	.x540_tx_ring_base: resq 1 ; Base of the TX ring tail
	.x540_tx_tail:      resq 1 ; Transmit tail
	.cur_port:          resq 1 ; Next port to transmit on. We transmit around
	                           ; a ring to distribute work load.
	.x540_rx_ring_base: resq 1 ; Base of the RX ring tail
	.x540_rx_head:      resq 1 ; RX head. This points to the next packet which
	                           ; we have not processed yet.
	.x540_packets_rx:   resq 1 ; Number of packets we have rxed on this core.

	.lwpcb:    resq 1
	.lwp_back: resq 1
	.pml4:     resq 1

	.xs_seed: resq 2

	.phys_4k_freelist: resq 1

	.guest_gs: resq 1
	.guest_fs: resq 1

	.pkt:      resq 1
	.os_state: resq 1
	.cur_samp: resq 1
	.vm_ctxt:  resb vm_ctxt_size

	.ioio:    resq 1
	.vm_ncr3: resq 1

	.fuzz_input:     resq 1
	.fuzz_maps:      resq 1
	.fuzz_input_len: resq 1

	.exhaust:         resq 1
	.fuzz_start_time: resq 1
	.elapsed:         resq 1

	.snapshot: resq 1

	.flut_pages:     resq 1
	.flut_pages_rem: resq 1

	.time_log: resq 1

	; Set this to nonzero if you want to report the result of the fuzz case
	; regardless of if it crashes.
	.force_report: resq 1
	.reported:     resq 1 ; Used to track reports so we dont double report

	.time_restore: resq 1 ; Number of clock cycles spent restoring VM state
	.time_corrupt: resq 1 ; Number of clock cycles spent corrupting RTFs
	.time_running: resq 1 ; Number of clock cycles spent running VM
	.time_coverag: resq 1 ; Number of clock cycles spent doing coverage
	.time_total:   resq 1 ; Number of clock cycles spent this fuzz case

	.fuzz_size: resq 1 ; File size to use for fuzzing, by providing a large
	                   ; base input template, we can then fuzz various
	                   ; sizes by only corrupting the starting fuzz_size bytes

	.modlist:       resq MAX_NUM_MODULES ; Pointer to modlist
	.modlist_count: resq 1               ; Number of entries in the modlist
	
	.ide_emu_state: resb ide_emu_state_size
endstruc

struc vm_ctxt
	.magic: resd 1


	.nod: resq 1

	.vec: resq 1
	.ei1: resq 1
	.ei2: resq 1
	.eii: resq 1
	.tim: resq 1

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

	.cid:  resq 2
	.bcrp: resq 1

	.n_cr3: resq 1

	.modlen: resq 1
	.modoff: resq 1
	.module: resb 512
	.stack:  resb 512
endstruc

struc crash_ent
	.hash: resq 2 ; Hash of the crashing input
	.seen: resq 1 ; Bit mask of nodes which have seen this crash
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

	; physical memory size of this snapshot
	.pmem_size: resq 1

	alignb 4096
	.xsave: resb 0x3C0 ; This length is processor specific!!! This is designed
	                   ; for AMD fam15h00-0f CPUs

	alignb 4096
	.vmcb:  resb 4096  ; Entire VMCB after the vm exits and a vmsave occurs
	                   ; Things like n_cr3 need to be rebuilt

	alignb 4096
	.physical_memory: ; All physical memory
endstruc

struc bb_struc
	.input_hash: resq 2
	.count:      resq 1
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

struc cc_report
	.magic:    resd 1

	.from_sym: resb 512
	.from_len: resq 1
	.from_off: resq 1

	.to_sym:   resb 512
	.to_len:   resq 1
	.to_off:   resq 1
endstruc

struc access_report
	.magic: resd 1

	.offs: resq 1
	.rip:  resq 1
endstruc

struc input_entry
	.len:   resq 1
	.input: resq 1
	.maps:  resq 1
endstruc

struc lwpcb
	.flags:   resd 1 ; Flags
	.bufsize: resd 1 ; BufferSize
	.bufbase: resq 1 ; BufferBase
	.head:    resd 1 ; BufferHeadOffset
	.rsvd1:   resd 1
	.missed:  resq 1 ; Missed events
	.thresh:  resd 1 ; Threshold
	.filters: resd 1 ; Filters
	.baseip:  resq 1 ; BaseIP
	.limitip: resq 1 ; LimitIP
	.rsvd2:   resq 1
	.tail:    resd 1 ; Tail
	.rsvd3:   resd 1
	.usr1:    resq 1 ; Reserved for software
	.usr2:    resq 1 ; Reserved for software
	.rsvd4:   resq 5

	.evt1int: resd 1
	.evt1ctr: resd 1
	.evt2int: resd 1
	.evt2ctr: resd 1
	.evt3int: resd 1
	.evt3ctr: resd 1
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
	test rax, rax
%ifndef SNAPSHOT_MODE
%ifdef ENABLE_SINGLE_CORE
	jnz halt
%else
	jnz do_thread_shit
%endif
%else
	jnz halt
%endif

	call init_hdd

%ifndef SNAPSHOT_MODE
	; Get the snapshot
	mov  r13, 0x8000000001230000
	call falktp_pull
	mov  rbx, [fs:globals.fs_base]
	lea  rbx, [rbx + globals.per_node_snapshot]
	call init_node_data

	; Get the pdfs
	mov  r13, 0x8000000000000012
	call falktp_pull
	mov  rbx, [fs:globals.fs_base]
	lea  rbx, [rbx + globals.per_node_pdfs]
	call init_node_data

	; Get the pdfmaps
	mov  r13, 0x8000000000000013
	call falktp_pull
	mov  rbx, [fs:globals.fs_base]
	lea  rbx, [rbx + globals.per_node_pdfmaps]
	call init_node_data
	
	mov  rcx, 28
	call fht_create
	mov  qword [fs:globals.coverage_fht], rcx

	mov  rcx, 28
	call fht_create
	mov  qword [fs:globals.input_fht], rcx
%endif ; SNAPSHOT_MODE

%ifdef ENABLE_CRASH_FEEDBACK
	call alloc_zero_4k
	mov  qword [fs:globals.crash_flut], rax
%endif

%ifdef SNAPSHOT_MODE
	call init_launch_svm
%else
	mov  rdi, 0xb8000
	mov  rdx, 0x8008
	call outhexq

	mov qword [fs:globals.vms_fuzzing], 1
	call do_thread_shit
%endif

halt:
	cli
	hlt
	jmp short halt

init_launch_svm:
	call init_svm
	call launch_svm
	ret

do_thread_shit:
	call init_svm
	call launch_snapshot_vm

	jmp halt

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

; rsi -> File A
; rdi -> File B
; rcx -> Length to compare (in bytes)
; rax <- Number of unmatching quadwords
diff:
	push rbx
	push rcx
	push rsi
	push rdi

	xor rax, rax

	shr  rcx, 3
	test rcx, rcx
	jz   short .end

.lewp:
	mov rbx, qword [rsi]
	cmp rbx, qword [rdi]
	je  short .next

	inc rax

.next:
	add rsi, 8
	add rdi, 8
	dec rcx
	jnz short .lewp

.end:
	pop rdi
	pop rsi
	pop rcx
	pop rbx
	ret

start_lwp:
	push rax
	push rbx
	push rcx
	push rdx
	push rdi
	push rsi
	push r15

	mov  rdx, qword [gs:thread_local.lwp_back]
	test rdx, rdx
	jnz  short .have_lwp_back

	mov  rcx, SPINLOCK_VMALC
	call acquire_spinlock

	; Allocate room in the guset virtual memory for the lwpcb
	mov  rcx, 4096
	call mm_guest_allocate_virt
	mov  qword [gs:thread_local.lwpcb], rcx

	; ALlocate room on the guest virtual memory for the lwp backing buffer
	mov  rcx, (128 * 1024 * 1024)
	call mm_guest_allocate_virt
	mov  qword [gs:thread_local.lwp_back], rcx

	; Since the above operations changed the page table, and we don't want the
	; change to get reset, manually save the pml4.
	mov  rax, [gs:thread_local.VMCB]
	mov  rbx, [rax + VMCB.cr3]
	mov  rdx, [rax + VMCB.n_cr3]
	call mm_get_phys
	mov  rsi, rax
	mov  rdi, [gs:thread_local.pml4]
	mov  rcx, (4096 / 8)
	rep  movsq
	
	mov  rcx, SPINLOCK_VMALC
	call release_spinlock

	jmp .enable

.have_lwp_back:
.enable:
	; Manually restore the pml4
	mov  rax, [gs:thread_local.VMCB]
	mov  rbx, [rax + VMCB.cr3]
	mov  rdx, [rax + VMCB.n_cr3]
	call mm_get_phys_with_cow
	mov  rdi, rax
	mov  rsi, [gs:thread_local.pml4]
	mov  rcx, (4096 / 8)
	rep  movsq

	mov rcx, qword [gs:thread_local.lwpcb]
	mov rdx, qword [gs:thread_local.lwp_back]

	mov dword [rcx + lwpcb.flags],   (1 << 3)
	mov dword [rcx + lwpcb.bufsize], (128 * 1024 * 1024) | (6 << 28)
	mov qword [rcx + lwpcb.bufbase], rdx
	mov dword [rcx + lwpcb.head],    0
	mov qword [rcx + lwpcb.missed],  0
	mov dword [rcx + lwpcb.thresh],  0
	mov dword [rcx + lwpcb.filters], 0
	mov qword [rcx + lwpcb.baseip],  0
	mov qword [rcx + lwpcb.limitip], 0
	mov dword [rcx + lwpcb.tail],    0

	mov dword [rcx + lwpcb.evt1int], 0
	mov dword [rcx + lwpcb.evt1ctr], 0
	mov dword [rcx + lwpcb.evt2int], 0
	mov dword [rcx + lwpcb.evt2ctr], 0

	call xorshift64
	and  r15, 0xff
	mov  dword [rcx + lwpcb.evt3int], 0
	mov  dword [rcx + lwpcb.evt3ctr], r15d

	llwpcb rcx

	pop r15
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

struc lwp_ent
	.eventid:   resb 1
	.coreid:    resb 1
	.reserved:  resb 6
	.src_ip:    resq 1
	.dest_ip:   resq 1
	.timestamp: resq 1
endstruc

; Perform coverage information with lwp
lwp_coverage:
	push rbx
	push rcx
	push rdx
	push rbp
	push rsi
	push rdi

	XMMPUSH xmm5
	XMMPUSH xmm6

%ifdef ENABLE_LOGGING
	call start_log
%endif

	slwpcb rcx
	mov rdx, qword [rcx + lwpcb.bufbase]
	mov ebp, dword [rcx + lwpcb.head]
	shr rbp, 5

	; rcx - Pointer to lwpcb
	; rdx - Pointer to backing lwp buffer
	; rbp - Number of entries in the lwp buffer

	test rbp, rbp
	jz   .done

.lewp:
	; If the event ID is not a branch retired event, panic.
	cmp byte [rdx + lwp_ent.eventid], 0x03
	jne panic

	mov rsi, qword [rdx + lwp_ent.src_ip]
	mov rdi, qword [rdx + lwp_ent.dest_ip]

	mov    rbx, rdi
	call   win32_symhash
	movdqa xmm6, xmm5
	mov    rbx, rsi
	call   win32_symhash
	aesenc xmm5, xmm6

	; Look up this edge in the coverage fht
	mov  rcx, qword [fs:globals.coverage_fht]
	call fht_fetch_or_lock
	jnc  .already_present

	; Place this fuzz image input database
	call input_create_entry

	; Allocate room for the bb_struc which describes the input hash and count
	mov rbx, bb_struc_size
	rand_alloc rbx
	mov qword [rbx + bb_struc.count],      0
	movdqu    [rbx + bb_struc.input_hash], xmm5

	; Place this bb_struc in the coverage flut
	mov qword [rcx], rbx

	; Move the bb_struc to rcx, as we increment the count below
	mov rcx, rbx

	push rbx
	push rcx
	push rsi
	push rdi
	push rbp
	sub  rsp, cc_report_size

	mov  rbx, qword [rdx + lwp_ent.src_ip]
	call win32_resolve_symbol
	test rbp, rbp
	jz   short .cant_report_cc
	mov  [rsp + cc_report.from_off], rbx
	mov  rbx, [rbp + modlist.namelen]
	mov  [rsp + cc_report.from_len], rbx
	lea  rsi, [rbp + modlist.name]
	lea  rdi, [rsp + cc_report.from_sym]
	mov  rcx, 512
	rep  movsb

	mov  rbx, qword [rdx + lwp_ent.dest_ip]
	call win32_resolve_symbol
	test rbp, rbp
	jz   short .cant_report_cc
	mov  [rsp + cc_report.to_off], rbx
	mov  rbx, [rbp + modlist.namelen]
	mov  [rsp + cc_report.to_len], rbx
	lea  rsi, [rbp + modlist.name]
	lea  rdi, [rsp + cc_report.to_sym]
	mov  rcx, 512
	rep  movsb

	mov dword [rsp + cc_report.magic], CC_MAGIC

	mov  rbx, rsp
	mov  rcx, cc_report_size
	call x540_send_packet

.cant_report_cc:
	add rsp, cc_report_size
	pop rbp
	pop rdi
	pop rsi
	pop rcx
	pop rbx

	lock inc qword [fs:globals.fuzz_status + fuzz_status.num_unique_bb]

.already_present:
	inc qword [rcx + bb_struc.count]
.skip_entry:

	add rdx, lwp_ent_size
	dec rbp
	jnz .lewp

.done:
%ifdef ENABLE_LOGGING
	call stop_log
	add  qword [gs:thread_local.time_coverag], rdx
%endif

	XMMPOP xmm6
	XMMPOP xmm5

	pop rdi
	pop rsi
	pop rbp
	pop rdx
	pop rcx
	pop rbx
	ret

; rsi -> File A
; rcx -> Length to compare (in bytes)
; rax <- Number of bytes which are zero at the end of the f ile
trailnull:
	push rcx
	push rsi

	xor rax, rax

	test rcx, rcx
	jz   short .end

	; Seek to the last byte of the file
	lea rsi, [rsi + rcx - 1]

.for_bytes:
	cmp byte [rsi], 0
	jne short .end

	inc rax
	dec rsi
	dec rcx
	jnz short .for_bytes

.end:
	pop rsi
	pop rcx
	ret

; rsi -> File A
; rcx -> Length to compare (in bytes)
; rax <- Number of bytes which are zero
nullcount:
	push rcx
	push rsi

	xor rax, rax

	test rcx, rcx
	jz   short .end

.lewp:
	cmp byte [rsi], 0
	jne short .not_zero

	inc rax

.not_zero:
	inc rsi
	dec rcx
	jnz short .lewp

.end:
	pop rsi
	pop rcx
	ret

report_vm_context:
	push rax
	push rbx
	push rcx
	push rbp
	push rsi
	push rdi

	; Resolve the module
	mov  rbx, qword [gs:thread_local.vm_ctxt + vm_ctxt.rip]
	call win32_resolve_symbol
	mov  qword [gs:thread_local.vm_ctxt + vm_ctxt.modlen], 0
	mov  qword [gs:thread_local.vm_ctxt + vm_ctxt.modoff], rbx
	test rbp, rbp
	jz   short .no_module
	
	; There was a module, copy over the module name
	mov  rdi, [gs:thread_local.gs_base]
	lea  rdi, [rdi + thread_local.vm_ctxt + vm_ctxt.module]
	lea  rsi, [rbp + modlist.name]
	mov  rcx, 512
	rep  movsb
	mov  rcx, [rbp + modlist.namelen]
	mov  qword [gs:thread_local.vm_ctxt + vm_ctxt.modlen], rcx
.no_module:
	
	call get_current_node
	mov  qword [gs:thread_local.vm_ctxt + vm_ctxt.nod], rcx

	call rdtsc64
	mov  qword [gs:thread_local.vm_ctxt + vm_ctxt.tim], rax

	mov  rax, qword [gs:thread_local.VMCB]
	mov  rsi, qword [rax + VMCB.rsp]
	mov  rdi, [gs:thread_local.gs_base]
	lea  rdi, [rdi + thread_local.vm_ctxt + vm_ctxt.stack]
	mov  rcx, 512
	call mm_copy_from_guest_vm_vmcb

	; Send the context of the crash
	mov  rbx, [gs:thread_local.gs_base]
	lea  rbx, [rbx + thread_local.vm_ctxt]
	mov  rcx, vm_ctxt_size
	call x540_send_packet

	pop rdi
	pop rsi
	pop rbp
	pop rcx
	pop rbx
	pop rax
	ret

report_crash:
	push rax
	push rbx
	push rcx
	push rdx
	push rdi
	push rsi
	push rbp
	push r10
	push r11

	XMMPUSH xmm5

	cmp qword [gs:thread_local.reported], 0
	jne .already_reported

	; Calculate the shitsum for this fuzz case
	mov    rdi, qword [gs:thread_local.fuzz_input]
	mov    rsi, qword [gs:thread_local.fuzz_input_len]
	call   falkhash
	movdqu [gs:thread_local.vm_ctxt + vm_ctxt.cid], xmm5

	mov qword [gs:thread_local.vm_ctxt + vm_ctxt.bcrp], 0

	; Send this fuzz image
	mov  r10, qword [gs:thread_local.fuzz_input]
	mov  r11, qword [gs:thread_local.fuzz_input_len]
	call falktp_transmit

	call report_vm_context

	mov qword [gs:thread_local.reported], 1

.already_reported:
	XMMPOP xmm5

	pop r11
	pop r10
	pop rbp
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; Boot a simple guest OS
launch_snapshot_vm:
.wait_for_vm_start:
	pause
	cmp qword [fs:globals.vms_fuzzing], 0
	je  short .wait_for_vm_start

	call alloc_zero_4k
	mov  [gs:thread_local.pml4], rax

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
	mov  al, 0xff
	rep stosb

	mov rbx, MAX_FUZZ_INPUT_SIZE
	bamp_alloc rbx
	mov [gs:thread_local.fuzz_input], rbx

	mov rbx, MAX_FUZZ_INPUT_SIZE
	bamp_alloc rbx
	mov [gs:thread_local.fuzz_maps], rbx

	; Allocate room for the 4K VMCB structure

	; Allocate room for the 4K VMCB structure
	call alloc_zero_4k
	mov  [gs:thread_local.VMCB], rax

%ifdef ENABLE_TIMER
	; Divide by 128
	mov ebx, 0xFEE003E0
	mov dword [rbx], 0b1010

	; Enable timer on NMI with periodic operation
	mov ebx, 0xFEE00320
	mov dword [rbx], (0b100 << 8) | (1 << 17)

	; APIC Timer decrements at CLKIN, which seems to be about 200MHz
	mov ebx, 0xFEE00380
	mov dword [rbx], 100000
%endif

.wait_for_vm:
	pause
	cmp qword [fs:globals.vms_fuzzing], 0
	je  short .wait_for_vm

	push rax
	push rbx
	mov  rbx, [fs:globals.fs_base]
	lea  rbx, [rbx + globals.per_node_snapshot]
	call per_node_data
	mov  rsi, rax
	pop  rbx
	pop  rax

	mov [gs:thread_local.snapshot], rsi

	; -----------------------------------------------------------
	; Start loading cr3 with initial state
	; -----------------------------------------------------------

	; Create/reload cr3
	push rax
	push rsi

	; Allocate a guest ncr3
	call alloc_zero_4k
	mov  r15, rax

	; Get the physical address of the snapshot physical memory
	lea  rbx, [rsi + vm_snapshot.physical_memory]
	call bamp_get_phys
	mov  rsi, rax

	mov rbx, 0
	mov  r8, VM_MEMORY_SIZE
.lewp:
	call probe_memory_dest
	test rdx, rdx
	jnz  short .is_mmio_map

	call add_breakpoints

	lea  rbp, [rsi + 5] ; Map the original snapshot memory as R and U
	mov  rdx, r15
	call mm_map_4k

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

	mov qword [gs:thread_local.vm_ncr3], r15

	; Start the timer
	call rdtsc64
	mov  qword [gs:thread_local.time_total], rax

	; -----------------------------------------------------------
	; Fuzz loop starts here :)
	; -----------------------------------------------------------
.next_fuzz:
	; Update the time spent fuzzing
	call rdtsc64
	sub  rax, qword [gs:thread_local.time_total]
	lock add [fs:globals.fuzz_status + fuzz_status.time_total], rax

	mov  qword [gs:thread_local.time_restore], 0
	mov  qword [gs:thread_local.time_corrupt], 0
	mov  qword [gs:thread_local.time_running], 0
	mov  qword [gs:thread_local.time_coverag], 0
	mov  qword [gs:thread_local.time_total],   0
	mov  qword [gs:thread_local.force_report], 0
	mov  qword [gs:thread_local.reported],     0

	; Start the timer
	call rdtsc64
	mov  qword [gs:thread_local.time_total], rax

	; Place the pointer to the VMCB in rax
	mov rax, [gs:thread_local.VMCB]

	call start_log

	; Get the snapshot pointer
	push rax
	push rbx
	mov  rax, [gs:thread_local.snapshot]
	lea  rbx, [rax + vm_snapshot.physical_memory]
	call bamp_get_phys
	mov  rsi, rax
	pop  rbx
	pop  rax

	mov  rdx, qword [gs:thread_local.vm_ncr3]
	lea  rbp, [rel restore_page]
	call mm_for_each_dirty_4k

	call stop_log
	add  qword [gs:thread_local.time_restore], rdx

	; Get the snapshot pointer
	mov rsi, [gs:thread_local.snapshot]

	; Copy the snapshot vmcb here
	push rsi
	lea  rsi, [rsi + vm_snapshot.vmcb]
	mov  rdi, rax
	mov  rcx, 4096 / 8
	rep  movsq
	pop  rsi

	; Intercept ins and outs, all interrupts, halts, FERR_FREEZE, and shutdowns
	mov dword [rax + VMCB.icpt_set_1], (1 << 30) | (1 << 27) | (1 << 31) | (1 << 24) | 0x1f

	; Intercept writes to CR3
	mov dword [rax + VMCB.CR_icpt], ((1 << 3) << 16)

	; Intercept all VM operations and all monitor/mwait instructions
	mov dword [rax + VMCB.icpt_set_2], 0x7f | (7 << 10)
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
	;mov rdx, [rsi + vm_snapshot.xcr0]
	;mov eax, edx
	;shr rdx, 32
	;xor ecx, ecx
	;xsetbv

	pop rax

	; ---------------------------------------------------------------------
	; No allocations allowed after this point!
	;
	; rax - VMCB
	; r8  - Dump
	; r13 - VM Context result
	; r14 - VM CR3 physical addr
	; ---------------------------------------------------------------------

	; Store the timeout threshold
	push rax
	mov  rax, TIMEOUT_US
	call rdtsc_future
	mov  qword [gs:thread_local.exhaust], rax

	call rdtsc64
	mov  qword [gs:thread_local.fuzz_start_time], rax
	pop  rax

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

%ifdef ENABLE_SINGLE_STEP
	bts qword [rax + VMCB.rfl], 8 ; Set trap flag
%endif

	; Construct the module list for this core. This only gets updated once so
	; cores must use the same snapshot per boot, otherwise we need to add a
	; way to dynamically regenerate this later.
	call win32_construct_modlist

	push rbx

	mov  rbx, 0
	mov  dr0, rbx
	mov  dr1, rbx
	mov  dr2, rbx
	mov  dr3, rbx
	mov  qword [rax + VMCB.dr6], 0
	mov  qword [rax + VMCB.dr7], 0

	pop rbx

	call corrupt_pdf
	call inject_pdf

%ifdef ENABLE_LWP_CC
	call start_lwp
%endif

%ifdef ENABLE_LOGGING
	call start_log
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

%ifdef ENABLE_SINGLE_STEP
	bts qword [rax + VMCB.rfl], 8 ; Set trap flag
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

	; Check if we got a #NPF, if it's COW, perform COW, otherwise continue
	cmp qword [rax + VMCB.exitcode], 0x400
	jne .not_cow

	; If the page is not present, this is an IO or OOB access, not COW
	test qword [rax + VMCB.exitinfo1], (1 << 0)
	jz   .not_cow
	
	; If the access was not a write, this is not COW
	test qword [rax + VMCB.exitinfo1], (1 << 1)
	jz   .not_cow

	; Make sure the memory access is within the physical memory range for COW
	push rbx
	mov  rbx, VM_MEMORY_SIZE
	cmp  qword [rax + VMCB.exitinfo2], rbx
	pop  rbx
	jae  .not_cow

	; At this point there was a write to a present page, assume it is COW
	; blindly for performance.
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp

	; Get the original page
	mov  rbx, qword [rax + VMCB.exitinfo2]
	and  rbx, ~0xFFF
	mov  rdx, qword [rax + VMCB.n_cr3]
	call mm_get_phys
	mov  rsi, rax
	
	call mm_alloc_phys_4k
	lea  rbp, [rax + 7] ; Map the original snapshot memory as R and S
	bts  rbp, 6         ; Dirty flag
	call mm_map_4k

	mov rdi, rax
	mov rcx, (4096 / 8)
	rep movsq

	pop rbp
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	jmp .relaunch

.not_cow:
%ifdef ENABLE_REPORT_ALL_VMEXIT
	call save_vm_context
	call report_vm_context
%endif

	; Check if we should time out
	push rax
	push rbx
	call rdtsc64
	mov  rbx, rax

	sub  rbx, qword [gs:thread_local.fuzz_start_time]
	mov  qword [gs:thread_local.elapsed], rbx

	cmp  rax, qword [gs:thread_local.exhaust]
	pop  rbx
	pop  rax
	jge  .done_timeout

	cmp qword [rax + VMCB.exitcode], 0x61
	jne .next_exitcode_0

%ifdef ENABLE_IBS_CC
	push rax
	push rbx
	push rcx
	push rdx
	push rdi
	push rsi
	push rbp

	XMMPUSH xmm5
	XMMPUSH xmm6

	; Check if IbsOpVal is set, indicating that the IBS value is valid.
	;mov ecx, 0xc0011033
	;rdmsr
	;bt  eax, 18
	;jnc .not_ibs

	mov    rax, [gs:thread_local.VMCB]
	mov    rbx, [rax + VMCB.br_to]
	call   win32_symhash
	movaps xmm6, xmm5
	mov    rbx, [rax + VMCB.br_from]
	call   win32_symhash
	aesenc xmm5, xmm6

	; Look up this edge in the coverage fht
	mov  rcx, qword [fs:globals.coverage_fht]
	call fht_fetch_or_lock
	jnc  .already_present

	; Place this fuzz image input database
	call input_create_entry

	; Allocate room for the bb_struc which describes the input hash and count
	mov rbx, bb_struc_size
	rand_alloc rbx
	mov qword [rbx + bb_struc.count],      0
	movdqu    [rbx + bb_struc.input_hash], xmm5

	; Place this bb_struc in the coverage flut
	mov qword [rcx], rbx

	; Move the bb_struc to rcx, as we increment the count below
	mov rcx, rbx

	lock inc qword [fs:globals.fuzz_status + fuzz_status.num_unique_bb]

.already_present:
	inc qword [rcx + bb_struc.count]
	
.not_ibs:
	XMMPOP xmm6
	XMMPOP xmm5

	pop rbp
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
%endif ; ENABLE_IBS_CC

	jmp .relaunch

.next_exitcode_0:
	cmp qword [rax + VMCB.exitcode], 0x41
	jne .next_exitcode_1

	; #DB here
	jmp .done

	mov qword [rax + VMCB.dr6], 0  ; Clear debug status
	bts qword [rax + VMCB.rfl], 16 ; Set resume flag
	jmp .relaunch

.next_exitcode_1:
	; #PF
	cmp qword [rax + VMCB.exitcode], 0x4e
	jne short .next_exitcode_2

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

.next_exitcode_2:
	; #BP
	cmp qword [rax + VMCB.exitcode], 0x43
	jne short .done

	; If rip is user mode, this isn't our page fault handler, it's just a
	; normal #BP, so report it!
	bt  qword [rax + VMCB.rip], 63
	jnc .done

%ifdef ENABLE_DISK
	push rbx
	mov  rbx, [rax + VMCB.rip]
	and  rbx, 0xfff
	cmp  rbx, 0x820
	pop  rbx
	jne  short .page_fault

	call handle_fileio

	; int3
	jmp .relaunch
%endif
	
.page_fault:
	; Store that this is a #PF, and use the #PF context saved from before
	mov qword [rax + VMCB.exitcode], 0x4e

	jmp .done_ignore_context

.done_timeout:
	; Burn the exit code as it is no longer valid. Replace it with a magic
	; timeout number.
	mov  qword [rax + VMCB.exitcode], 0x1337
	lock inc qword [fs:globals.fuzz_status + fuzz_status.fuzz_timeout]
.done:
	call save_vm_context
.done_ignore_context:
%ifdef ENABLE_LWP_CC
	call lwp_coverage
%endif

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

	; Increment the global fuzz case counter
	mov  r15, 1
	lock xadd qword [fs:globals.fuzz_status + fuzz_status.fuzz_cases], r15

	; NPT fault
	cmp qword [rax + VMCB.exitcode], 0x400
	je  short .hit_io

	; in/out instruction
	cmp qword [rax + VMCB.exitcode], 0x7b
	je  short .hit_io

	; interrupt
	cmp qword [rax + VMCB.exitcode], 0x60
	je  short .hit_io

	; NMI
	cmp qword [rax + VMCB.exitcode], 0x61
	je  short .hit_io

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
	;cmp qword [rax + VMCB.exitcode], 0x43 ; ignore int3s
	;je  .not_crash

	push rbx
	mov  rbx, 0x00007ff6775a897e
	cmp  qword [rax + VMCB.rip], rbx
	pop  rbx
	je   .not_crash

	lock inc qword [fs:globals.fuzz_status + fuzz_status.num_crashes]

%ifdef ENABLE_CRASH_FEEDBACK
	; Record the crash in the crash input database
	push rbx
	push rcx
	push r15

	XMMPUSH xmm4
	XMMPUSH xmm5

	; Calculate the symhash for RIP
	mov  rbx, qword [gs:thread_local.vm_ctxt + vm_ctxt.rip]
	call win32_symhash

	; Get the type of crash we had and integrate it with the symhash
	call   classify_crash
	movq   xmm4, rcx
	aesenc xmm5, xmm4

	; Generate a random number and integrate it with the hash
	;call   xorshift64
	;and    r15, 0xF
	;movq   xmm4, r15
	;aesenc xmm5, xmm4

	; Check if we already have this crash
	mov  rcx, qword [fs:globals.crash_flut]
	call flut_fetch_or_lock
	jnc  short .crash_present

	; Hash our input file and store it in the input database
	call input_create_entry

	; Allocate the crash entry
	mov rbx, crash_ent_size
	rand_alloc rbx

	; Populate the crash entry with the correct data
	movdqu       [rbx + crash_ent.hash], xmm5
	mov    qword [rbx + crash_ent.seen], 0

	; Set that this node has seen this crash
	mov r15, qword [gs:thread_local.node_id]
	bts qword [rbx + crash_ent.seen], r15

	lock inc qword [fs:globals.fuzz_status + fuzz_status.num_uniq_crashes]

	; Store this crash in the crash flut!
	mov qword [rcx], rbx

	; Report this crash!
	call report_crash

.crash_present:

	XMMPOP xmm5
	XMMPOP xmm4

	pop r15
	pop rcx
	pop rbx
%else
	; Without crash feedback, report ALL crashes
%ifndef ENABLE_MINIMIZE
	call report_crash
%endif
%endif

.not_crash:
	; If there was reporting forced on this input, report it
	cmp qword [gs:thread_local.force_report], 0
	je  short .no_force

	; Force reporting
	call report_crash

.no_force:
	; Report the fuzz status over the network
	mov  rbx, [fs:globals.fs_base]
	lea  rbx, [rbx + globals.fuzz_status]
	mov  dword [rbx + fuzz_status.magic], FUZZ_STATUS_MAGIC
	mov  rcx, fuzz_status_size
	call x540_send_packet

	; Discard the saved FS and GS
	pop rbx
	pop rbx

%ifdef ENABLE_EOFC
	call report_vm_context
%endif

%ifdef ENABLE_SINGLE_RUN
	jmp halt
%endif

	cmp qword [fs:globals.stop_fuzzing], 0
	je  .next_fuzz

.dead_fuzz:
	jmp halt

panic:
	DBGPRINT 0xDEADDEAD
	call debug_report_state
	cli
.lewp:
	hlt
	jmp short .lewp

debug_report_state:
	push rbx
	push rcx
	push rdi
	push rsi

	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rax], rax
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
	lea  rbx, [rsp + (8*5)]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rsp], rbx
	mov  rbx, [rsp + (8*4)]
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rip], rbx
	pushfq
	pop  rbx
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.rfl], rbx

	mov  rbx, cr0
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.cr0], rbx
	mov  rbx, cr2
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.cr2], rbx
	mov  rbx, cr3
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.cr3], rbx
	mov  rbx, cr4
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.cr4], rbx

	mov  dword [gs:thread_local.vm_ctxt + vm_ctxt.magic], VM_STATE_DUMP

	mov  rbx, 0xdead1337
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.ei1],   rbx
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.ei2],   rbx
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.eii],   rbx
	mov  [gs:thread_local.vm_ctxt + vm_ctxt.n_cr3], rbx

	mov rdi, [gs:thread_local.gs_base]
	lea rdi, [rdi + thread_local.vm_ctxt + vm_ctxt.stack]
	lea rsi, [rsp + (8*5)]
	mov rcx, 512
	rep movsb

	; Send the context of the crash
	mov  rbx, [gs:thread_local.gs_base]
	lea  rbx, [rbx + thread_local.vm_ctxt]
	mov  rcx, vm_ctxt_size
	call x540_send_packet

	pop rsi
	pop rdi
	pop rcx
	pop rbx
	ret

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
; rdx -> cr3 passed to mm_for_each_dirty_4k
; r13 -> Pointer to page entry
; rsi -> VM Snapshot
restore_page:
	push rdi
	push rsi
	push rcx

	mov rcx, VM_MEMORY_SIZE
	cmp rbx, rcx
	jae short .dont_restore

	; Get the physical address for this page
	bextr rdi, qword [r13], 0x280c
	shl   rdi, 12

	add rsi, rbx
	mov rcx, (4096 / 8)
	rep movsq

.dont_restore:
	pop rcx
	pop rsi
	pop rdi
	ret

; Boot a simple guest OS
launch_svm:
	; Copy the first sector of the boot image to 0x7c00
	push rax
	push rsi
	push rdi
	push rcx
	mov  rbx, 0
	mov   cx, 1
	mov   r8, 0x7c00
	call ide_pio_read_sectors
	pop  rcx
	pop  rdi
	pop  rsi
	pop  rax

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
	mov  [gs:thread_local.VMCB], rax

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

	xor ebx, ebx
	mov rsi, VM_MEMORY_SIZE
.lewp:
	; DRAM pages are cloned for a guest copy which can be modified
	; MMIO pages are identity mapped through to the host with no caching
	call probe_memory_dest
	test rdx, rdx
	jnz  short .is_mmio_map

	; Allocate the page to go in the guest
	push rax
	call mm_rand_alloc_phys_4k
	mov  rbp, rax
	pop  rax

	mov rcx, (4 * 1024 * 1024 * 1024)
	cmp rbx, rcx
	jae short .dont_clone

	; Copy the host physical page to the guest allocated page
	push rdi
	push rsi
	push rcx
	mov  rdi, rbp
	mov  rsi, rbx
	mov  rcx, (4096 / 8)
	rep  movsq
	pop  rcx
	pop  rsi
	pop  rdi

.dont_clone:
	or   rbp, 7
	mov  rdx, r15
	call mm_map_4k

	jmp short .next_map

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

	mov  rbx, r15
	call iommu_init

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

	jmp .inject_swint

.process_int15:
	push rax
	mov  rax, [rax + VMCB.rax]
	cmp   ax, 0xE820
	pop  rax
	jne  .failnext

	; Bounds check our continuation
	cmp ebx, 0x3
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

.failnext:
	bts qword [rax + VMCB.rfl], 0 ; Zero cf to signify success
	add qword [rax + VMCB.rip], 2 ; Increment rip
	jmp .relaunch

.int15_map:
%if VM_MEMORY_SIZE == (16 * 1024 * 1024 * 1024)
	; start, length, avail, continuation
	; 16GB VM
	dq 0x000000000, 0x000009e000, 0x1, 0x1
	dq 0x000100000, 0x0000600000, 0x1, 0x2
	dq 0x000e10000, 0x00cf04f000, 0x1, 0x3
	dq 0x100000000, 0x0300000000, 0x1, 0x0
%elif VM_MEMORY_SIZE == (4 * 1024 * 1024 * 1024)
	; start, length, avail, continuation
	; 4GB VM
	dq 0x000000000, 0x000009e000, 0x1, 0x1
	dq 0x000100000, 0x0000600000, 0x1, 0x2
	dq 0x000e10000, 0x00cf04f000, 0x1, 0x0
%elif VM_MEMORY_SIZE == (1 * 1024 * 1024 * 1024)
	; start, length, avail, continuation
	; 1GB VM
	dq 0x000000000, 0x000009e000, 0x1, 0x1
	dq 0x000100000, 0x0000600000, 0x1, 0x2
	dq 0x000e10000, 0x003F1F0000, 0x1, 0x0
%else
%error "Invalid memory size"
%endif

.process_int13:
	; Only service for drive 0x80
	cmp dl, 0x80
	jne .inject_swint

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
	bextr r11, rcx, 0x0206 ; Get high 2 bits of cylinder
	shl   r11, 8
	or    r10, r11
	imul  r10, 255
	bextr r11, rdx, 0x0808 ; Get DH into r11 (head)
	add   r10, r11
	imul  r10, 63
	bextr r11, rcx, 0x0600 ; Get CL into r11 (sector)
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
	mov rbx, (900 * 1024 * 1024 * 1024) / 512
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
	mov edx, 0xff01
	mov ebx, 0x0000

	btr qword [rax + VMCB.rfl], 0 ; Zero cf to signify success
	add qword [rax + VMCB.rip], 2 ; Increment rip
	jmp .relaunch

.next5:
	push rbx
	mov  rbx, qword [rax + VMCB.rax]
	cmp  bh, 0x15
	pop  rbx
	jne  .unh_inject_swint

	mov qword [rax + VMCB.rax], 0x0300 ; We're a fixed disk
	mov cx, 0xffff
	mov dx, 0xffff

	btr qword [rax + VMCB.rfl], 0 ; Zero cf to signify success
	add qword [rax + VMCB.rip], 2 ; Increment rip
	jmp .relaunch

.unh_inject_swint:
	call dump_vm_state

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
	call x540_send_packet

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

