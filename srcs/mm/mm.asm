[bits 64]

; Get the APIC ID for this core
get_thread_id:
	mov rax, 0xFEE00020
	mov eax, dword [rax]
	shr rax, (32 - 8)
	ret

; rcx <- Node ID
get_current_node:
	push rax
	push rbx
	push rdx

	mov eax, 0x8000001E
	cpuid
	and ecx, (MAX_NODES - 1)

	pop rdx
	pop rbx
	pop rax
	ret

; rdi -> Haystack
; rdx -> Haystack size
; rsi -> Needle
; rcx -> Needle size
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

	add rdi, 1
	sub rdx, 1
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

; rdi -> memory to zero
; rcx -> size in bytes of memory to zero
bzero:
	push rax
	push rcx
	push rdx
	push rdi

	; Zero out rax for stosq
	xor eax, eax

	mov rdx, rcx
	and edx, 0x7 ; Get remainder of bytes to do individually
	shr rcx, 3   ; Get number of 8-byte chunks
	jz  short .individual

	rep stosq

.individual:
	; We know rcx is 0, so this is effectively a 'mov' that sets flags
	xor rcx, rdx
	jz  short .done

	rep stosb

.done:
	pop rdi
	pop rdx
	pop rcx
	pop rax
	ret

; Allocate 1MB and store the address to it in GS-base
;
; rax -> Core ID
init_per_core_storage:
	push rax
	push rbx
	push rcx
	push rdx

	push rax

	mov rbx, (1024 * 1024)
	bamp_alloc rbx

	; Zero out the structure
	push rdi
	mov  rdi, rbx
	mov  rcx, (1024 * 1024)
	xor  eax, eax
	rep  stosb
	pop  rdi

	mov   eax, ebx
	bextr rdx, rbx, 0x2020
	mov   ecx, 0xC0000101 ; gs_base
	wrmsr

	mov qword [gs:thread_local.gs_base], rbx

	call get_current_node
	mov  qword [gs:thread_local.node_id], rcx

	pop rax
	mov qword [gs:thread_local.core_id], rax

	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; rbx -> Node struct to initialize
; rsi -> Source data
; rbp -> Size of data (in bytes)
init_node_data:
	push rcx

	mov rcx, qword [gs:thread_local.node_id]

	mov qword [rbx + node_struct.node_data + rcx*8], rsi
	mov qword [rbx + node_struct.orig_data],         rsi
	mov qword [rbx + node_struct.data_len],          rbp

	pop rcx
	ret

; rbx -> node_struct
; rax <- Pointer to data local to this node
;
; This is thread safe. You can call this before the orig_data and data_len
; are set, as it will wait until they are set!
;
per_node_data:
	push rcx
	push rdi

	; Wait for the initial data and length to be populated
.wait_for_data:
	pause
	cmp qword [rbx + node_struct.orig_data], 0
	je  short .wait_for_data
.wait_for_len:
	pause
	cmp qword [rbx + node_struct.data_len], 0
	je  short .wait_for_len

	mov rcx, qword [gs:thread_local.node_id]

	; Check if we already have a local data pointer
	cmp qword [rbx + node_struct.node_data + rcx*8], 0
	jne short .done

	; Acquire a lock on the per node data. This will only occur when two
	; threads both race to initialize an empty node pointer.
	mov  rax, 1
	lock xadd qword [rbx + node_struct.node_race + rcx*8], rax
	test rax, rax
	jnz  short .poll_for_done ; If we're not the first, wait for the first to
	                          ; finish setting up the copy.

	; Check again for presence of node data. This is possible if we didn't see
	; data above, then the guy populating the node released the lock and then
	; we got lock #0
	cmp qword [rbx + node_struct.node_data + rcx*8], 0
	jne short .release_lock

	; Allocate on this node
	mov rdi, qword [rbx + node_struct.data_len]
	bamp_alloc rdi

	; Copy from the master data source to our local allocation
	push rcx
	push rsi
	push rdi
	mov  rcx, qword [rbx + node_struct.data_len]
	mov  rsi, qword [rbx + node_struct.orig_data]
	rep  movsb
	pop  rdi
	pop  rsi
	pop  rcx

	; Save the data pointer!
	mov qword [rbx + node_struct.node_data + rcx*8], rdi

	jmp short .release_lock

	; Wait for the winner of the race to populate the node data
.poll_for_done:
	pause
	cmp qword [rbx + node_struct.node_data + rcx*8], 0
	je  short .poll_for_done

.release_lock:
	; Release the lock
	lock dec qword [rbx + node_struct.node_race + rcx*8]

.done:
	mov rax, qword [rbx + node_struct.node_data + rcx*8]

	pop rdi
	pop rcx
	ret

; rsi -> Size to allocate
; rsi <- Pointer
bamp_alloc_int:
	push rax
	push rbx
	push rcx
	push rdx
	push rdi
	
	call get_current_node

	; rcx now contains the node id

	mov rbx, [fs:globals.fs_base]
	lea rbx, [rbx + globals.bamp_addr + rcx*8]

	add  rsi,  0xFFF
	and  rsi, ~0xFFF
	mov  rdx,  rsi
	lock xadd qword [rbx], rsi

	; Check for OOM
	push rdx
	add  rdx, rsi
	cmp  rdx, [fs:globals.bamp_ends + rcx*8]
	pop  rdx
	jbe  short .not_oom

	int3

.not_oom:
	lock add qword [fs:globals.fuzz_status + fuzz_status.alloc_charge + rcx*8], rdx

	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; rsi -> Size to allocate
; rsi <- Pointer
rand_alloc_int:
	push rax
	push rbx
	push rcx
	push rdx
	push rdi

	XMMPUSH xmm15
	
	call falkrand
	movq rcx, xmm15
	and  rcx, 0x7

	; rcx now contains the node id

	mov rbx, [fs:globals.fs_base]
	lea rbx, [rbx + globals.bamp_addr + rcx*8]

	add  rsi,  0xFFF
	and  rsi, ~0xFFF
	mov  rdx,  rsi
	lock xadd qword [rbx], rsi

	; Check for OOM
	push rdx
	add  rdx, rsi
	cmp  rdx, [fs:globals.bamp_ends + rcx*8]
	pop  rdx
	jbe  short .not_oom

	int3

.not_oom:
	lock add qword [fs:globals.fuzz_status + fuzz_status.alloc_charge + rcx*8], rdx

	XMMPOP xmm15

	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; bamp_get_phys
;
; Summary:
;
; This performs a manual page table lookup to get the physical address for
; a virtual address. Bounds are not checked. A valid vaddr must be provided!
;
; Parameters:
;
; rbx - Virtual address to look up
;
; Alignment:
;
; None
;
; Returns:
;
; rax - Physical address
;
; Smashes:
;
; rax - Return value
;
; Optimization
;
; Readability
;
bamp_get_phys:
	push rdx
	mov  rdx, cr3
	call mm_get_phys
	pop  rdx
	ret

alloc_zero_4k:
	push rcx
	push rdi

	call mm_alloc_phys_4k

	push rax
	mov  rdi, rax
	mov  ecx, 4096
	xor  eax, eax
	rep  stosb
	pop  rax

	pop rdi
	pop rcx
	ret

; rbx -> vaddr
; rcx -> Mark present? (zero - mark not present, nonzero - mark present)
; rdx -> cr3
bamp_mark_pte_present:
	push rax
	push rbx
	push rdx

	; Save the virtual address
	mov rax, rbx

	; Get CR3
	shr rdx, 12
	shl rdx, 12

	; Get the PML4E
	shr rbx, 39
	and rbx, 0x1FF
	mov rdx, [rdx + rbx * 8]
	bt  rdx, 0
	jnc .fail
	shr rdx, 12
	shl rdx, 12

	; Get the PDPTE
	mov rbx, rax
	shr rbx, 30
	and rbx, 0x1FF
	mov rdx, [rdx + rbx * 8]
	bt  rdx, 0
	jnc .fail
	shr rdx, 12
	shl rdx, 12
	btr rdx, 63

	; Get the PDE
	mov rbx, rax
	shr rbx, 21
	and rbx, 0x1FF
	mov rdx, [rdx + rbx * 8]
	bt  rdx, 0
	jnc .fail
	shr rdx, 12
	shl rdx, 12
	btr rdx, 63

	; Get the PTE
	mov rbx, rax
	shr rbx, 12
	and rbx, 0x1FF

	test rcx, rcx
	jnz  short .mark_present

	; Mark the PTE not present
	btr qword [rdx + rbx * 8], 0
	jmp short .fail

.mark_present:
	; Mark the PTE present
	bts qword [rdx + rbx * 8], 0

.fail:
	pop rdx
	pop rbx
	pop rax
	ret

; rbx -> Physical address to probe
; rdx <- Zero if DRAM, nonzero if MMIO
probe_memory_dest:
	push rax
	push rbx
	push rcx
	push rbp

	lea rax, [rel mmio_routing_table]
	mov rcx, 12
.lewp:
	mov rdx, qword [rax + 0] ; Base
	mov rbp, qword [rax + 8] ; Limit

	; If the limit does not exist then go to the next table
	test rbp, rbp
	jz   short .next_table

	; If we're < the base, we can't possibly be in this region
	cmp rbx, rdx
	jb  short .next_table

	; If we're <= the limit, then we're MMIO
	cmp rbx, rbp
	jbe short .is_mmio

.next_table:
	add rax, 0x10
	dec rcx
	jnz short .lewp

	xor rdx, rdx
	jmp short .done

.is_mmio:
	mov rdx, 1

.done:
	pop rbp
	pop rcx
	pop rbx
	pop rax
	ret

; rax <- Physical address to 4k page
mm_alloc_phys_4k:
	push rbx
	push rcx

	; Get the per node entry
	mov rbx, qword [gs:thread_local.phys_4k_freelist]

	; If the list is dead, allocate a new entry from the global pool
	test rbx, rbx
	jz   short .alloc_new

	; Get the next free element and set it as the next free entry
	mov rcx, [rbx]
	mov qword [gs:thread_local.phys_4k_freelist], rcx
	jmp short .done

.alloc_new:
	mov rbx, 4096
	bamp_alloc rbx

.done:
	call bamp_get_phys

	pop rcx
	pop rbx
	ret

; rax <- Physical address to 4k page
mm_rand_alloc_phys_4k:
	push rbx
	push rcx

	; Get the per node entry
	mov rbx, qword [gs:thread_local.phys_4k_freelist]

	; If the list is dead, allocate a new entry from the global pool
	test rbx, rbx
	jz   short .alloc_new

	; Get the next free element and set it as the next free entry
	mov rcx, [rbx]
	mov qword [gs:thread_local.phys_4k_freelist], rcx
	jmp short .done

.alloc_new:
	mov rbx, 4096
	rand_alloc rbx

.done:
	call bamp_get_phys

	pop rcx
	pop rbx
	ret

; rax -> Physical address to 4k page to free
mm_free_phys_4k:
	push rbx

	; Get the current free list
	mov rbx, qword [gs:thread_local.phys_4k_freelist]

	; Put the free list link after us
	mov [rax], rbx

	; Make us the head of the free list
	mov qword [gs:thread_local.phys_4k_freelist], rax

	pop rbx
	ret

; rcx -> Number of bytes to allocate
; rax <- Allocation
mm_mixed_alloc:
	push rbx
	push rcx
	push rdx
	push rbp
	push r10
	push r13
	push r14
	push r15

	; Zero out the return value
	xor r15, r15

	; Page align the length
	add rcx,  0xFFF
	and rcx, ~0xFFF

	; If there is no length, fail
	test rcx, rcx
	jz   short .done

	; Get a vaddr to map to and update the current pointer
	mov  r10, rcx
	lock xadd qword [fs:globals.next_free_vaddr], r10

	; Save off the base virtual address
	mov r15, r10

	; For each page, create a map
.lewp:
	call mm_rand_alloc_phys_4k
	mov  rbx, r10
	mov  rdx, cr3
	lea  rbp, [rax + 3] ; Map as R/W
	call mm_map_4k

	add r10, 4096
	sub rcx, 4096
	jnz short .lewp

.done:
	mov rax, r15
	
	pop r15
	pop r14
	pop r13
	pop r10
	pop rbp
	pop rdx
	pop rcx
	pop rbx
	ret

; rbx -> Address to linearlly map (rounded down to page boundry)
; rcx -> Number of bytes to linearlly map (rounded up to page boundry)
; rdx -> cr3 of the source
; rax <- Mapping
mm_linear_map:
	push rbx
	push rcx
	push rdx
	push rbp
	push r10
	push r13
	push r14
	push r15

	; Zero out the return value
	xor r15, r15

	; Get the rounding amount on the address
	mov r13, rbx
	and r13, 0xFFF

	; Round down the address
	and rbx, ~0xFFF

	; Add the length to the rounded amount and then round it up
	lea rcx, [rcx + r13 + 0xFFF]
	and rcx, ~0xFFF

	; If there is no length, fail
	test rcx, rcx
	jz   short .done

	; Get a vaddr to map to and update the current pointer
	mov  r10, rcx
	lock xadd qword [fs:globals.next_free_vaddr], r10

	; Save off the base virtual address
	mov r14, r10

	; For each page, create a map
.lewp:
	; Get the physical memory backing this page
	call mm_get_phys

	; Check if this memory is present
	test rax, rax
	jnz  short .mapped

	jmp panic

.mapped:
	push rbx
	push rdx
	push rbp
	mov  rbx, r10
	mov  rdx, cr3
	lea  rbp, [rax + 3] ; Map as R/W
	call mm_map_4k
	pop  rbp
	pop  rdx
	pop  rbx

	add r10, 4096
	add rbx, 4096
	sub rcx, 4096
	jnz short .lewp

	lea r15, [r14 + r13]

.done:
	mov rax, r15
	
	pop r15
	pop r14
	pop r13
	pop r10
	pop rbp
	pop rdx
	pop rcx
	pop rbx
	ret

; rbx -> Guest physical memory to access for write
; rdx -> Guest n_cr3
; rax <- Host physical address for write (zero on failure)
mm_get_phys_with_cow:
	push rcx
	push rdi
	push rsi
	push rbp
	push r10

	; First get the mapping
	call mm_get_phys_int
	test rax, rax
	jz   .done

	; If the mapping is already writable do nothing
	bt rcx, 1
	jc .done

	; Mapping is not writeable, make a new allocation and map it as writable
	; then copy the memory here.

	; Get the base address of the original page
	mov rsi, rax
	mov r10, rax
	and rsi, ~0xFFF
	and r10,  0xFFF

	; Allocate a new page and copy the old contents to it
	call mm_alloc_phys_4k
	mov  rdi, rax
	mov  rcx, (4096 / 8)
	rep  movsq

	; Create the new mapping
	lea  rbp, [rax + 7]
	call mm_map_4k

	; Return the pointer to the new mapping plus the original offset
	add rax, r10

.done:
	pop r10
	pop rbp
	pop rsi
	pop rdi
	pop rcx
	ret	

; rbx -> Virtual Address
; rdx -> CR3 to use for mapping
; rax <- Physical Address (zero on failure)
mm_get_phys:
	push rcx
	call mm_get_phys_int
	pop  rcx
	ret

; rbx -> Virtual Address
; rdx -> CR3 to use for mapping
; rax <- Physical Address (zero on failure)
; rcx <- Raw entry
mm_get_phys_int:
	push rdx

	; ------ PML4 -------------------------------------------------

	; Extract the PML4 base address, bits 51:12
	bextr rdx, rdx, 0x280c
	shl   rdx, 12

	; Extract the PML4 offset from bits 47:39 of the vaddr
	bextr rax, rbx, 0x0927

	; Fetch the PML4E and check for presence
	mov rdx, qword [rdx + rax*8]
	bt  rdx, 0
	jnc .not_present

	; ------ PDP -------------------------------------------------

	; Extract the PDP base address, bits 51:12
	bextr rdx, rdx, 0x280c
	shl   rdx, 12

	; Extract the PDP offset from bits 38:30 of the vaddr
	bextr rax, rbx, 0x091e

	; Fetch the PDPE and check for presence
	mov rdx, qword [rdx + rax*8]
	bt  rdx, 0
	jnc short .not_present

	; Check for 1GB paging
	mov eax, (30 << 8) ; Virtual address bextr mask to get physical page offset
	bt  rdx, 7
	jc  short .present

	; ------ PD -------------------------------------------------

	; Extract the PD base address, bits 51:12
	bextr rdx, rdx, 0x280c
	shl   rdx, 12

	; Extract the PD offset from bits 29:21 of the vaddr
	bextr rax, rbx, 0x0915

	; Fetch the PDE and check for presence
	mov rdx, qword [rdx + rax*8]
	bt  rdx, 0
	jnc short .not_present

	; Check for 2MB paging
	mov eax, (21 << 8) ; Virtual address bextr mask to get physical page offset
	bt  rdx, 7
	jc  short .present

	; ------ PT -------------------------------------------------

	; Extract the PT base address, bits 51:12
	bextr rdx, rdx, 0x280c
	shl   rdx, 12

	; Extract the PT offset from bits 20:12 of the vaddr
	bextr rax, rbx, 0x090c

	; Fetch the PTE and check for presence
	mov rdx, qword [rdx + rax*8]
	bt  rdx, 0
	jnc short .not_present

	; We're using 4KB paging
	mov eax, (12 << 8) ; Virtual address bextr mask to get physical page offset

.present:
	; At this point
	; rax - Mask for bextr to get physical address offset
	;       (12 for 4KB, 21 for 2MB, and 30 for 1GB)
	; rdx - Raw entry from the page table

	mov rcx, rdx

	; Extract the physical page base address, bits 51:12
	bextr rdx, rdx, 0x280c
	shl   rdx, 12

	; Extract the n number of bits from the virtual address to get our offset
	bextr rax, rbx, rax

	; Calculate the physical address + offset for our final result
	add rax, rdx

	jmp short .done

.not_present:
	xor eax, eax

.done:
	pop rdx
	ret

; rbx -> Virtual Address
; rdx -> Guest cr3
; rbp -> Guest nested page table
; rax <- Physical Address
mm_guest_virt_to_host_phys:
	push rcx
	push r10
	mov  r10, 0
	call mm_guest_virt_to_host_phys_int
	pop  r10
	pop  rcx
	ret

; rbx -> Virtual Address
; rdx -> Guest cr3
; rbp -> Guest nested page table
; rax <- Physical Address
mm_guest_virt_to_host_phys_cow:
	push rcx
	push r10
	mov  r10, 1
	call mm_guest_virt_to_host_phys_int
	pop  r10
	pop  rcx
	ret

; rbx -> Virtual Address
; rdx -> Guest cr3
; rbp -> Guest nested page table
; r10 -> 0 - read access, 1 - write access
; rax <- Physical Address
; rcx <- Raw page table entry (in a failure case, it's the contents of the non
;        present data)
mm_guest_virt_to_host_phys_int:
	push rdx

	xor rcx, rcx

	; ------ PML4 -------------------------------------------------

	; Extract the PML4 base address, bits 51:12
	bextr rdx, rdx, 0x280c
	shl   rdx, 12

	; Translate guest physical into host physical via ncr3
	push rax
	push rbx
	mov  rbx, rdx
	mov  rdx, rbp
	call mm_get_phys
	mov  rdx, rax
	pop  rbx
	pop  rax

	; Validate that the guest physical to host physical was successful
	test rdx, rdx
	jz   .not_present
	
	; Extract the PML4 offset from bits 47:39 of the vaddr
	bextr rax, rbx, 0x0927

	; Fetch the PML4E and check for presence
	mov rdx, qword [rdx + rax*8]
	mov rcx, rdx
	bt  rdx, 0
	jnc .not_present

	; ------ PDP -------------------------------------------------

	; Extract the PDP base address, bits 51:12
	bextr rdx, rdx, 0x280c
	shl   rdx, 12

	; Translate guest physical into host physical via ncr3
	push rax
	push rbx
	mov  rbx, rdx
	mov  rdx, rbp
	call mm_get_phys
	mov  rdx, rax
	pop  rbx
	pop  rax

	; Validate that the guest physical to host physical was successful
	test rdx, rdx
	jz   .not_present
	
	; Extract the PDP offset from bits 38:30 of the vaddr
	bextr rax, rbx, 0x091e

	; Fetch the PDPE and check for presence
	mov rdx, qword [rdx + rax*8]
	mov rcx, rdx
	bt  rdx, 0
	jnc .not_present

	; Check for 1GB paging
	mov eax, (30 << 8) ; Virtual address bextr mask to get physical page offset
	bt  rdx, 7
	jc  .present

	; ------ PD -------------------------------------------------

	; Extract the PD base address, bits 51:12
	bextr rdx, rdx, 0x280c
	shl   rdx, 12

	; Translate guest physical into host physical via ncr3
	push rax
	push rbx
	mov  rbx, rdx
	mov  rdx, rbp
	call mm_get_phys
	mov  rdx, rax
	pop  rbx
	pop  rax

	; Validate that the guest physical to host physical was successful
	test rdx, rdx
	jz   .not_present

	; Extract the PD offset from bits 29:21 of the vaddr
	bextr rax, rbx, 0x0915

	; Fetch the PDE and check for presence
	mov rdx, qword [rdx + rax*8]
	mov rcx, rdx
	bt  rdx, 0
	jnc .not_present

	; Check for 2MB paging
	mov eax, (21 << 8) ; Virtual address bextr mask to get physical page offset
	bt  rdx, 7
	jc  short .present

	; ------ PT -------------------------------------------------

	; Extract the PT base address, bits 51:12
	bextr rdx, rdx, 0x280c
	shl   rdx, 12

	; Translate guest physical into host physical via ncr3
	push rax
	push rbx
	mov  rbx, rdx
	mov  rdx, rbp
	call mm_get_phys
	mov  rdx, rax
	pop  rbx
	pop  rax

	; Validate that the guest physical to host physical was successful
	test rdx, rdx
	jz   .not_present

	; Extract the PT offset from bits 20:12 of the vaddr
	bextr rax, rbx, 0x090c

	; Fetch the PTE and check for presence
	mov rdx, qword [rdx + rax*8]
	mov rcx, rdx
	bt  rdx, 0
	jnc short .not_present

	; We're using 4KB paging
	mov eax, (12 << 8) ; Virtual address bextr mask to get physical page offset

.present:
	; At this point
	; rax - Mask for bextr to get physical address offset
	;       (12 for 4KB, 21 for 2MB, and 30 for 1GB)
	; rdx - Raw entry from the page table

	; Extract the physical page base address, bits 51:12
	bextr rdx, rdx, 0x280c
	shl   rdx, 12

	; Extract the n number of bits from the virtual address to get our offset
	bextr rax, rbx, rax

	; Calculate the physical address + offset for our final result
	add rax, rdx

	; Translate guest physical into host physical via ncr3
	push rbx
	mov  rbx, rax
	mov  rdx, rbp
	test r10, r10
	jnz  short .cow
	call mm_get_phys
	jmp  short .done_cow
.cow:
	call mm_get_phys_with_cow
.done_cow:
	pop  rbx

	; Validate that the guest physical to host physical was successful
	test rax, rax
	jz   .not_present

	jmp short .done

.not_present:
	xor eax, eax

.done:
	pop rdx
	ret

; rbx -> Virtual address to make a map for
; rdx -> Page table base address (what you would have in cr3) [allocated already]
; rbp -> Physical page to describe with this vaddr
mm_map_4k:
	push rax
	push rcx
	push rdx
	push rsi

	; ------ PML4 -------------------------------------------------

	; Extract the PML4 base address, bits 51:12
	bextr rdx, rdx, 0x280c
	shl   rdx, 12

	; Extract the PML4 offset from bits 47:39 of the vaddr
	bextr rcx, rbx, 0x0927

	; Fetch the PML4E and check for presence
	mov rsi, qword [rdx + rcx*8]
	bt  rsi, 0
	jc  .already_mapped_pml4

	; Allocate PML4E as RW, present, and user
	call alloc_zero_4k
	or   rax, 7 | (3 << 9)
	bts  rax, 62
	bts  rax, 61
	mov  qword [rdx + rcx*8], rax
	mov  rsi, rax

	; ------ PDP -------------------------------------------------

.already_mapped_pml4:
	; Extract the PDP base address, bits 51:12
	bextr rdx, rsi, 0x280c
	shl   rdx, 12

	; Extract the PDP offset from bits 38:30 of the vaddr
	bextr rcx, rbx, 0x091e

	; Fetch the PDPE and check for presence
	mov rsi, qword [rdx + rcx*8]
	bt  rsi, 0
	jc  .already_mapped_pdp

	; Allocate PDPE as RW, present, and user
	call alloc_zero_4k
	or   rax, 7 | (2 << 9)
	bts  rax, 62
	bts  rax, 61
	mov  qword [rdx + rcx*8], rax
	mov  rsi, rax

	; ------ PD -------------------------------------------------

.already_mapped_pdp:
	; Extract the PD base address, bits 51:12
	bextr rdx, rsi, 0x280c
	shl   rdx, 12

	; Extract the PD offset from bits 29:21 of the vaddr
	bextr rcx, rbx, 0x0915

	; Fetch the PDE and check for presence
	mov rsi, qword [rdx + rcx*8]
	bt  rsi, 0
	jc  .already_mapped_pde

	; Allocate PDE as RW, present, and user
	call alloc_zero_4k
	or   rax, 7 | (1 << 9)
	bts  rax, 62
	bts  rax, 61
	mov  qword [rdx + rcx*8], rax
	mov  rsi, rax

	; ------ PT -------------------------------------------------

.already_mapped_pde:
	; Extract the PT base address, bits 51:12
	bextr rdx, rsi, 0x280c
	shl   rdx, 12

	; Extract the PT offset from bits 20:12 of the vaddr
	bextr rcx, rbx, 0x090c

	; Fetch the PTE and check for presence
	;mov rsi, qword [rdx + rcx*8]
	;bt  rsi, 0
	;jc  .already_mapped_pte

	; Move in specified value as PTE
	bts rbp, 62
	bts rbp, 61
	mov qword [rdx + rcx*8], rbp

.already_mapped_pte:
	pop rsi
	pop rdx
	pop rcx
	pop rax
	ret

; Allocate contiguous physical memory by discarding anything that isn't. This
; can very dangerously exhaust memory!!! For anything <= 4K, simply call
; mm_alloc_phys_4k
;
; rcx -> Number of physically contiguous bytes needed
; rax <- Physical address to memory
; 
mm_alloc_contig_phys:
	push rbx
	push rcx
	push rdx
	push rdi
	push rsi
	push rbp

	; Round up bytes requested to next 4k boundry
	add rcx,  0xFFF
	and rcx, ~0xFFF

	; Prevent an infinite loop on the zero case
	test rcx, rcx
	jz   short .fail

	; Save off the aligned number of bytes needed
	mov rbp, rcx

	; Store cr3 in rdx for mm_get_phys calls
	mov rdx, cr3

.try_another_allocation:
	; Restore number of bytes needed
	mov rcx, rbp

	; Allocate!
	mov rbx, rcx
	bamp_alloc rbx

	; Get the number of contiguous pages we need
	shr rcx, 12

	; Get the physical address of the first page
	call mm_get_phys
	mov  rsi, rax
	mov  rdi, rax

.for_each_page:
	add rbx, 4096
	dec rcx
	jz  short .done

	; Get the physical address of the next page
	call mm_get_phys

	; Did our next page follow directly after the previous? If not, try again!
	add rsi, 4096
	cmp rsi, rax
	jne short .try_another_allocation

	jmp short .for_each_page

.done:
	; Get the original physical address
	mov rax, rdi
	jmp short .end

.fail:
	xor eax, eax

.end:
	pop rbp
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	ret

; rdx -> CR3 to use for mapping
; rbp -> Function to call with each dirty page
;          r13 -> Pointer to page entry
;          rbx -> Virtual address
mm_for_each_dirty_4k:
	push rax
	push rbx
	push r10
	push r11
	push r12
	push r13
	push r14

	; Extract the PML4 base address, bits 51:12
	bextr r10, rdx, 0x280c
	shl   r10, 12

.for_each_pml4:
	; Fetch the PML4E and check for presence
	mov r11, qword [r10]
	bt  r11, 0
	jnc .next_pml4

	; If the entry is not accessed, ignore
	bt  r11, 5
	jnc .next_pml4

	; Extract the PDP base address, bits 51:12
	bextr r11, r11, 0x280c
	shl   r11, 12

.for_each_pdpe:
	; Fetch the PDPE and check for presence
	mov r12, qword [r11]
	bt  r12, 0
	jnc .next_pdpe

	; If the entry is not accessed, ignore
	bt  r12, 5
	jnc .next_pdpe

	; Extract the PD base address, bits 51:12
	bextr r12, r12, 0x280c
	shl   r12, 12

.for_each_pde:
	; Fetch the PDPE and check for presence
	mov r13, qword [r12]
	bt  r13, 0
	jnc .next_pde

	; If the entry is not accessed, ignore
	bt  r13, 5
	jnc .next_pde

	; Extract the PT base address, bits 51:12
	bextr r13, r13, 0x280c
	shl   r13, 12

.for_each_pte:
	; Fetch the PTE and check for presence
	mov r14, qword [r13]
	bt  r14, 0
	jnc .next_pte

	; If the entry is not dirty, ignore
	bt  r14, 6
	jnc .next_pte

	; Compute the virtual address for this map
	xor   rbx, rbx
	bextr rax, r10, 0x0c00
	shl   rax, (39 - 3)
	or    rbx, rax
	bextr rax, r11, 0x0c00
	shl   rax, (30 - 3)
	or    rbx, rax
	bextr rax, r12, 0x0c00
	shl   rax, (21 - 3)
	or    rbx, rax
	bextr rax, r13, 0x0c00
	shl   rax, (12 - 3)
	or    rbx, rax

	call rbp

.next_pte:
	btr  qword [r13], 5 ; Clear accessed
	btr  qword [r13], 6 ; Clear dirty
	add  r13, 8
	test r13, 0xfff
	jnz  short .for_each_pte

.next_pde:
	btr  qword [r12], 5 ; Clear accessed
	btr  qword [r12], 6 ; Clear dirty
	add  r12, 8
	test r12, 0xfff
	jnz  .for_each_pde

.next_pdpe:
	btr  qword [r11], 5 ; Clear accessed
	btr  qword [r11], 6 ; Clear dirty
	add  r11, 8
	test r11, 0xfff
	jnz  .for_each_pdpe

.next_pml4:
	btr  qword [r10], 5 ; Clear accessed
	btr  qword [r10], 6 ; Clear dirty
	add  r10, 8
	test r10, 0xfff
	jnz  .for_each_pml4

.done:
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop rbx
	pop rax
	ret

; rdx -> CR3 to clean
mm_clean_all_pages:
	push r10
	push r11
	push r12
	push r13
	push r14

	; Extract the PML4 base address, bits 51:12
	bextr r10, rdx, 0x280c
	shl   r10, 12

.for_each_pml4:
	; Fetch the PML4E and check for presence
	mov r11, qword [r10]
	bt  r11, 0
	jnc .next_pml4

	; Clear both the accessed and dirty flags
	and qword [r10], ~((1 << 6) | (1 << 5))

	; Extract the PDP base address, bits 51:12
	bextr r11, r11, 0x280c
	shl   r11, 12

.for_each_pdpe:
	; Fetch the PDPE and check for presence
	mov r12, qword [r11]
	bt  r12, 0
	jnc .next_pdpe

	; Clear both the accessed and dirty flags
	and qword [r11], ~((1 << 6) | (1 << 5))

	; Extract the PD base address, bits 51:12
	bextr r12, r12, 0x280c
	shl   r12, 12

.for_each_pde:
	; Fetch the PDPE and check for presence
	mov r13, qword [r12]
	bt  r13, 0
	jnc .next_pde

	; Clear both the accessed and dirty flags
	and qword [r12], ~((1 << 6) | (1 << 5))

	; Extract the PT base address, bits 51:12
	bextr r13, r13, 0x280c
	shl   r13, 12

.for_each_pte:
	; Fetch the PTE and check for presence
	mov r14, qword [r13]
	bt  r14, 0
	jnc .next_pte

	; Clear both the accessed and dirty flags
	and qword [r13], ~((1 << 6) | (1 << 5))

.next_pte:
	add  r13, 8
	test r13, 0xfff
	jnz  short .for_each_pte

.next_pde:
	add  r12, 8
	test r12, 0xfff
	jnz  short .for_each_pde

.next_pdpe:
	add  r11, 8
	test r11, 0xfff
	jnz  short .for_each_pdpe

.next_pml4:
	add  r10, 8
	test r10, 0xfff
	jnz  .for_each_pml4

.done:
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	ret

; rsi -> Host resident vaddr to copy from
; rdi -> Guest resident vaddr to copy to
; rcx -> Number of bytes to copy
; rdx -> Guest CR3
; rbp -> Nested CR3
mm_copy_to_guest_vm:
	push rax
	push rbx
	push rcx
	push rsi
	push rdi
	push r8

	; Bail on the nothing to copy case
	test rcx, rcx
	jz   short .done

	; Fetch a host physical mapping to the guest memory
	mov  rbx, rdi
	call mm_guest_virt_to_host_phys_cow
	test rax, rax
	jz   short .done

.lewp:
	; Check if we're on a new page boundry
	test rdi, 0xFFF
	jnz  short .not_new_page

	; If we're on a new page boundry, get the new page address
	mov  rbx, rdi
	call mm_guest_virt_to_host_phys_cow
	test rax, rax
	jz   short .done

.not_new_page:
	mov r8b, byte [rsi]
	mov byte [rax], r8b

	inc rax ; Increment guest paddr
	inc rsi ; Increment host vaddr
	inc rdi ; Increment guest vaddr
	dec rcx ; Decrement count
	jnz short .lewp

.done:
	pop r8
	pop rdi
	pop rsi
	pop rcx
	pop rbx
	pop rax
	ret

; rsi -> Host resident vaddr to copy from
; rdi -> Guest resident vaddr to copy to
; rcx -> Number of bytes to copy
mm_copy_to_guest_vm_vmcb:
	push rax
	push rdx
	push rbp

	mov  rax, [gs:thread_local.VMCB]
	mov  rdx, [rax + VMCB.cr3]
	mov  rbp, [rax + VMCB.n_cr3]
	call mm_copy_to_guest_vm

	pop rbp
	pop rdx
	pop rax
	ret

; rdx -> Address to read qword from
; rdx <- Result
mm_read_guest_qword:
	push rax
	push rsi
	push rdi
	push rcx
	push rbp
	sub  rsp, 0x8

	mov  rdi, rsp
	mov  rsi, rdx
	mov  rcx, 0x8
	mov  rax, [gs:thread_local.VMCB]
	mov  rdx, [rax + VMCB.cr3]
	mov  rbp, [rax + VMCB.n_cr3]
	call mm_copy_from_guest_vm
	mov  rdx, qword [rsp]

	add rsp, 0x8
	pop rbp
	pop rcx
	pop rdi
	pop rsi
	pop rax
	ret

; rdx -> Address to write qword to
; rbx -> Value to write
mm_write_guest_qword:
	push rax
	push rsi
	push rdi
	push rcx
	push rdx
	push rbp
	sub  rsp, 0x8

	mov qword [rsp], rbx

	mov  rsi, rsp
	mov  rdi, rdx
	mov  rcx, 0x8
	mov  rax, [gs:thread_local.VMCB]
	mov  rdx, [rax + VMCB.cr3]
	mov  rbp, [rax + VMCB.n_cr3]
	call mm_copy_to_guest_vm

	add rsp, 0x8
	pop rbp
	pop rdx
	pop rcx
	pop rdi
	pop rsi
	pop rax
	ret

; rdx -> Address to read qword from
; rdx <- Result
mm_read_guest_qword_phys:
	push rax
	push rbx
	push rbp

	mov  rbx, rdx
	mov  rax, [gs:thread_local.VMCB]
	mov  rdx, [rax + VMCB.n_cr3]
	call mm_get_phys
	test rax, rax
	jz   short .fail

	mov rdx, [rax]

.fail:
	pop rbp
	pop rbx
	pop rax
	ret

; rdx -> Address to write qword to
; rbx -> Value to write
mm_write_guest_qword_phys:
	push rax
	push rbx
	push rcx
	push rbp

	push rbx
	mov  rbx, rdx
	mov  rax, [gs:thread_local.VMCB]
	mov  rdx, [rax + VMCB.n_cr3]
	call mm_get_phys_with_cow
	test rax, rax
	pop  rbx
	jz   short .fail

	mov [rax], rbx

.fail:
	pop rbp
	pop rcx
	pop rbx
	pop rax
	ret

; rsi -> Guest resident vaddr to copy from
; rdi -> Host resident vaddr to copy to
; rcx -> Number of bytes to copy
mm_copy_from_guest_vm_vmcb:
	push rax
	push rdx
	push rbp

	mov  rax, [gs:thread_local.VMCB]
	mov  rdx, [rax + VMCB.cr3]
	mov  rbp, [rax + VMCB.n_cr3]
	call mm_copy_from_guest_vm

	pop rbp
	pop rdx
	pop rax
	ret

; rsi -> Guest resident vaddr to copy from
; rdi -> Host resident vaddr to copy to
; rcx -> Number of bytes to copy
; rdx -> Guest CR3
; rbp -> Nested CR3
mm_copy_from_guest_vm:
	push rax
	push rbx
	push rcx
	push rsi
	push rdi
	push r8

	; Bail on the nothing to copy case
	test rcx, rcx
	jz   short .done

	; Fetch a host physical mapping to the guest memory
	mov  rbx, rsi
	call mm_guest_virt_to_host_phys
	test rax, rax
	jz   short .done

.lewp:
	; Check if we're on a new page boundry
	test rsi, 0xFFF
	jnz  short .not_new_page

	; If we're on a new page boundry, get the new page address
	mov  rbx, rsi
	call mm_guest_virt_to_host_phys
	test rax, rax
	jz   short .done

.not_new_page:
	mov r8b, byte [rax]
	mov byte [rdi], r8b

	inc rax ; Increment guest paddr
	inc rsi ; Increment guest vaddr
	inc rdi ; Increment host vaddr
	dec rcx ; Decrement count
	jnz short .lewp

.done:
	pop r8
	pop rdi
	pop rsi
	pop rcx
	pop rbx
	pop rax
	ret

; sil -> Byte to set (second argument to memset())
; rdi -> Guest resident vaddr to copy to
; rcx -> Number of bytes to copy
; rdx -> Guest CR3
; rbp -> Nested CR3
mm_memset:
	push rax
	push rbx
	push rcx
	push rdi
	push r8

	; Bail on the nothing to copy case
	test rcx, rcx
	jz   short .done

	; Fetch a host physical mapping to the guest memory
	mov  rbx, rdi
	call mm_guest_virt_to_host_phys
	test rax, rax
	jz   short .done

.lewp:
	; Check if we're on a new page boundry
	test rdi, 0xFFF
	jnz  short .not_new_page

	; If we're on a new page boundry, get the new page address
	mov  rbx, rdi
	call mm_guest_virt_to_host_phys
	test rax, rax
	jz   short .done

.not_new_page:
	mov byte [rax], sil

	inc rax ; Increment guest paddr
	inc rdi ; Increment guest vaddr
	dec rcx ; Decrement count
	jnz short .lewp

.done:
	pop r8
	pop rdi
	pop rcx
	pop rbx
	pop rax
	ret

; sil -> Byte to set (second argument to memset())
; rdi -> Guest resident vaddr to copy to
; rcx -> Number of bytes to copy
; rdx -> Guest CR3
; rbp -> Nested CR3
mm_memset_backwards:
	push rax
	push rbx
	push rcx
	push rdi
	push r8
	push r9

	; Bail on the nothing to copy case
	test rcx, rcx
	jz   short .done

	; Fetch a host physical mapping to the guest memory
	mov  rbx, rdi
	call mm_guest_virt_to_host_phys
	test rax, rax
	jz   short .done

.lewp:
	; Check if we're on a new page boundry
	mov r9, rdi
	and r9, 0xFFF
	cmp r9, 0xFFF
	jne short .not_new_page

	; If we're on a new page boundry, get the new page address
	mov  rbx, rdi
	call mm_guest_virt_to_host_phys
	test rax, rax
	jz   short .done

.not_new_page:
	mov byte [rax], sil

	dec rax ; Decrement guest paddr
	dec rdi ; Decrement guest vaddr
	dec rcx ; Decrement count
	jnz short .lewp

.done:
	pop r9
	pop r8
	pop rdi
	pop rcx
	pop rbx
	pop rax
	ret

; rcx -> Size in bytes to allocate in the guest
; rcx <- Guest physical address of the allocation
mm_guest_allocate_phys:
	push rax
	push rbx
	push rdx
	push rbp
	push r15

	add rcx,  0xFFF
	and rcx, ~0xFFF
	jz  .done

.try_alloc_phys:
	call xorshift64
	mov  rbx, 0x7FFFFFFFF000
	and  r15, rbx

	; Get the number of pages to allocate
	mov rbp, rcx
	shr rbp, 12
	mov rbx, r15
.next_phys_page:
	; Get the current mapping. If this page is present, try all over again
	mov  rax, [gs:thread_local.VMCB]
	mov  rdx, [rax + VMCB.n_cr3]
	call mm_get_phys
	test rax, rax
	jnz  short .try_alloc_phys

	add rbx, 4096
	dec rbp
	jnz short .next_phys_page

	; rcx - Size to allocate, in bytes
	; r15 - Physical memory location to map to

	mov rbp, rcx
	shr rbp, 12
	mov rbx, r15
.alloc_phys_page:
	push rbp
	call mm_alloc_phys_4k
	push rax
	mov  rax, [gs:thread_local.VMCB]
	mov  rdx, [rax + VMCB.n_cr3]
	pop  rax
	lea  rbp, [rax + 7]
	call mm_map_4k
	pop  rbp

	add rbx, 4096
	dec rbp
	jnz short .alloc_phys_page

	mov rcx, r15

.done:
	pop r15
	pop rbp
	pop rdx
	pop rbx
	pop rax
	ret

; rcx -> Size to allocate in guest (in bytes)
; rcx <- Guest virtual address of the buffer
; The buffer returned from this function is present in both host and guest
; virtual memory. Meaning the host can access this memory directly as well.
mm_guest_allocate_virt:
	push rax
	push rbx
	push rdx
	push rbp
	push r12
	push r13
	push r14
	push r15

	add rcx,  0xFFF
	and rcx, ~0xFFF
	jz  .done

	push rcx
	call mm_guest_allocate_phys
	mov  r14, rcx
	pop  rcx

	; Now we try to find room in the virtual mapping
.try_alloc_virt:
	call xorshift64
	mov  rbx, 0x7FFFFFFFF000
	and  r15, rbx

	; Get the number of pages to allocate
	mov rbp, rcx
	shr rbp, 12
	mov rbx, r15
.next_virt_page:
	; Get the current mapping. If this page is present, try all over again
	mov   rax, [gs:thread_local.VMCB]
	mov   rdx, [rax + VMCB.cr3]
	bextr rax, rbx, 0x0927
	lea   rdx, [rdx + rax*8]
	call  mm_read_guest_qword_phys
	bt    rdx, 0
	jc    .try_alloc_virt

	mov  rdx, cr3
	call mm_get_phys
	test rax, rax
	jnz  short .try_alloc_virt

	add rbx, 4096
	dec rbp
	jnz short .next_virt_page

	; At this point we know that the guest virtual space has enough room for
	; rcx bytes at virtual address r15

	mov r13, rcx
	shr r13, 12
	mov rbx, r15
	mov r12, r14
.map_virt_page:
	lea  rbp, [r12 + 7]
	call mm_guest_map_4k
	test rax, rax
	jz   .try_alloc_virt

	mov  rax, [gs:thread_local.VMCB]
	mov  rdx, [rax + VMCB.cr3]
	mov  rbp, [rax + VMCB.n_cr3]
	call mm_guest_virt_to_host_phys
	test rax, rax
	jz   .try_alloc_virt

	mov  rdx, cr3
	lea  rbp, [rax + 7]
	call mm_map_4k

	add rbx, 4096
	add r12, 4096
	dec r13
	jnz .map_virt_page

	mov rcx, r15

.done:
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbp
	pop rdx
	pop rbx
	pop rax
	ret

; rax <- Guest physical address
guest_alloc_zero_4k:
	push rbx
	push rcx
	push rdx
	push rdi

	mov rax, [gs:thread_local.VMCB]

	mov  rcx, 4096
	call mm_guest_allocate_phys

	mov  rbx, rcx
	mov  rdx, [rax + VMCB.n_cr3]
	call mm_get_phys
	test rax, rax
	jz   panic

	mov  rdi, rax
	mov  rcx, (4096 / 8)
	xor  eax, eax
	rep  stosq

	mov rax, rbx

	pop rdi
	pop rdx
	pop rcx
	pop rbx
	ret

; rbx -> Virtual address to map
; rbp -> Entry to place in for the mapping
mm_guest_map_4k:
	push rcx
	push rdx
	push rsi

	mov rax, [gs:thread_local.VMCB]
	mov rdx, [rax + VMCB.cr3]

	; ------ PML4 -------------------------------------------------

	; Extract the PML4 base address, bits 51:12
	bextr rdx, rdx, 0x280c
	shl   rdx, 12

	; Extract the PML4 offset from bits 47:39 of the vaddr
	bextr rcx, rbx, 0x0927

	; Fetch the PML4E and check for presence
	push rdx
	lea  rdx, [rdx + rcx*8]
	call mm_read_guest_qword_phys
	mov  rsi, rdx
	pop  rdx
	bt   rsi, 0
	jc   .already_mapped_pml4

	; Allocate PML4E as RW, present, and user
	call guest_alloc_zero_4k
	or   rax, 7
	push rbx
	push rdx
	lea  rdx, [rdx + rcx*8]
	mov  rbx, rax
	call mm_write_guest_qword_phys
	pop  rdx
	pop  rbx
	mov  rsi, rax

	; ------ PDP -------------------------------------------------

.already_mapped_pml4:
	; Make sure the memory is user and writable and not a large page
	bt  rsi, 1
	jnc .unmapable_memory
	bt  rsi, 2
	jnc .unmapable_memory
	bt  rsi, 7
	jc  .unmapable_memory

	; Extract the PDP base address, bits 51:12
	bextr rdx, rsi, 0x280c
	shl   rdx, 12

	; Extract the PDP offset from bits 38:30 of the vaddr
	bextr rcx, rbx, 0x091e

	; Fetch the PDPE and check for presence
	push rdx
	lea  rdx, [rdx + rcx*8]
	call mm_read_guest_qword_phys
	mov  rsi, rdx
	pop  rdx
	bt   rsi, 0
	jc   .already_mapped_pdp

	; Allocate PDPE as RW, present, and user
	call guest_alloc_zero_4k
	or   rax, 7
	push rbx
	push rdx
	lea  rdx, [rdx + rcx*8]
	mov  rbx, rax
	call mm_write_guest_qword_phys
	pop  rdx
	pop  rbx
	mov  rsi, rax

	; ------ PD -------------------------------------------------

.already_mapped_pdp:
	; Make sure the memory is user and writable and not a large page
	bt  rsi, 1
	jnc .unmapable_memory
	bt  rsi, 2
	jnc .unmapable_memory
	bt  rsi, 7
	jc  .unmapable_memory

	; Extract the PD base address, bits 51:12
	bextr rdx, rsi, 0x280c
	shl   rdx, 12

	; Extract the PD offset from bits 29:21 of the vaddr
	bextr rcx, rbx, 0x0915

	; Fetch the PDE and check for presence
	push rdx
	lea  rdx, [rdx + rcx*8]
	call mm_read_guest_qword_phys
	mov  rsi, rdx
	pop  rdx
	bt   rsi, 0
	jc   .already_mapped_pde

	; Allocate PDE as RW, present, and user
	call guest_alloc_zero_4k
	or   rax, 7
	push rbx
	push rdx
	lea  rdx, [rdx + rcx*8]
	mov  rbx, rax
	call mm_write_guest_qword_phys
	pop  rdx
	pop  rbx
	mov  rsi, rax

	; ------ PT -------------------------------------------------

.already_mapped_pde:
	; Make sure the memory is user and writable and not a large page
	bt  rsi, 1
	jnc .unmapable_memory
	bt  rsi, 2
	jnc .unmapable_memory
	bt  rsi, 7
	jc  .unmapable_memory

	; Extract the PT base address, bits 51:12
	bextr rdx, rsi, 0x280c
	shl   rdx, 12

	; Extract the PT offset from bits 20:12 of the vaddr
	bextr rcx, rbx, 0x090c

	; Move in specified value as PTE
	push rbx
	push rdx
	lea  rdx, [rdx + rcx*8]
	mov  rbx, rbp
	call mm_write_guest_qword_phys
	pop  rdx
	pop  rbx

	mov eax, 1
	jmp short .done

.unmapable_memory:
	xor eax, eax
.done:
	pop rsi
	pop rdx
	pop rcx
	ret

; rbx -> nested page table to use
iommu_init:
	push rax
	push rbx
	push rcx
	push rdx
	push rbp
	push rdi

	; get the low 32-bits of the IOMMU base address
	mov  eax, (0x00 << 16) | (0x00 << 11) | (0x02 << 8) | (1 << 31) | 0x44
	mov   dx, 0x0CF8
	out   dx, eax
	mov   dx, 0x0CFC
	in   eax, dx
	mov  ebp, eax
	and  ebp, ~0x3FFF

	; get the high 32-bits of the IOMMU base address
	mov  eax, (0x00 << 16) | (0x00 << 11) | (0x02 << 8) | (1 << 31) | 0x48
	mov   dx, 0x0CF8
	out   dx, eax
	mov   dx, 0x0CFC
	in   eax, dx
	shl  rax, 32
	or   rbp, rax

	; rbp now contains the IOMMU base address

	; Allocate the device table
	mov  rcx, (2 * 1024 * 1024)
	call mm_alloc_contig_phys

	; Zero out the device table
	mov  rdi, rax
	mov  rcx, (2 * 1024 * 1024)
	call bzero

	; Create our device table entry template
	; IW   - Enable DMA writes
	; IR   - Enable DMA reads
	; Mode - 4 level page table
	; TV   - Translation information valid
	; V    - DTE valid
	mov rdx, (1 << 62) | (1 << 61) | (4 << 9) | (1 << 1) | (1 << 0)
	or  rdx, rbx ; Add in the page table root pointer

	; Fill in the device table
	xor ecx, ecx
.lewp:
	mov qword [rdi + rcx], rdx

	add ecx, 32
	cmp ecx, (2 * 1024 * 1024)
	jb  short .lewp

	; Set up the device table base (with maximum size of 0x1ff)
	or  rdi, 0x1ff
	mov qword [rbp + 0x00], rdi

	; Enable the IOMMU :)
	bts qword [rbp + 0x18], 0

	pop rdi
	pop rbp
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

; rdi -> Dest
; rsi -> Source
; rcx -> Length
memmove:
memcpy:
	push rcx
	push rsi
	push rdi

	; If there is nothing to be copied, do nothing.
	test rcx, rcx
	jz   short .done

	; If the dest and source are the same, there is no effect, don't copy.
	cmp rsi, rdi
	je  short .done
	ja  short .copy_forwards

.copy_backwards:
	std
	lea rsi, [rsi + rcx - 1]
	lea rdi, [rdi + rcx - 1]

.copy_forwards:
	rep movsb

.done:
	cld
	pop rdi
	pop rsi
	pop rcx
	ret

