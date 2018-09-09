%define SERIAL_PORT 0x3f8

%define DMA_BUFFER_ZONE 0x60000000

%define MPIC_CTRL 0x20
%define MPIC_DATA 0x21
%define SPIC_CTRL 0xA0
%define SPIC_DATA 0xA1

%define PIC_ICW4 0x01
%define PIC_INIT 0x10

%define PIC_8086 0x01

%define IRQ07_MAP 0x20
%define IRQ8F_MAP 0x28

%define MEMORY_MAP_LOC 0x500

%define MAX_NODES 8
%define MAX_CORES 64
%define NUM_CORES 64

%define VM_STATE_DUMP 0xe7c928b1

; Must be a page-size multiple!
%define GLOBAL_STORAGE (1024 * 1024)

%define MAX_NUM_MODULES 512

%macro XMMPUSH 1
	sub    rsp, 16
	movdqu [rsp], %1
%endmacro

%macro XMMPOP 1
	movdqu %1, [rsp]
	add    rsp, 16
%endmacro

%macro DBGPRINT 1
	push rdi
	push rdx
	mov  rdx, %1
	call per_core_screen
	call outhexq
	pop  rdx
	pop  rdi
%endmacro

;%define ASLR

; bamp_alloc
;
; Summary:
;
; This is the core allocator for the system. It is a simple linear allocator
; which is thread safe. All allocations are ensured to be 4KB aligned
;
; Parameters:
;
; %1 - Number of bytes to allocate
;
; Alignment:
;
; None
;
; Returns:
;
; %1 - Address to allocated memory
;
; Smashes:
;
; %1 - Return value
;
; Optimization
;
; Speed
;
%macro bamp_alloc 1
%if %1 != rsi
	push rsi
	mov  rsi, %1
%endif

	call bamp_alloc_int

%if %1 != rsi
	mov  %1, rsi
	pop  rsi
%endif
%endmacro

%macro rand_alloc 1
%if %1 != rsi
	push rsi
	mov  rsi, %1
%endif

	call rand_alloc_int

%if %1 != rsi
	mov  %1, rsi
	pop  rsi
%endif
%endmacro

%macro mixed_alloc 1
%if %1 != rax
	push rax
%endif
%if %1 != rcx
	push rcx
%endif

	mov  rcx, %1
	call mm_mixed_alloc
	mov  %1, rax

%if %1 != rcx
	pop rcx
%endif
%if %1 != rax
	pop rax
%endif
%endmacro

struc node_struct
	.orig_data: resq 1         ; Original data pointer
	.data_len:  resq 1         ; Length of data (in bytes)
	.node_data: resq MAX_NODES ; Each nodes pointer to data
	.node_race: resq MAX_NODES ; Locks for each node
endstruc

struc i825xx_dev
	.pcireq:       resq 1
	.mmio_base:    resq 1
	.rx_ring_base: resq 1
	.tx_ring_base: resq 1
	.tx_tail:      resq 1
	.rx_tail:      resq 1
	.rxed_count:   resq 1
endstruc

