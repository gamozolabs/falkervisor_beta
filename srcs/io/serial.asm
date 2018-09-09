[bits 64]

; init_serial
;
; Summary:
;
; This function prepares the serial port SERIAL_PORT for operation of 115,200
; baud no pairty, one stop bit operation.
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
init_serial:
	push rax
	push rdx

	; Disable all interrupts
	xor al, al
	mov dx, (SERIAL_PORT + 1)
	out dx, al

	; Set DLAB
	mov al, 0b10000000
	mov dx, (SERIAL_PORT + 3)
	out dx, al

	mov al, 0b00000001
	mov dx, (SERIAL_PORT + 0)
	out dx, al

	mov al, 0b00000000
	mov dx, (SERIAL_PORT + 1)
	out dx, al

	mov al, 0b00000011
	mov dx, (SERIAL_PORT + 3)
	out dx, al
	; End Set Baud

	; Disable FIFO
	mov al, 0x00
	mov dx, (SERIAL_PORT + 2)
	out dx, al

	; Enable DTR
	mov al, 0b00001011
	mov dx, (SERIAL_PORT + 4)
	out dx, al

	; Enable data available interrupt
	mov al, 0b00000001
	mov dx, (SERIAL_PORT + 1)
	out dx, al

	pop rdx
	pop rax
	ret

; ser_int
;
; Summary:
;
; This function handles IRQ4, thus serial port interrupts for COM1
;
ser_int:
	push rax
	push rdx
	push rdi

	mov dx, SERIAL_PORT
	out dx, al

	pop rdx
	pop rax
	ret

