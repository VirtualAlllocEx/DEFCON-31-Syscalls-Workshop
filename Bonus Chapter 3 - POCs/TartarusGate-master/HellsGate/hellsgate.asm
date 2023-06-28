; Hell's Gate
; Dynamic system call invocation 
; 
; by smelly__vx (@RtlMateusz) and am0nsec (@am0nsec)

.data
	wSystemCall DWORD 000h

.code 
	HellsGate PROC
		nop
		mov wSystemCall, 000h
		nop
		mov wSystemCall, ecx
		nop
		ret
	HellsGate ENDP

	HellDescent PROC
		nop
		mov rax, rcx
		nop
		mov r10, rax
		nop
		mov eax, wSystemCall
		nop
		syscall
		ret
	HellDescent ENDP
end
