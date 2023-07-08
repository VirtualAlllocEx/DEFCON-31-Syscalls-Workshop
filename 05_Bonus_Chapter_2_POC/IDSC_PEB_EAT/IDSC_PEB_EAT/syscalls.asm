.data
	SSN DWORD 000h
	syscallInstr QWORD 0h

.code

	PrepareSSN proc
					mov SSN, ecx
					ret
	PrepareSSN endp

	PrepareSyscallInst proc
			mov syscallInstr, rcx
			ret
	PrepareSyscallInst endp

	NtAllocateVirtualMemory proc
					mov r10, rcx
					mov eax, SSN
					jmp	qword ptr syscallInstr
					ret
	NtAllocateVirtualMemory endp

	/*something is missing here*/
	/*something is missing here*/
	/*something is missing here*/

end
