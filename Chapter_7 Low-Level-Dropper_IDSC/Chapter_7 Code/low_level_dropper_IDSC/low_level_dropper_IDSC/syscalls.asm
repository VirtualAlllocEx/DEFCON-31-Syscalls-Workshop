EXTERN sysAddrNtAllocateVirtualMemory:QWORD         ; The actual address of the NtAllocateVirtualMemory syscall in ntdll.dll.
EXTERN sysAddrNtWriteVirtualMemory:QWORD            ; The actual address of the NtWriteVirtualMemory syscall in ntdll.dll.
EXTERN sysAddrNtCreateThreadEx:QWORD                ; The actual address of the NtCreateThreadEx syscall in ntdll.dll.
EXTERN sysAddrNtWaitForSingleObject:QWORD           ; The actual address of the NtWaitForSingleObject syscall in ntdll.dll.


.CODE  ; Start the code section

; Procedure for the NtAllocateVirtualMemory syscall
NtAllocateVirtualMemory PROC
    mov r10, rcx                                    ; Move the contents of rcx to r10. This is necessary because the syscall instruction in 64-bit Windows expects the parameters to be in the r10 and rdx registers.
    mov eax, 18h                                    ; Move the syscall number into the eax register.
    jmp QWORD PTR [sysAddrNtAllocateVirtualMemory]  ; Jump to the actual syscall.
NtAllocateVirtualMemory ENDP                     	; End of the procedure.


; Similar procedures for NtWriteVirtualMemory syscalls
NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, 3AH
    jmp QWORD PTR [sysAddrNtWriteVirtualMemory]
NtWriteVirtualMemory ENDP


; Similar procedures for NtCreateThreadEx syscalls
NtCreateThreadEx PROC
    mov r10, rcx
    mov eax, 0C2h
    jmp QWORD PTR [sysAddrNtCreateThreadEx]
NtCreateThreadEx ENDP


; Similar procedures for NtWaitForSingleObject syscalls
NtWaitForSingleObject PROC
    mov r10, rcx
    mov eax, 4
    jmp QWORD PTR [sysAddrNtWaitForSingleObject]
NtWaitForSingleObject ENDP

END  ; End of the module