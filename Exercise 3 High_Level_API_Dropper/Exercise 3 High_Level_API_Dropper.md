## Introduction
In this exercise, we want to take the first step towards creating our own direct system call dropper. But to understand the principle of a legitimate
sysall itself, we start by creating a high-level API (HLA) shellcode dropper based on Windows APIs, which will serve as our reference for later modifications. The technical functionality of the high level API is relatively simple and therefore, in my opinion, perfectly suited to gradually develop the high level API dropper into a direct system call dropper. In the HLA dropper we use the following Windows APIs: 
- VirtualAlloc
- WriteProcessMemory
- CreateThread
- WaitForSingleObject

## Workshop tasks: 
- Create a new C++ POC in Visual Studio 2019 and use the provided code for the HLA dropper
- Create staged x64 meterpreter shellcode with msfvenom and copy it into the C++ HLA Dropper POC. 
- Compile the HLA Dropper as release or debug x64 
- Create and run a staged x64 meterpreter listener with msfconsole
- Run your compiled .exe and check if a stable command and control channel opens 
- Use the Visual Studio dumpbin tool to verify that all used Windows APIs are correctly imported by kernel32.dll. 
- Use the API Monitor tool to check the transition from the used Windows APIs to the corresponding native APIs. 
- Use x64 dbg and check where the syscall execution of each used Native API comes from ? Module? Location? 
