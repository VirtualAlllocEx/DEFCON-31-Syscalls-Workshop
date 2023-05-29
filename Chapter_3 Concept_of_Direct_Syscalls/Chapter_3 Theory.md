## What is a Direct System Call?
This is a technique that allows an attacker (red team) to execute malicious code, e.g. shell code, in such a way that the **system call or syscall stub** is not obtained via ntdll.dll, but is **implemented directly** as an assembly instruction, e.g. in the .text region of the malware. Hence the name direct system calls. There are now several tools and POCs such as SysWhispers2, SysWhispers3, Hell's Gate, Halo's Gate etc. that can be used to implement or exploit the capabilities of direct system calls in your own malware.

But in this course we will deliberately not use any of them, because I want to keep all the C and assembler code used as simple as possible and focus on teaching you the concept of direct and indirect syscalls in a proper way. The code examples provided definitely do not use the most stealthy code and depend on the EDR, Windows version etc. but I found it the best way to teach the concept of direct and indirect sycalls in the best and most practical way. All the POCs needed for this course can be found in the relevant chapter as a Visual Studio project. 

Compared to the previous illustration in the System Calls chapter, the following illustration shows the principle of direct system calls on Windows in a simplified way. You can see that the user mode process malware.exe does not get the system call, or more precisely the instructions from the sycall stub, from the native API NtCreateFile via ntdll.dll, as would normally be the case, but instead has implemented the necessary instructions for the system call itself.
![Prinicipal_direct_syscalls](https://github.com/VirtualAlllocEx/DEFCON-31-Workshop-Syscalls/assets/50073731/16e74b5c-f470-48d8-b674-3740e695c621)


## Why Direct System Calls?
Both anti-virus (AV) and endpoint detection and response (EDR) products rely on different defence mechanisms to protect against malware. To dynamically inspect potentially malicious code in the context of Windows APIs, most EDRs today implement the principle of user-mode API hooking. Put simply, this is a technique whereby code executed in the context of a Windows API, such as VirtualAlloc or its native API NtAllocateVirtualMemory, is deliberately redirected by the EDR into the EDR's own "hooking.dll". Under Windows, the following types of hooking can be distinguished, among others:
- Inline API Hooking
- Import Adress Table (IAT) Hooking
- SSDT Hooking (Windows Kernel)

Before the introduction of Kernel Patch Protection (KPP) aka Patch Guard, it was possible for antivirus products to implement their hooks in the Windows kernel, e.g. using SSDT hooking. With Patch Guard, this was prevented by Microsoft for reasons of operating system stability. Most of the EDRs I have analysed rely primarily on inline API hooking. Technically, an inline hook is a 5-byte assembly instruction (also called a jump or trampoline) that causes a redirection to the EDR's hooking.dll before the system call is executed in the context of the respective native API. The return from the memory of the EDR's hooking.dll back to the memory of the respective native function in ntdll.dll for the final execution of the sycall instruction only occurs if the code executed in the context of the respective native function was determined by the EDR to be harmless, otherwise the execution of the corresponding system call is prevented by the Endpoint Protection (EPP) component of an EPP/EDR combination. The following diagram provides a simplified illustration of how user-mode API hooking works with EDR.
![Prinicipal_usermode_hooking](https://github.com/VirtualAlllocEx/DEFCON-31-Workshop-Syscalls/assets/50073731/444c4bab-78d7-4fa3-9443-a53182891e27)


## Consequences for the Red Team
From Red Team's perspective, the usermode hooking technique results in EDR making it difficult or impossible for malware, such as shellcode, to execute. For this reason, Red Teamer as well as malicious attackers use various techniques to bypass EDR usermode hooks. Among others, the following techniques are used individually, but also in combination, e.g. API Unhooking and Direct System Calls.
- Use no hooked APIs
- User mode unhooking 
- Indirect syscalls 
- Direct syscalls 

In this workshop we will only focus on the **Direct System Call** technique, i.e. we will implement Direct System Calls in the dropper later on, thus trying to avoid getting the corresponding system calls from Ntdll.dll, where some EDRs place their usermode hooks. The basics of Direct System Calls and Usermode Hookings should be clear now and the development of the Direct System Call Dropper can begin.
