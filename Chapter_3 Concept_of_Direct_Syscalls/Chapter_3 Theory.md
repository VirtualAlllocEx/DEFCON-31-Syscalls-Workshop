## What is a Direct System Call?
This is a technique that allows an attacker (red team) to execute malicious code, e.g. shell code, in such a way that the **system call or syscall stub** is not obtained via ntdll.dll, but is **implemented directly** as an assembly instruction, e.g. in the .text region of the malware. Hence the name direct system calls. There are now several tools and POCs such as SysWhispers, SysWhispers2, SysWhispers3, Hell's Gate, Halo's Gate etc. that can be used to implement or exploit the capabilities of direct system calls in your own malware.

But in this course we will deliberately not use them, or use them less, because I want to keep all the C and assembler code used as simple as possible, and concentrate on teaching you the concept of direct and indirect syscalls in a proper way. The code examples provided definitely do not use the most stealthy code, but I found it the best way to teach the concept of direct and indirect sycalls in the best and most practical way. All the POCs needed for this course can be found in the relevant chapter as a Visual Studio project. 

Compared to the previous illustration in the system calls chapter, the following illustration shows the principle of direct system calls on Windows in a simplified way. You can see that the user mode process malware.exe does not get the system call, or more precisely the instructions from the sycall stub, from the native API NtCreateFile via ntdll.dll, as would normally be the case, but instead has implemented the necessary instructions for the system call itself.
![Prinicipal_direct_syscalls](https://github.com/VirtualAlllocEx/DEFCON-31-Workshop-Syscalls/assets/50073731/16e74b5c-f470-48d8-b674-3740e695c621)


## Why Direct System Calls?
Both anti-virus (AV) and endpoint detection and response (EDR) products rely on different defence mechanisms to protect against malware. To dynamically inspect potentially malicious code in the context of Windows APIs, most EDRs today implement the principle of **user-mode API hooking**. Put simply, this is a technique whereby code executed in the context of a Windows API, such as VirtualAlloc or its native API NtAllocateVirtualMemory, is deliberately redirected by the EDR into the EDR's own "hooking.dll". Under Windows, the following types of hooking can be distinguished, among others:
- Inline API Hooking
- Import Adress Table (IAT) Hooking
- SSDT Hooking (Windows Kernel)

Before the introduction of Kernel Patch Protection (KPP) aka Patch Guard, it was possible for antivirus products to implement their hooks in the Windows kernel, e.g. using SSDT hooking. With Patch Guard, this was prevented by Microsoft for reasons of operating system stability. Most of the EDRs I have analysed rely primarily on inline API hooking. Technically, an inline hook is a ``5-byte`` assembly instruction (also called a jump or trampoline) that causes a redirection to the EDR's hooking.dll before the system call is executed in the context of the respective native API. The return from the memory of the EDR's hooking.dll back to the memory of the respective native function in ntdll.dll for the final execution of the sycall instruction only occurs if the code executed in the context of the function was determined by the EDR to be harmless, otherwise the execution of the corresponding system call is prevented by the Endpoint Protection (EPP) component of an EPP/EDR combination. The following diagram provides a simplified illustration of how user-mode API hooking works with EDR.
![Prinicipal_usermode_hooking](https://github.com/VirtualAlllocEx/DEFCON-31-Workshop-Syscalls/assets/50073731/84f0ca7c-5c8c-48b9-a215-36d20fc7e2a6)

Important note! Because ntdll.dll is more or less a common denominator in user space before the transition to kernel mode, many EDRs set their user mode hooks in ntdll.dll. But depending on the EDR, they also set their hooks in other important DLLs in user space. Based on my research by analysing different EDRs, here are some examples where they set their user mode hooks in different DLLs in user space. 

| DLL Name           | Examples of hooked APIs          |
| :---:              | :---:                            |
| ntdll.dll          | NtAllocateVirtualMemory          |
| user32.dll         | NtUserSetWindowLong              |
| kernel32.dll       | CreateRemoteThread               |
| kernelbase.dll     | CreateRemoteThreadEx             |
| combase.dll        | CoGetInstanceFromIStorage        |
| crypt32.dll        | CryptUnprotectData               |
| ole32.dll          | CoGetObject                      |
| samcli.dll         | NetUserAdd                       |  
| shell32.dll        | Shell_NotifyIconW                |
| advapi32.dll       | ClearEventLogA                   |
| sechost.dll        | StartServiceW                    |
| wevtapi.dll        | EvtOpenSession                   |
|wininet.dll         | InternetConnectA                 |

The total number of hooks varies from vendor to vendor or from EDR to EDR. There are EDRs that have around 20 hooks and their other EDRs that have around 90 hooks. It is also important to note that an EDR will never be able to hook all APIs in user mode, otherwise the performance impact would be dramatic. Never forget that a good EDR will try to protect as much as possible, but also stay in the background as much as possible and not slow down a system too much.  

## Consequences for the Red Team
From Red Team's perspective, the usermode hooking technique results in EDR making it difficult or impossible for malware, such as shellcode, to execute. For this reason, Red Teamer as well as malicious attackers use various techniques to bypass EDR usermode hooks. Among others, the following techniques are used individually, but also in combination, e.g. API Unhooking and Direct System Calls.
- Use no hooked APIs
- User mode unhooking 
- Indirect syscalls 
- Direct syscalls 

In this workshop we will focus on the **direct syscall** and **indirect syscall** technique, i.e. we will create a direct syscall and an indirect syscall shellcode dropper step by step. The basics of direct syscalls and usermode hookings should now be clear, and the development of the direct syscall dropper can begin. 
