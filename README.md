<img width="705" alt="Intro_ws_logo" src="https://user-images.githubusercontent.com/50073731/235339663-9c59e27f-57ea-4bbd-8188-e9e2849990f3.png">

# Direct Syscalls: A Journey from High to Low

## Disclaimer 
The content and all code examples int this repository are for teaching and research purpose only and must not be used in an unethical context! The code samples are not new and I make no claim to it. Most of the code comes, as so often, from **ired.team, thank you @spotheplanet for your brilliant work and sharing it with us all!**. For the syscall POCs, **Syswhispers3** was used, also thanks to **@KlezVirus** for providing this awesome code. 


## Abstract 
A system call is a technical instruction in the Windows operating system that allows a temporary transition from user mode to kernel mode. This is necessary, for example, when a user-mode application such as Notepad wants to save a document. Each system call has a specific syscall ID, which can vary from one version of Windows to another. Direct system calls are a technique for attackers (red team) to execute code in the context of Windows APIs via system calls without the targeted application (malware) obtaining Windows APIs from Kernel32.dll or native APIs from Ntdll.dll. The assembly instructions required to switch from user mode to kernel mode are built directly into the malware.

In recent years, more and more vendors have implemented the technique of user-mode hooking, which, simply put, allows an EDR to redirect code executed in the context of Windows APIs to its own hooking.dll for analysis. If the code executed does not appear to be malicious to the EDR, the affected system call will be executed correctly, otherwise the EDR will prevent execution. Usermode hooking makes malware execution more difficult, so attackers (red teams) use various techniques such as API unhooking, direct system calls or indirect system calls to bypass EDRs.

In this article, I will focus on the Direct System Call technique and show you how to create a Direct System Call shellcode dropper step-by-step using Visual Studio in C++. I will start with a dropper that only uses the Windows APIs (High Level APIs). In the second step, the dropper undergoes its first development and the Windows APIs are replaced by Native APIs (Medium Level APIs). And in the last step, the Native APIs are replaced by Direct System Calls (Low Level APIs).

 
