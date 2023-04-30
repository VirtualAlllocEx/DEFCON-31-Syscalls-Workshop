<img width="705" alt="Intro_ws_logo" src="https://user-images.githubusercontent.com/50073731/235339663-9c59e27f-57ea-4bbd-8188-e9e2849990f3.png">

# Direct Syscalls: A Journey from High to Low

## Disclaimer 
The content and all code examples int this repository are for teaching and research purpose only and must not be used in an unethical context! The code samples are not new and I make no claim to it. 
- Most of the code comes, as so often, from [**ired.team**](https://www.ired.team/), thank you [**@spotheplanet**](https://twitter.com/spotheplanet) for your brilliant work and sharing it with us all!. 
- For the syscall POCs, [**SysWhispers3**](https://github.com/klezVirus/SysWhispers3) was used, also thanks to [**@KlezVirus**](https://twitter.com/KlezVirus) for his research, providing this awesome code and his article [**SysWhispers is dead, long live SysWhispers!**](https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/)

I would also like to thank all those members of the infosec community who have researched, shaped, and continue to research the topic of direct system calls. Without all of you, this workshop would never have been possible! Please forgive me if I have forgotten anyone.
- [**@Cneelis**](https://twitter.com/Cneelis) from [**@OutflankNL**](https://twitter.com/OutflankNL) and his research and article [**Red Team Tactics: Combining Direct System Calls and sRDI to bypass AV/EDR**](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)
- [**@j00ru**](https://twitter.com/j00ru) for his research in [**syscall tables**](https://j00ru.vexillium.org/syscalls/nt/64/)
- [**@Jackson_T**](https://twitter.com/Jackson_T) for his research and creation of [**SysWhispers**](https://github.com/jthuraisamy/SysWhispers) and [**SysWhispers2**](https://github.com/jthuraisamy/SysWhispers2)
- [**@AliceCliment**](https://twitter.com/AliceCliment) for her research and article [**A Syscall Journey in the Windows Kernel**](https://alice.climent-pommeret.red/posts/a-syscall-journey-in-the-windows-kernel/) and her other research and [**articles**](https://alice.climent-pommeret.red/) in area of syscalls 
- [**@modexpblog**](https://twitter.com/modexpblog) from [**@MDSecLabs**](https://twitter.com/MDSecLabs) and his research and article [**Bypassing User-Mode Hooks and Direct Invocation of System Calls for Red Teams**](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)
- [**@CaptMeelo**](https://captmeelo.com/redteam/maldev/2021/11/18/av-evasion-syswhisper.html) for his research and article [**When You sysWhisper Loud Enough for AV to Hear You**](https://captmeelo.com/redteam/maldev/2021/11/18/av-evasion-syswhisper.html)
- [**@0xBoku**](https://twitter.com/0xBoku) for his overall great research, his [**blog**](https://0xboku.com/) and contributions to infosec, helping new community members, and the continued advancement of infosec 

## Abstract 
The goal of this workshop is to provide new community members or members who want to understand and learn about direct system calls on Windows OS. The workshop includes slides, exercises, and a step-by-step guide. I hope you enjoy it and it can help you get a basic understanding of the red teaming technique of direct system calls.

## Introduction
A system call is a technical instruction in the Windows operating system that allows a temporary transition from user mode to kernel mode. This is necessary, for example, when a user-mode application such as Notepad wants to save a document. Each system call has a specific syscall ID, which can vary from one version of Windows to another. Direct system calls are a technique for attackers (red team) to execute code in the context of Windows APIs via system calls without the targeted application (malware) obtaining Windows APIs from Kernel32.dll or native APIs from Ntdll.dll. The assembly instructions required to switch from user mode to kernel mode are built directly into the malware.

In recent years, more and more vendors have implemented the technique of user-mode hooking, which, simply put, allows an EDR to redirect code executed in the context of Windows APIs to its own hooking.dll for analysis. If the code executed does not appear to be malicious to the EDR, the affected system call will be executed correctly, otherwise the EDR will prevent execution. Usermode hooking makes malware execution more difficult, so attackers (red teams) use various techniques such as API unhooking, direct system calls or indirect system calls to bypass EDRs.

In this workshop we will focus on the **Direct System Call** technique and want to:
- Understand what a system call aka syscall is in Windows OS in general and why we need them.
- Understand what a Direct System Call aka Direct Syscall is and why we as Red Teamers need it. 
- Step-by-step create a direct syscall shellcode dropper, analyze and understand the dropper

 ## What is a System call?
Before we discuss what a direct system call is and how it is used by attackers (red team), it is important to clarify what a system call or syscall is. Technically, at the assembly level, a system call is a set of instructions, also called a syscall stub, that enables the temporary transition (CPU switch) from user mode to kernel mode after the execution of code in Windows user mode in the context of the respective Windows API. The syscall is thus the interface between a user-mode process and the task to be executed in the Windows kernel. What are some of the interesting features of a system call in the Windows operating system for us?
- Each syscall is associated contains a specific syscall ID (syscall number or system service number (SSN)).
- Each syscall or syscall number is associated with a specific native API (NTAPI)
In the following screenshot we can see that the syscall ID 18 is related to the NTAPI ZwAllocateVirtualMemory, but very important, syscall numbers can change from one Windows version to another.![syscall_stub_ID](https://user-images.githubusercontent.com/50073731/235344044-ff5682e2-0f38-4386-937c-5abc675c30a1.png)

## Why do we need system calls at all?
Because a modern operating system like Windows 10 is divided into user mode and kernel mode, syscalls are necessary or responsible for initializing the transition from user mode to kernel mode. For example, system alls in Windows are necessary for:
- Access hardware such as scanners and printers 
- Network connections to send and receive data packets
- Reading and writing files

A practical example in the context of writing a file to disk, the usermode process like notepad.exe wants to save content to disk in the form of a file, the process needs temporary "access" to kernelmode. Why is this necessary? Because the components that need to be accessed or that need to perform the task in kernel mode, such as the file system and the appropriate device drivers, are located in the Windows kernel. The following figure shows the principle and interaction between notepad.exe -> kernel32.dll -> ntdll.dll and syscalls to write a file to disk.![Prinicipal_syscalls_transition_notepad](https://user-images.githubusercontent.com/50073731/235347362-798b0c53-0071-43b4-a06b-74008f1311bf.png)

The figure above shows the technical principle of system calls using the above example with notepad. In order for the save operation to be performed in the context of the user mode process notepad.exe, in the first step it accesses Kernel32.dll and calls the Windows API WriteFile. In the second step, Kernel32.dll accesses Kernelbase.dll in the context of the same Windows API. In the third step, the Windows API WriteFile accesses the Native API NtCreateFile via the Ntdll.dll. The Native API contains the technical instruction to initiate the system call (system call ID) and enables the temporary transition (CPU switch) from user mode (ring 3) to kernel mode (ring 0) after execution.

It then calls the System Service Dispatcher aka KiSystemCall/KiSystemCall64 in the Windows kernel, which is responsible for querying the System Service Descriptor Table (SSDT) for the appropriate function code based on the executed System Call ID (index number in the EAX register). Once the system service dispatcher and the SSDT have worked together to identify the function code for the system call in question, the task is executed in the Windows kernel. Thanks to **@re_and_more** for the cool explanation of the System Service Dispatcher.

In simple terms, system calls are needed in Windows to perform the temporary transition (CPU switch) from user mode to kernel mode, or to execute tasks initiated in user mode that require temporary access to kernel mode - such as saving files - as a task in kernel mode.

## What is a Direct System Call?



