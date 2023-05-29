![image](https://github.com/VirtualAlllocEx/DEFCON-31-Workshop-Syscalls/assets/50073731/7acf6efa-da5e-47fc-83fe-50f92d18a676)

# (In)direct Syscalls: A Journey from High to Low

## Disclaimer 
The content and all code examples int this repository are for teaching and research purpose only and must not be used in an unethical context! The code samples are not new and I make no claim to it. 
- Most of the code comes, as so often, from [**ired.team**](https://www.ired.team/), thank you [**@spotheplanet**](https://twitter.com/spotheplanet) for your brilliant work and sharing it with us all!. 

I would also like to thank all those members of the infosec community who have researched, shaped, and continue to research the topic of direct system calls. Without all of you, this workshop would never have been possible! Please forgive me if I have forgotten anyone.
- [**@Cneelis**](https://twitter.com/Cneelis) from [**@OutflankNL**](https://twitter.com/OutflankNL) and his research and article [**Red Team Tactics: Combining Direct System Calls and sRDI to bypass AV/EDR**](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)
- [**@j00ru**](https://twitter.com/j00ru) for his research in [**syscall tables**](https://j00ru.vexillium.org/syscalls/nt/64/)
- [**@Jackson_T**](https://twitter.com/Jackson_T) for his research and creation of [**SysWhispers**](https://github.com/jthuraisamy/SysWhispers) and [**SysWhispers2**](https://github.com/jthuraisamy/SysWhispers2)
- Thanks to [**@KlezVirus**](https://twitter.com/KlezVirus) for his research, providing this awesome tool [**SysWhispers3**](https://github.com/klezVirus/SysWhispers3) and his article [**SysWhispers is dead, long live SysWhispers!**](https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/) 
- [**@AliceCliment**](https://twitter.com/AliceCliment) for her research and article [**A Syscall Journey in the Windows Kernel**](https://alice.climent-pommeret.red/posts/a-syscall-journey-in-the-windows-kernel/) and her other research and [**articles**](https://alice.climent-pommeret.red/) in area of syscalls 
- [**@modexpblog**](https://twitter.com/modexpblog) from [**@MDSecLabs**](https://twitter.com/MDSecLabs) and his research and article [**Bypassing User-Mode Hooks and Direct Invocation of System Calls for Red Teams**](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)
- [**@CaptMeelo**](https://captmeelo.com/redteam/maldev/2021/11/18/av-evasion-syswhisper.html) for his research and article [**When You sysWhisper Loud Enough for AV to Hear You**](https://captmeelo.com/redteam/maldev/2021/11/18/av-evasion-syswhisper.html)
- [**@0xBoku**](https://twitter.com/0xBoku) for his overall great research, his [**blog**](https://0xboku.com/) and contributions to infosec, helping new community members, and the continued advancement of infosec 


## Abstract 
This workshop is designed for new community members or members who want to understand and learn about system calls in general and the Red Teaming techniques of direct system calls and indirect system calls on Windows OS. The workshop includes slides, exercises and a step-by-step guide. I hope you enjoy it and it can help you get a basic understanding of the red teaming technique of direct system calls.


## Introduction
In recent years, more and more vendors have implemented the technique of user-mode hooking, which, simply put, allows an EDR to redirect code executed in the context of Windows APIs to its own hooking.dll for analysis. If the code executed does not appear to be malicious to the EDR, the affected system call will be executed correctly, otherwise the EDR will prevent execution. User-mode hooking makes malware execution more difficult, so attackers (red teams) use various techniques such as API unhooking, direct system calls or indirect system calls to bypass EDRs.

In this workshop we will focus on the **direct system call** and **indirect system call** techniques and will cover the following topics:
- **Chapter 1:** Necessary basics about the Windows NT architecture
- **Chapter 2:** What are system calls in the Windows operating system in general and why are they necessary?
- **Chapter 3:** The concept of direct system calls and why we need them as red teamers.
- **Chapter 4:** Create and analyse a shellcode dropper based on Windows APIs (High Level APIs).
- **Chapter 5:** Build and analyse a shellcode dropper based on Native APIs (mid-level APIs)
- **Chapter 6:** Building and analysing a shellcode dropper based on direct system calls (low level APIs)
- **Chapter 7:** The concept of indirect system calls and why we need them as red teamers Create and analyse a shellcode dropper based on indirect syscalls (low level APIs).
- **Chapter 8:** Compare direct syscall and indirect syscall techniques. What are the limitations of indirect syscalls in the context of EDRs?
- **Chapter 9:** Workshop summary 

![image](https://github.com/VirtualAlllocEx/DEFCON-31-Workshop-Syscalls/assets/50073731/96e4bbd1-3753-464b-8975-83129190913c)



## What is a Direct System Call?
This is a technique that allows an attacker (red team) to execute malicious code, e.g. shell code, in the context of APIs on Windows in such a way that the system call is not obtained via Ntdll.dll, but is implemented directly as an assembly instruction, e.g. in the .text region of the malware. Hence the name Direct System Calls.

There are several ways to implement Direct System Calls in malware. In the provided exercise to create your own direct syscall dropper I will show you how to use SysWhispers3 to generate the required syscall or syscall stubs and implement them in the C++ project under Visual Studio as Microsoft Macro Assembler (masm) code.

Compared to the previous illustration in the System Calls chapter, the following illustration shows the principle of direct system calls under Windows in a simplified way. It can be seen that the user-mode process Malware.exe does not get the system call for the Native API NtCreateFile via Ntdll.dll, as would normally be the case, but instead has implemented the necessary instructions for the system call in itself.
![Prinicipal_direct_syscalls](https://user-images.githubusercontent.com/50073731/235348028-506c4e37-f0ae-4fbd-a73c-9ab29fae8f68.png)



## Why Direct System Calls?
Both anti-virus (AV) and endpoint detection and response (EDR) products rely on different defence mechanisms to protect against malware. To dynamically inspect potentially malicious code in the context of Windows APIs, most EDRs today implement the principle of user-mode API hooking. Put simply, this is a technique whereby code executed in the context of a Windows API, such as VirtualAlloc or its native API NtAllocateVirtualMemory, is deliberately redirected by the EDR into the EDR's own Hooking.dll. Under Windows, the following types of hooking can be distinguished, among others:
- Inline API Hooking
- Import Adress Table (IAT) Hooking
- SSDT Hooking (Windows Kernel)

Before the introduction of Kernel Patch Protection (KPP) aka Patch Guard, it was possible for antivirus products to implement their hooks in the Windows kernel, e.g. using SSDT hooking. With Patch Guard, this was prevented by Microsoft for reasons of operating system stability. Most of the EDRs I have analysed rely primarily on inline API hooking. Technically, an inline hook is a 5-byte assembly instruction (also called a jump or trampoline) that causes a redirection to the EDR's Hooking.dll before the system call is executed in the context of the respective native API. The redirection from the Hooking.dll back to the system call in the Ntdll.dll only occurs if the executed code analysed by the Hooking.dll was found to be harmless. Otherwise, the execution of the corresponding system call is prevented by the Endpoint Protection (EPP) component of an EPP/EDR combination. The following figure shows a simplified illustration of how user-mode API hooking works with EDR.
![Prinicipal_usermode_hooking](https://user-images.githubusercontent.com/50073731/235348163-90ce327a-e146-4376-af85-db75d889f4d9.png)



## Consequences for the Red Team
From Red Team's perspective, the usermode hooking technique results in EDR making it difficult or impossible for malware, such as shellcode, to execute. For this reason, Red Teamer as well as malicious attackers use various techniques to bypass EDR usermode hooks. Among others, the following techniques are used individually, but also in combination, e.g. API Unhooking and Direct System Calls.
- Use no hooked APIs
- User mode unhooking 
- Indirect syscalls 
- Direct syscalls 

In this workshop we will only focus on the **Direct System Call** technique, i.e. we will implement Direct System Calls in the dropper later on, thus trying to avoid getting the corresponding system calls from Ntdll.dll, where some EDRs place their usermode hooks. The basics of Direct System Calls and Usermode Hookings should be clear now and the development of the Direct System Call Dropper can begin.



## Getting Started
All the step-by-step instructions and code samples can be found in the respective exercise folder. 
### Prerequisites LAB
- VmWare [Workstation](https://www.vmware.com/go/getworkstation-win) or [VirtualBox](https://www.virtualbox.org/wiki/Downloads)

  - **Windows 10 DEV machine**
    - AV/EPP/EDR disabled
    - [Visual Studio Free 2019](https://visualstudio.microsoft.com/de/vs/older-downloads/)
    - [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
    - [x64dbg](https://x64dbg.com/)
    - [API-Monitor v2](http://www.rohitab.com/downloads) portable or install
    
  - **Windows 10 LAB machine** (Required if you want to do exercise 2 )
    - With Windows Defender or 3rd party AV/EPP/EDR installed
    - [WinDbg Preview](https://www.microsoft.com/store/productId/9PGJGD53TN86)
  
  - [**Kali Linux**](https://www.kali.org/get-kali/#kali-platforms)
    - [SysWhispers3](https://github.com/klezVirus/SysWhispers3)


## Happy Hacking!
I hope you enjoy the direct syscall workshop. Have fun with it!


Daniel Feichter [**@VirtualAllocEx**](https://twitter.com/VirtualAllocEx)



## Previous work and references
- https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/
- https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/
- https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/
- https://captmeelo.com/redteam/maldev/2021/11/18/av-evasion-syswhisper.html
- https://winternl.com/detecting-manual-syscalls-from-user-mode/
- https://alice.climent-pommeret.red/posts/a-syscall-journey-in-the-windows-kernel/
- https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/#with-freshycalls
- https://redops.at/en/blog/direct-syscalls-a-journey-from-high-to-low
- https://j00ru.vexillium.org/syscalls/nt/64/
- https://github.com/jthuraisamy/SysWhispers
- https://github.com/jthuraisamy/SysWhispers2
- https://github.com/klezVirus/SysWhispers3
- Windows internals. Part 1 Seventh edition; Yosifovich, Pavel; Ionescu, Alex; Solomon, David A.; Russinovich, Mark E.
- Pavel Yosifovich (2019): Windows 10 System Programming, Part 1: CreateSpace Independent Publishing Platform
