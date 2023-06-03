![image](https://github.com/VirtualAlllocEx/DEFCON-31-Workshop-Syscalls/assets/50073731/7acf6efa-da5e-47fc-83fe-50f92d18a676)

# (In)direct Syscalls: A journey from high to low  
## DEFCON 31 | Red Team Village

## Disclaimer 
The content and all code examples in this repository are for educational and research purposes only and should only be used in an ethical context! The code examples are not new and I do not claim that they are.

- Most of the code comes, as so often, from [**ired.team**](https://www.ired.team/), thank you [**@spotheplanet**](https://twitter.com/spotheplanet) for your brilliant work and sharing it with us all!. 

I would also like to **thank** all those members of the infosec community who have researched, shaped and continue to research the topic of syscalls, direct system calls and indirect syscalls etc. Without all of you, this workshop would not have been possible! Please forgive me if I have forgotten anyone. 

**Creds to:**

| Name          | Contribution  | 
| ------------- | ------------- |
| Content Cell  | Content Cell  |
| Content Cell  | Content Cell  |


- [**@Cneelis**](https://twitter.com/Cneelis) from [**@OutflankNL**](https://twitter.com/OutflankNL) and his research and article [**Red Team Tactics: Combining Direct System Calls and sRDI to bypass AV/EDR**](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)
- [**@NinjaParanoid**](https://twitter.com/NinjaParanoid) for his research in the are of Windows Internals, EDRs etc. and his articles [**Hiding In PlainSight - Indirect Syscall is Dead! Long Live Custom Call Stacks**](https://0xdarkvortex.dev/hiding-in-plainsight/), [**Hiding In PlainSight - Proxying DLL Loads To Hide From ETWTI Stack Tracing**](https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/)
- [**@j00ru**](https://twitter.com/j00ru) for his research in [**syscall tables**](https://j00ru.vexillium.org/syscalls/nt/64/)
- [**@Jackson_T**](https://twitter.com/Jackson_T) for his research and creation of [**SysWhispers**](https://github.com/jthuraisamy/SysWhispers) and [**SysWhispers2**](https://github.com/jthuraisamy/SysWhispers2)
- Thanks to [**@KlezVirus**](https://twitter.com/KlezVirus) for his research, providing this awesome tool [**SysWhispers3**](https://github.com/klezVirus/SysWhispers3) and his article [**SysWhispers is dead, long live SysWhispers!**](https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/) 
- [**@0xBoku**](https://twitter.com/0xBoku) for his overall great research, his [**blog**](https://0xboku.com/) and contributions to infosec, helping new community members, and the continued advancement of infosec
- [**@zodiacon**](https://twitter.com/zodiacon) for all his [**books**](https://scorpiosoftware.net/books/), his great course about the [**Windows Internals**](https://scorpiosoftware.net/category/training/) and for taking the time to always answer my questions.
- [**@AliceCliment**](https://twitter.com/AliceCliment) for her research and article [**A Syscall Journey in the Windows Kernel**](https://alice.climent-pommeret.red/posts/a-syscall-journey-in-the-windows-kernel/) and her other research and [**articles**](https://alice.climent-pommeret.red/) in area of syscalls 
- [**@modexpblog**](https://twitter.com/modexpblog) from [**@MDSecLabs**](https://twitter.com/MDSecLabs) and his research and article [**Bypassing User-Mode Hooks and Direct Invocation of System Calls for Red Teams**](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)
- **[@netero_1010]**(https://twitter.com/netero_1010) for his research and his article [**Indirect Syscall in CSharp**](https://www.netero1010-securitylab.com/evasion/indirect-syscall-in-csharp)
- [**@CaptMeelo**](https://captmeelo.com/redteam/maldev/2021/11/18/av-evasion-syswhisper.html) for his research and article [**When You sysWhisper Loud Enough for AV to Hear You**](https://captmeelo.com/redteam/maldev/2021/11/18/av-evasion-syswhisper.html)


## Introduction
In recent years, more and more vendors have implemented the technique of user-mode hooking, which, simply put, allows an EDR to redirect code executed in the context of Windows APIs to its own hooking.dll for analysis. If the code executed does not appear to be malicious to the EDR, the affected system call will be executed correctly, otherwise the EDR will prevent execution. User-mode hooking makes malware execution more difficult, so attackers (red teams) use various techniques such as API unhooking, direct system calls or indirect system calls to bypass EDRs.

## Abstract 
This workshop is designed for new community members or members who want to understand and learn about **system calls** in general and the Red Teaming techniques of **direct system calls** and **indirect system calls** on **Windows OS**. The workshop includes original slides from DEFCON 31, and different chapters containing theory, playbooks and code samples. I hope you enjoy it and it can help you get a basic understanding of syscalls and the red teaming techniques of direct syscalls and indirect syscalls.

In this workshop we will focus on the **direct system call** and **indirect system call** techniques and will cover the following topics:
- **Chapter 1: Windows NT Basics**
     - Necessary basics about the Windows NT architecture
- **Chapter 2: Windows OS system calls** 
     - What are system calls in the Windows operating system in general and why are they necessary?
- **Chapter 3: Direct syscalls** 
     - The concept of direct system calls and why we need them as red teamers?
- **Chapter 4: Win32 Dropper** 
     - Create and analyse a shellcode dropper based on Windows APIs (High Level APIs).
- **Chapter 5: Native Dropper** 
     - Build and analyse a shellcode dropper based on Native APIs (mid-level APIs)
- **Chapter 6: Direct Syscall Dropper** 
     - Building and analysing a shellcode dropper based on direct system calls (low level APIs)
- **Chapter 7: Indirect Syscall Dropper** 
     - The concept of indirect system calls and why we need them as red teamers Create and analyse a shellcode dropper based on indirect syscalls (low level APIs).
- **Chapter 8: Direct Syscalls vs Indirect Syscalls** 
     - Compare direct syscall and indirect syscall techniques. What are the limitations of indirect syscalls in the context of EDRs?
- **Chapter 9: Summary** 
     - Workshop summary and closing 

![image](https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/cb154bf0-47bb-4de2-8fe1-ea5eee81a2e0)

## Getting Started
All the step-by-step instructions and code samples can be found in the respective exercise folder. 
### Prerequisites LAB

- **[Windows 10 x64 DEV/LAB machine](https://go.microsoft.com/fwlink/p/?linkid=2195587&clcid=0x407&culture=de-de&country=de)**
    - AV/EPP/EDR disabled
    - [Visual Studio Free 2019](https://visualstudio.microsoft.com/de/vs/older-downloads/)
    - [x64dbg](https://x64dbg.com/)
    - [WinDbg Preview](https://www.microsoft.com/store/productId/9PGJGD53TN86)
    - [Process Hacker](https://processhacker.sourceforge.io/downloads.php)
    - [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmo  
    
- [**Kali Linux**](https://www.kali.org/get-kali/#kali-platforms)
    - Metasploit to create shellcode and an MSF-Listener


I hope you will enjoy the workshop and that you can use it to gain a better understanding of sycalls, direct sycalls and indirect sycalls. Have fun with it!

**Happy Hacking!**

Daniel Feichter [**@VirtualAllocEx**](https://twitter.com/VirtualAllocEx), Founder **[@RedOps](https://redops.at/en/) Information Security** 

## Previous work and references
- https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/
- https://0xdarkvortex.dev/hiding-in-plainsight/
- https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/
- https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/
- https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/
- https://captmeelo.com/redteam/maldev/2021/11/18/av-evasion-syswhisper.html
- https://winternl.com/detecting-manual-syscalls-from-user-mode/
- https://alice.climent-pommeret.red/posts/a-syscall-journey-in-the-windows-kernel/
- https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/#with-freshycalls
- https://www.netero1010-securitylab.com/evasion/indirect-syscall-in-csharp
- https://j00ru.vexillium.org/syscalls/nt/64/
- https://github.com/jthuraisamy/SysWhispers
- https://github.com/jthuraisamy/SysWhispers2
- https://github.com/klezVirus/SysWhispers3
- https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list
- https://www.geoffchappell.com/studies/windows/km/index.htm
- "Windows Internals, Part 1: System architecture, processes, threads, memory management, and more (7th Edition)" by Pavel Yosifovich, David A. Solomon, and Alex Ionescu
- "Windows Internals, Part 2 (7th Edition)" by Pavel Yosifovich, David A. Solomon, and Alex Ionescu
- "Programming Windows, 5th Edition" by Charles Petzold
- "Windows System Architecture" available on Microsoft Docs
- "Windows Kernel Programming" by Pavel Yosifovich
