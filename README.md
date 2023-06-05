![image](https://github.com/VirtualAlllocEx/DEFCON-31-Workshop-Syscalls/assets/50073731/7acf6efa-da5e-47fc-83fe-50f92d18a676)

# (In)direct Syscalls: A journey from high to low  
## DEFCON 31 | Red Team Village | RedOps

## Disclaimer 
The content and all code examples in this repository are for educational and research purposes only and should only be used in an ethical context! The code examples are not new and I do not claim that they are.

- Most of the code comes, as so often, from [**ired.team**](https://www.ired.team/), thank you [**@spotheplanet**](https://twitter.com/spotheplanet) for your brilliant work and sharing it with us all!. 

Furthermore, and very importantly, this workshop is not a silver bullet in the context of EDR evasion, but it should help to understand the basics of direct syscalls and indirect syscalls and a little bit about call stacks, no more and no less. This workshop do not cover  

I would also like to **thank all those members** of the infosec community who have researched, shaped and continue to research the topic of syscalls, direct system calls and indirect syscalls etc. Without all of you, this workshop would not have been possible!

**Creds to:**

| Twitter Handle                             						 | Contribution and Research                                                                                                      															    																					 	  			| Company |
| :---:                                         				     | :---:                                                                                                                 																		    																					 		    |:---: | 
| [@spotheplanet](https://twitter.com/spotheplanet)             	 |   [His whole blog and research](https://www.ired.team/)					   																																																						|         |
| [@NinjaParanoid](https://twitter.com/NinjaParanoid) 			     | For his great blogs, research, courses and always answering my questions. [Hiding In PlainSight - Indirect Syscall is Dead! Long Live Custom Call Stacks](https://0xdarkvortex.dev/hiding-in-plainsight/), [Hiding In PlainSight - Proxying DLL Loads To Hide From ETWTI Stack Tracing](https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/)   | [Dark Vortex](https://0xdarkvortex.dev/), [Brute Ratel](https://bruteratel.com/)|
| [@ShitSecure](https://twitter.com/ShitSecure) 					 | For is great research in general, his blog https://s3cur3th1ssh1t.github.io/ and for the great discussion about EDRs, syscalls, etc.     																																						|         |
| [@KlezVirus](https://twitter.com/KlezVirus)						 | For his great blogs, research and great discussions about EDRs, syscalls, etc. [SysWhispers3](https://github.com/klezVirus/SysWhispers3), [SysWhispers is dead, long live SysWhispers!](https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/), [SilentMoonwalk](https://github.com/klezVirus/SilentMoonwalk)										    |         |
| [@Cneelis](https://twitter.com/Cneelis)    						 | [Red Team Tactics: Combining Direct System Calls and sRDI to bypass AV/EDR](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)   		 			  																		        | [OutflankNL](https://outflank.nl/) |
| [@0xBoku](https://twitter.com/0xBoku)								 | For his overall great research, his [blog](https://0xboku.com/) and contributions to infosec, helping new community members, and the continued advancement of infosec                                                                                                                 			| [IBM X-Force Red](https://www.ibm.com/x-force/team) |
| [@Jackson_T](https://twitter.com/Jackson_T)						 | [SysWhispers](https://github.com/jthuraisamy/SysWhispers), [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2)																							 															     			    |         |
| [@j00ru](https://twitter.com/j00ru)								 | [syscall tables](https://j00ru.vexillium.org/syscalls/nt/64/)                                                                                                         																												 			|         |
| [@modexpblog](https://twitter.com/modexpblog)					     | [Bypassing User-Mode Hooks and Direct Invocation of System Calls for Red Teams](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)        																				  			| [@MDSecLabs](https://www.mdsec.co.uk/      )  |
| [@netero_1010](https://twitter.com/netero_1010)			         |  [Indirect Syscall in CSharp](https://www.netero1010-securitylab.com/evasion/indirect-syscall-in-csharp) 																						  																							        |         |
| [@CaptMeelo](https://captmeelo.com/redteam/maldev/2021/11/18/av-evasion-syswhisper.html) | [When You sysWhisper Loud Enough for AV to Hear You](https://captmeelo.com/redteam/maldev/2021/11/18/av-evasion-syswhisper.html) 																																	        | 	      | 


## Introduction
In recent years, more and more vendors have implemented the technique of user-mode hooking, which, simply put, allows an EDR to redirect code executed in the context of Windows APIs to its own hooking.dll for analysis. If the code executed does not appear to be malicious to the EDR, the affected system call will be executed correctly, otherwise the EDR will prevent execution. User-mode hooking makes malware execution more difficult, so attackers (red teams) use various techniques such as API unhooking, direct system calls or indirect system calls to bypass EDRs.

## Abstract 
This workshop is designed for new community members or members who want to understand and learn about **system calls** in general and the Red Teaming techniques of **direct system calls** and **indirect system calls** on **Windows OS**. The workshop includes original slides from DEFCON 31, and different chapters containing theory, playbooks and code samples. I hope you enjoy it and it can help you get a basic understanding of syscalls and the red teaming techniques of direct syscalls and indirect syscalls.

In this workshop we will focus on the **direct system call** and **indirect system call** techniques and will cover the following topics:
- **Chapter 1: Windows NT Basics**
     - Necessary basics about the Windows NT architecture
- **Chapter 2: Windows OS system calls** 
     - What are system calls in the Windows operating system in general and why are they necessary?
- **Chapter 3: Concept of Direct syscalls** 
     - The concept of direct system calls and why we need them as red teamers?
- **Chapter 4: Win32 APIs** 
     - Create and analyse a shellcode dropper based on Windows APIs (High Level APIs).
- **Chapter 5: Native APIs** 
     - Create and analyse a shellcode dropper based on Native APIs (mid-level APIs)
- **Chapter 6: Direct Syscalls** 
     - Create and analyse a shellcode dropper based on direct system calls (low level APIs)
- **Chapter 7: Indirect Syscalls** 
     - The concept of indirect system calls and why we need them as red teamers? Create and analyse a shellcode dropper based on indirect syscalls (low level APIs).
- **Chapter 8: Call stack analysis** 
     - Compare the call stack from each dropper and compare them to each other. What is the advantage of indirect sycalls over direct syscalls in the context of EDR evasion?
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
    - [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)  
    
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
- https://offensivecraft.wordpress.com/2022/12/08/the-stack-series-return-address-spoofing-on-x64/
- https://offensivecraft.wordpress.com/2023/02/11/the-stack-series-the-x64-stack/
- https://j00ru.vexillium.org/syscalls/nt/64/
- https://github.com/jthuraisamy/SysWhispers
- https://github.com/jthuraisamy/SysWhispers2
- https://github.com/klezVirus/SysWhispers3
- https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list
- https://www.geoffchappell.com/studies/windows/km/index.htm
- "Windows Internals, Part 1: System architecture, processes, threads, memory management, and more (7th Edition)" by Pavel Yosifovich, David A. Solomon, and Alex Ionescu
- "Windows Internals, Part 2 (7th Edition)" by Pavel Yosifovich, David A. Solomon, and Alex Ionescu
