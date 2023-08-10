<p align="center">
<img width="700" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/8bdac03d-74ad-4f58-88b9-7380ff25fa97">
</p>

# (In)direct Syscalls: A journey from high to low  
## RedOps | Red Team Village | DEF CON 31

## Getting Started
Ready to rock! The last few months have definitely been a journey from high to low for me. I have challenged myself once again by creating this workshop or project for the **Red Team Village** at **DEF CON 31** and presenting my biggest project yet to the infosec community. I am happy and a bit proud to share my hard work. 

I hope it is useful and a good reference/source of mostly free material for community members to learn or teach others about syscalls, direct syscalls, indirect syscalls.

All the **theory** and **playbooks for the exercises** can be found in the [**wiki**](https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/wiki), which together with the prepared POCs is the heart of this project. The **POCs** for the **exercises** can be found here on the **main page**. 

**Happy Learning!**


Daniel Feichter [**@VirtualAllocEx**](https://twitter.com/VirtualAllocEx), Founder [**@RedOps**](https://redops.at/en/) Information Security

## Disclaimer 
First of all, **many thanks** to my girlfriend, who has supported me in everything I do for over 10 years now! Among 8 billion people, she is and remains my absolute favourite person and my biggest supporter. Without her support and backing none of my projects in the last 10 years would have been possible. 

Thanks also to my good friend Andreas Clementi of [**AV-Comparatives**](https://www.av-comparatives.org/), who has been supporting me since we first met. Also thanks to my friend Jonas Kemmner (who is an excellent Red Teamer) for supporting me and reading all my blog posts in advance. I am very grateful to have crossed paths with all these amazing people.

The content and all code examples in this repository are for educational and research purposes only and should only be used in an ethical context! The code examples are not new and I do not claim them to be. Most of the code or the basis  comes, as so often, from [**ired.team**](https://www.ired.team/), thank you [**@spotheplanet**](https://twitter.com/spotheplanet) for your brilliant work and sharing it with us all. Also many thanks to [**@mrexodia**](https://twitter.com/mrexodia) for your awesome tool [**x64dbg**](https://twitter.com/x64dbg).

Furthermore, and very importantly, this workshop is **not a silver bullet** in the context of EDR evasion, but it **should help to understand** the basics of ``Win32 APIs``, ``Native APIs``, ``direct syscalls`` and ``indirect syscalls`` and a bit about ``call stacks`` in context of shellcode execution and EDR evasion, no more and no less. The aim of this workshop is not to show the most stealthy options or the most complex POCs for direct and indirect syscalls, instead I will focus on teaching the basics.This means using as few tools as possible and doing as much work manually as possible.

I would like to **thank all those members** of the infosec community who have researched, shaped and continue to research the topic of syscalls, direct system calls and indirect syscalls etc. Without all of you, this workshop would not have been possible! 

Special thanks to **Cornelis de Plaa** (@Cneelis) from **Outflank** for his blog post "Combining Direct System Calls and sRDI to bypass AV/EDR" in 2019, which sparked my interest in system calls, direct syscalls, etc., and also marked the starting point of my journey to learn about Windows Internals.

## Creds and References
| Twitter Handle                             					 | Contribution and Research |
| :---:                                         			 | :---: |
| [@Cneelis](https://twitter.com/Cneelis)    					 | https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/  | 
| [@spotheplanet](https://twitter.com/spotheplanet)    | His whole awesome blog and research <br /> https://www.ired.team/	|         
| [@NinjaParanoid](https://twitter.com/NinjaParanoid)  | For his blogs, research, courses and always answering my questions. <br /> https://0xdarkvortex.dev/hiding-in-plainsight/ <br /> https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/   | 
| [@ShitSecure](https://twitter.com/ShitSecure) 			 | For his research, his blog https://s3cur3th1ssh1t.github.io/ and for the great discussion about EDRs, syscalls, etc. |         
| [@AliceCliment](https://twitter.com/alicecliment?lang=de) | For her blog, research and the discussions about EDRs, syscalls etc. <br /> https://alice.climent-pommeret.red/posts/how-and-why-to-unhook-the-import-address-table/ <br /> https://alice.climent-pommeret.red/posts/a-syscall-journey-in-the-windows-kernel/ <br /> https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/ | 
| [@0xBoku](https://twitter.com/0xBoku)								 | For his overall research, and contributions to infosec, helping new community members, and the continued advancement of infosec <br /> https://0xboku.com/ <br /> https://github.com/boku7/AsmHalosGate <br /> https://github.com/boku7/HellsGatePPID <br /> https://github.com/boku7/halosgate-ps| 
| [@Jackson_T](https://twitter.com/Jackson_T)					 | For his research and tools SysWhispers and SysWhispers2 <br /> https://github.com/jthuraisamy/SysWhispers) <br /> https://github.com/jthuraisamy/SysWhispers2 | 
| [@KlezVirus](https://twitter.com/KlezVirus)					 | For his blog, research, great discussions about EDRs, syscalls, etc. and SysWhispers3 <br /> https://github.com/klezVirus/SysWhispers3 <br /> https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/ <br /> https://github.com/klezVirus/SilentMoonwalk							|      
| [@j00ru](https://twitter.com/j00ru)								   | https://j00ru.vexillium.org/syscalls/nt/64/ |   
| [@modexpblog](https://twitter.com/modexpblog)				 | https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/  | 
| [@netero_1010](https://twitter.com/netero_1010)			 | https://www.netero1010-securitylab.com/evasion/indirect-syscall-in-csharp)  |        
| [@CaptMeelo](https://captmeelo.com/redteam/maldev/2021/11/18/av-evasion-syswhisper.html) | https://captmeelo.com/redteam/maldev/2021/11/18/av-evasion-syswhisper.html	 | 	 
| Paul Laîné [@am0nsec](https://twitter.com/am0nsec) and smelly__vx @RtlMateusz |https://github.com/am0nsec/HellsGate/tree/master |
| [@mrd0x](https://twitter.com/mrd0x)                  | https://github.com/Maldev-Academy/HellHall |
| [@SEKTOR7net](https://twitter.com/SEKTOR7net)        | https://blog.sektor7.net/#!res/2021/halosgate.md |
| [@D1rkMtr](https://twitter.com/D1rkMtr)              | https://github.com/TheD1rkMtr/D1rkLdr |  
| [@trickster012](https://twitter.com/trickster012)    | https://github.com/trickster0/TartarusGate |
| [@thefLinkk](https://twitter.com/thefLinkk)          | https://github.com/thefLink/RecycledGate |
| [@ElephantSe4l](https://twitter.com/ElephantSe4l) and MarioBartolome  | https://github.com/crummie5/FreshyCalls |

## Further resources
- Windows Internals, Part 1: System architecture, processes, threads, memory management, and more (7th Edition) by Pavel Yosifovich, David A. Solomon, and Alex Ionescu
- Windows Internals, Part 2 (7th Edition) by Pavel Yosifovich, David A. Solomon, and Alex Ionescu
- https://offensivecraft.wordpress.com/2022/12/08/the-stack-series-return-address-spoofing-on-x64/
- https://offensivecraft.wordpress.com/2023/02/11/the-stack-series-the-x64-stack/ 
- https://winternl.com/detecting-manual-syscalls-from-user-mode/

## Sponsorship
If you are interested in supporting my work in general and/or would like to learn more about how to improve your indirect syscalls shellcode loader step by step, and would like access to the learning materials or playbooks from the three bonus chapters, you can get access via a  **one-time** [GitHub sponsorship](https://github.com/sponsors/VirtualAlllocEx) (Individual student or Corporate students).

| Chapter Nr.       |Chapter Name                | Chapter Description | 
| :---:             | :---:                      |   :---:             |
| **Bonus Chapter 1** |Dynamic SSN retrieval via APIs| We want to improve our indirect syscall shellcode loader and implement dynamic SSN retrieval via the ``GetModuleHandleA`` and ``GetProcAddress`` APIs.|
| **Bonus Chapter 2** |Dynamically Retrieving SSN via PEB/EAT| We want to further improve our indirect syscall shellcode loader and implement dynamic SSN retrieval via the PEB walk and EAT parsing|
| **Bonus Chapter 3** |Indirect Syscalls and hooked APIs | We want to further improve our indirect syscall loader and implement the Halos Gate approach to dynamically retrieve SSNs via PEB/EAT parsing, even if the four used APIs in our loader are hooked by an EDR. |
