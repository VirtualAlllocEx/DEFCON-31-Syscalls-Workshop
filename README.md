<p align="center">
<img width="700" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/8bdac03d-74ad-4f58-88b9-7380ff25fa97">
</p>

# (In)direct Syscalls: A journey from high to low  
## DEFCON 31 | Red Team Village | RedOps

## Getting Started
All the theory and playbooks for the exercises can be found in the [**wiki**](https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/wiki) and the **POCs** for the **exercises** can be found here on the **main page**. I hope you will enjoy the workshop and that you can use it to gain a better understanding of sycalls, direct sycalls and indirect sycalls. Have fun with it!

**Happy Hacking!**


Daniel Feichter [**@VirtualAllocEx**](https://twitter.com/VirtualAllocEx), Founder [**@RedOps**](https://redops.at/en/) Information Security

## Disclaimer 
First of all, **many thanks** to my girlfriend Brigitte, who has been supporting me in everything I do for over 10 years now. Without her none of this would be possible! Also many thanks to my good friend Andreas Clementi of [**AV-Comparatives**](https://www.av-comparatives.org/), who has supported me since we first met, your support has been invaluable. Also, many thanks to my good friend Robert Rostek of [**Rostech**](https://rostech.at/), who has also supported me in cybersecurity from day one and has pushed me every day with critical questions about all my stuff and answering all my questions. Also, many thanks to my good friend Jonas Kemmner for supporting me and pre-reading all my blog posts. I am very grateful that our paths have crossed. 

The content and all code examples in this repository are for educational and research purposes only and should only be used in an ethical context! The code examples are not new and I do not claim them to be. Most of the code or the basis  comes, as so often, from [**ired.team**](https://www.ired.team/), thank you [**@spotheplanet**](https://twitter.com/spotheplanet) for your brilliant work and sharing it with us all. Also many thanks to [**@mrexodia**](https://twitter.com/mrexodia) for your awesome tool [**x64dbg**](https://twitter.com/x64dbg).

Furthermore, and very importantly, this workshop is **not a silver bullet** in the context of EDR evasion, but it **should help to understand** the basics of ``Win32 APIs``, ``Native APIs``, ``direct syscalls`` and ``indirect syscalls`` and a bit about ``call stacks`` in context of shellcode execution and EDR evasion, no more and no less. The aim of this workshop is not to show the most stealthy options or the most complex pocs for direct syscalls and indirect syscalls, instead I will focus on teaching the basics. This means that we will use as few tools as possible and do as much work as possible by hand. 

I would like to **thank all those members** of the infosec community who have researched, shaped and continue to research the topic of syscalls, direct system calls and indirect syscalls etc. Without all of you, this workshop would not have been possible!

## Creds and References
| Twitter Handle                             					 | Contribution and Research |
| :---:                                         			 | :---: |
| [@spotheplanet](https://twitter.com/spotheplanet)    | His whole awesome blog and research <br /> https://www.ired.team/	|         
| [@NinjaParanoid](https://twitter.com/NinjaParanoid)  | For his blogs, research, courses and always answering my questions. <br /> https://0xdarkvortex.dev/hiding-in-plainsight/ <br /> https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/   | 
| [@ShitSecure](https://twitter.com/ShitSecure) 			 | For his research, his blog https://s3cur3th1ssh1t.github.io/ and for the great discussion about EDRs, syscalls, etc. |         
| [@AliceCliment](https://twitter.com/alicecliment?lang=de) | For her blog, research and the discussions about EDRs, syscalls etc. <br /> https://alice.climent-pommeret.red/posts/how-and-why-to-unhook-the-import-address-table/ <br /> https://alice.climent-pommeret.red/posts/a-syscall-journey-in-the-windows-kernel/ <br /> https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/ | 
| [@Cneelis](https://twitter.com/Cneelis)    					 | https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/  | 
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

- Windows Internals, Part 1: System architecture, processes, threads, memory management, and more (7th Edition) by Pavel Yosifovich, David A. Solomon, and Alex Ionescu
- Windows Internals, Part 2 (7th Edition) by Pavel Yosifovich, David A. Solomon, and Alex Ionescu
- https://offensivecraft.wordpress.com/2022/12/08/the-stack-series-return-address-spoofing-on-x64/
- https://offensivecraft.wordpress.com/2023/02/11/the-stack-series-the-x64-stack/ 
- https://winternl.com/detecting-manual-syscalls-from-user-mode/
