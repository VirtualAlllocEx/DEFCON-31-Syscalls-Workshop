<p align="center">
<img width="700" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Workshop-Syscalls/assets/50073731/7acf6efa-da5e-47fc-83fe-50f92d18a676">
</p>

# (In)direct Syscalls: A journey from high to low  
## DEFCON 31 | Red Team Village | RedOps

## Getting Started
All the theory and playbooks for the exercises can be found in the [**wiki**](https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/wiki) and the **POCs** for the **exercises** can be found here on the **main page**. I hope you will enjoy the workshop and that you can use it to gain a better understanding of sycalls, direct sycalls and indirect sycalls. Have fun with it!

**Happy Hacking!**


Daniel Feichter [**@VirtualAllocEx**](https://twitter.com/VirtualAllocEx), Founder **[@RedOps](https://redops.at/en/) Information Security**

## Disclaimer 
The content and all code examples in this repository are for educational and research purposes only and should only be used in an ethical context! The code examples are not new and I do not claim them to be. Most of the code or the basis  comes, as so often, from [**ired.team**](https://www.ired.team/), thank you [**@spotheplanet**](https://twitter.com/spotheplanet) for your brilliant work and sharing it with us all. Also many thanks to [**@mrexodia**](https://twitter.com/mrexodia) for your awesome tool [**x64dbg**](https://twitter.com/x64dbg).

Furthermore, and very importantly, this workshop is **not a silver bullet** in the context of EDR evasion, but it **should help to understand** the basics of ``Win32 APIs``, ``Native APIs``, ``direct syscalls`` and ``indirect syscalls`` and a bit about ``call stacks`` in context of shellcode execution and EDR evasion, no more and no less. The aim of this workshop is not to show the most stealthy options or the most complex pocs for direct syscalls and indirect syscalls, instead I will focus on teaching the basics. This means that we will use as few tools as possible and do as much work as possible by hand. 

I would like to **thank all those members** of the infosec community who have researched, shaped and continue to research the topic of syscalls, direct system calls and indirect syscalls etc. Without all of you, this workshop would not have been possible!

**Creds and references**

| Twitter Handle                             					 | Contribution and Research |
| :---:                                         			 | :---: |
| [@spotheplanet](https://twitter.com/spotheplanet)    | His whole awesome blog and research <br /> https://www.ired.team/	|         
| [@NinjaParanoid](https://twitter.com/NinjaParanoid)  | For his blogs, research, courses and always answering my questions. <br /> https://0xdarkvortex.dev/hiding-in-plainsight/ <br /> https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/   | 
| [@ShitSecure](https://twitter.com/ShitSecure) 			 | For his research, his blog https://s3cur3th1ssh1t.github.io/ and for the great discussion about EDRs, syscalls, etc. |         
| [@AliceCliment](https://twitter.com/alicecliment?lang=de) | For her blog, research and the discussions about EDRs, syscalls etc. <br /> https://alice.climent-pommeret.red/posts/how-and-why-to-unhook-the-import-address-table/ <br /> https://alice.climent-pommeret.red/posts/a-syscall-journey-in-the-windows-kernel/ <br /> https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/ | 
| [@Cneelis](https://twitter.com/Cneelis)    					 | https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/  | 
| [@0xBoku](https://twitter.com/0xBoku)								 | For his overall research, and contributions to infosec, helping new community members, and the continued advancement of infosec <br /> https://0xboku.com/ <br /> https://github.com/boku7/AsmHalosGate <br /> https://github.com/boku7/HellsGatePPID <br /> https://github.com/boku7/halosgate-ps| 


