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

| Twitter Handle                             						           | Contribution and Research |
| :---:                                         				          | :---:                                                                                                                 																		    																					 		    |
| [@spotheplanet](https://twitter.com/spotheplanet)           | His whole awesome blog and research <ul><li>https://www.ired.team/</ul></li>					   																																																						|         
| [@NinjaParanoid](https://twitter.com/NinjaParanoid) 			     | For his great blogs, research, courses and always answering my questions. <ul><li>https://0xdarkvortex.dev/hiding-in-plainsight/</li><li>https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/)</li></ul>   | 


