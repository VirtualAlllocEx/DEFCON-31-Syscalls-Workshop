# Tartarus' Gate - Bypassing EDRs

<p align="center">
    <img height="500" alt="OffensiveRust" src="https://github.com/trickster0/TartarusGate/raw/master/tartarus.jpg">
</p>

### Description

Hell's Gate evolved to Halo's Gate to bypass EDRs by unhooking some of them and now it turned to Tartarus' Gate to handle even more WINAPI hooking methods.  

I have added some more ASM commands just for "obfuscation" for the syscalls.  
To use, just simply replace without shellcode, that is in .text segment on purpose although it will work in any other segments. I will let you figure out why.  

The custom method of "memcpy" is replaced with NtWriteVirtualMemory since it did not work very well with certain EDRs but if you still want to use it, just comment the line of NtWriteVirtualMemory and uncomment the VxMoveMemory. 

### Credits / References
##### Reenz0h from @SEKTOR7net (Creator of the HalosGate technique )
  + This HalosGate project is based on the work of Reenz0h.
  + Most of the C techniques I use are from Reenz0h's awesome courses and blogs 
  + Best classes for malware development out there.
  + Creator of the halos gate technique. His work was the motivation for this work.
  + https://blog.sektor7.net/#!res/2021/halosgate.md 
  + https://institute.sektor7.net/
##### @smelly__vx & @am0nsec ( Creators/Publishers of the Hells Gate technique )
  + Awesome work on this method, really enjoyed working through it myself. Thank you!
  + https://github.com/am0nsec/HellsGate 
  + Link to the Hell's Gate paper: https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf
