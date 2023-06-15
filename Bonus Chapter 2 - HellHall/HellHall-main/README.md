## HellsHall - Another Way To Fetch Clean Syscalls

HellsHall is a combination of [HellsGate](https://github.com/am0nsec/HellsGate) and indirect syscalls.  

<br>


## How it works

First, HellsHall checks whether the *syscall address* is hooked and tries to retrieve the syscall number by checking the presence of the following bytes: 

`0x4C, 0x8B, 0xD1, 0xB8` which represent `mov r10,rcx && mov eax,SSn`. This is how every syscall should start.

At this point, HellsGate simply grabs the Syscall SSn (Syscall Number) and uses it **directly** resulting in a syscall being called from outside of the address space of `ntdll.dll`. This is an IoC in itself and can be used to detect such syscalls. Detection Examples:

* [Detecting Manual Syscalls from User Mode](https://winternl.com/detecting-manual-syscalls-from-user-mode/)

* [Detecting Direct Syscalls with Frida](https://passthehashbrowns.github.io/detecting-direct-syscalls-with-frida)

HellsHall however will search for a `syscall` instruction near the address of the syscall function and then save this *syscall's instruction's address* to a global variable which will be jumped to later on rather than executing this instruction directly from the `asm` file. This will cause the syscall function to be executed from inside of `ntdll.dll` address space with the only difference being that it's unhooked.

## Enhancement

[TartarusGate](https://github.com/trickster0/TartarusGate) can be used to further enhance this technique.

<br>


## HellsGate

![image](https://user-images.githubusercontent.com/111295429/210207400-594383fb-158f-415c-9e3a-2d3d43198644.png)

<br>

## HellsHall

![image](https://user-images.githubusercontent.com/111295429/210207411-f6dca820-dbfe-4c87-bb33-60e0d036bd73.png)


<br>

## Profit
Bypassing The Below EDR using [This HellsHall Implementation](https://github.com/Maldev-Academy/HellHall/blob/main/Hell'sHall-Clang%26NoCrt.zip) That is Using `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, and `NtCreateThreadEx` syscalls with an `RWX` section. 

![image](https://user-images.githubusercontent.com/111295429/210299245-d366566a-0e14-4622-8bb0-91fd645a9d2e.png)


<br>

## Code
The Github repo can be found [here](https://github.com/Maldev-Academy/HellHall)

<br>

## Authors

* NULL (@NUL0x4C)
* mr.d0x (@mrd0x)

