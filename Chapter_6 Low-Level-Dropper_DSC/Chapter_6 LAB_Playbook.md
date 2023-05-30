## LAB Exercise 4:Direct Syscall Dropper
In this exercise we will make the second modification to the reference dropper, create the direct syscall dropper and implement the required syscalls or syscall stubs from each of the four native functions directly into the assembly (dropper). We call this the Low Level Direct Syscall Dropper, or LLDSC for short. 
![low_level_dropper_principal](https://user-images.githubusercontent.com/50073731/235438881-e4af349a-0109-4d8e-80e2-730915c927f6.png)

## Exercise 4 Tasks:
### Creating the Direct Syscall Dropper 
1. Download the LLDSC Visual Studio POC from the Code section of this chapter.
2. Most of the code is already implemented in the POC. But take a look at the .asm file and add the missing assembler code for the remaining three native APIs following the scheme of the already implemented code for the NTallocateVirtualMemory native API. 
3. Create x64 calc shellcode with msfvenom, copy it to the POC, compile it and run it for the first time. Check that the calc spawns correctly. 
4. Create a staged x64 meterpreter shellcode with msfvenom and copy it to the POC or replace the calc shellcode with it.  
5. Compile the POC as an x64 release. 
6. Create and run a staged x64 meterpreter listener using msfconsole.
7. Run your compiled .exe and check that a stable command and control channel opens. 
### Analysing the Direct Syscall Dropper
8. Use the Visual Studio **dumpbin** tool to analyse the dropper. Is the result what you expected?  
9. Use the **API Monitor** tool to analyse the compiled low level dropper in the context of the four APIs used. Is the result what you expected? 
10. Use the **x64dbg** debugger to analyse the compiled low level dropper: from which module and location are the syscalls of the four APIs used executed? Is the result what you expected? 
11. Use Process Hacker to analyse the call stack of the direct syscall dropper.


## Visual Studio
To create the Low-Level-Dropper project, follow the procedure of the High-Level-Dropper exercise, take a look to follow the necessary steps.
The code works as follows, shellcode declaration is the same as before in both droppers.
<details>
<summary>Details</summary>
```
// Insert the Meterpreter shellcode as an array of unsigned chars (replace the placeholder with actual shellcode)
    unsigned char code[] = "\xfc\x48\x83";
```
</details>
