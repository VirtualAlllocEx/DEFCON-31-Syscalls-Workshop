## Exercise 5: Low_Level_API_Dropper
In this exercise, we will make the second modification to the reference dropper, create the direct syscall dropper, and implement the required syscalls or syscall stub directly into the **Low-Level API shellcode dropper** for short **LLA dropper**. 
![low_level_dropper_principal](https://user-images.githubusercontent.com/50073731/235438881-e4af349a-0109-4d8e-80e2-730915c927f6.png)

## Exercise 5 tasks:
### Create LLA-Dropper 
1. Create necessary code for LLA-Dropper with SysWhispers3
1. Create a new C++ POC in Visual Studio 2019 and use the provided code for the LLA-Dropper.
2. Create staged x64 meterpreter shellcode with msfvenom and copy it to the C++ LLA-Dropper poc. 
3. Compile the LLA-Dropper as release or debug x64. 
4. Create and run a staged x64 meterpreter listener with msfconsole.
5. Run your compiled .exe and verify that a stable command and control channel opens. 
### Analyse HLA-Dropper
6. Use the Visual Studio tool dumpbin to analyze the compiled LLA-Dropper. Is the result what you expected?  
7. Use the API Monitor to analyze the compiled LLA-Dropper in the context of the four APIs used. Is the result what you expected? 
8. Use the x64dbg debugger to analyze the compiled LLA dropper: from which module and location are the syscalls from the four APIs used being executed?
Is the result what you expected? 

## SysWhispers 3
Again, we need to implement the code for the four native APIs we use, but unlike the Medium_Level dropper, we do not load the corresponding syscalls from ntdll.dll. Instead, we want to implement the necessary code directly in our LLA dropper. Therefore we have to create the corresponding code or files with the tool SysWhispers3 from [**@KlezVirus**](https://twitter.com/KlezVirus). To create the necessary code in context of our LLA-Dropper you can use the following command with SysWhispers. Because we work with the MSVC compiler in Visual Studio we choose for the -c parameter msvc. 
<details>
    
**kali>**
```
python syswhispers.py -a x64 -c msvc -f NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx,NtWaitForSingleObject -o syscalls -v
```
</details>

SysWhispers creates for us the three files syscalls.h, syscalls.c and syscalls-asm.x64.asm, which we later implement in our LLA-Dropper and which represent the code for the direct syscall implementation. 
<details>
 
<p align="center">
<img width="942" alt="image" src="https://user-images.githubusercontent.com/50073731/235453951-f99fe798-79b9-458e-93af-5d0b3c52a0de.png">
</details>




## Visual Studio
To create the LLA-Dropper project, follow the procedure of the high-level API dropper exercise, take a look to follow the necessary steps. In this case, we will not load the required syscalls or syscall stub from ntll.dll, but will implement them directly in the LLA-Dropper itself. Shellcode declaration same as before in both droppers.
<details>

```
// Insert the Meterpreter shellcode as an array of unsigned chars (replace the placeholder with actual shellcode)
    unsigned char code[] = "\xfc\x48\x83";
```
</details>


