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

SysWhispers3 creates for us the three files **syscalls.h**, **syscalls.c** and **syscalls-asm.x64.asm**, which we later implement in our LLA-Dropper and which represent the code for the direct syscall implementation. 
<details>
 
<p align="center">
<img width="942" alt="image" src="https://user-images.githubusercontent.com/50073731/235453951-f99fe798-79b9-458e-93af-5d0b3c52a0de.png">
</details>



## Visual Studio
To create the LLA-Dropper project, follow the procedure of the high-level API dropper exercise, take a look to follow the necessary steps.
The code works as follows, shellcode declaration is the same as before in both droppers.
<details>

```
// Insert the Meterpreter shellcode as an array of unsigned chars (replace the placeholder with actual shellcode)
    unsigned char code[] = "\xfc\x48\x83";
```
</details>


In the case of the LLA-Dropper, we also need to access the syscalls or syscalls stub from the respective native APIs. Again, we use the same native APIs as in the MLA-Dropper. 
But this time we do not want to run/import the syscalls from ntdll.dll and instead want to implement the functionality directly in the LLA-Dropper itself, we have to import the generated files/code from SysWhispers 3 into our LLA-Dropper. The syscalls.h provides the structure of the used native APIs NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx and NtWaitForSingleObject and the syscalls-asm.x64.asm contains the corresponding syscalls or syscall stubs. This allows the LLA dropper to execute syscalls directly without the transition from dropper.exe -> kernel32.dll -> ntdll.dll. Practically, we need to implement the generated code with SysWhispers 3 as follows: 

1. Copy all three files we created with SysWhispers 3 into the directory of your LLA-Dropper Visual Studio project.
<details>
 
<p align="center">
<img width="697" alt="image" src="https://user-images.githubusercontent.com/50073731/235456064-2b124b99-6936-4a96-a878-2e8dd8cdb460.png">
</details>

    
2. Add the syscalls.h file to your LLA-Dropper project as a header file. 
<details>
 
<p align="center">
<img width="1269" alt="image" src="https://user-images.githubusercontent.com/50073731/235456468-ffd08548-6f71-4904-821c-6d88580fa3fb.png">
<img width="599" alt="image" src="https://user-images.githubusercontent.com/50073731/235456549-4385fe3d-4a77-49d7-a153-19e0c5e54cf8.png">
</details>

3. We also need to include the header syscalls.h as a library in our code. 
Customisations.
<details>
 
<p align="center">
<img width="1285" alt="image" src="https://user-images.githubusercontent.com/50073731/235458107-e86178b5-f4f2-4110-a415-d93a08f61373.png">
</details>

4. Add the syscalls-asm.x64.asm file as a resource file. 
<details>
 
<p align="center">
<img width="1268" alt="image" src="https://user-images.githubusercontent.com/50073731/235456751-b44a0786-5225-46d7-9ec3-032a6b8ab36c.png">
<img width="590" alt="image" src="https://user-images.githubusercontent.com/50073731/235456831-138e449f-11ae-4cc6-9483-4073eed67c49.png">
</details>

5. Add the file syscall.c as source file
<details>
 
<p align="center">
<img width="1263" alt="image" src="https://user-images.githubusercontent.com/50073731/235457023-473375d1-591d-4479-b47c-2918af056ff2.png">
<img width="598" alt="image" src="https://user-images.githubusercontent.com/50073731/235457085-bf6775f0-c370-4bb0-b883-db99123b06ca.png">
</details>

6. To use the assembly code from the syscalls-asm.x64.asm file in Visual Studio, you must enable the Microsoft Macro Assembler (.masm) option in Build Dependencies/Build. Customisations.
<details>
 
<p align="center">
<img width="1278" alt="image" src="https://user-images.githubusercontent.com/50073731/235457590-371f3519-b7cf-483d-9c1c-6bfd6368be42.png">
<img width="590" alt="image" src="https://user-images.githubusercontent.com/50073731/235457782-780d2136-30d7-4e87-a022-687ed2557b33.png">
</details>

7. Then we need to set the Item Type of the syscalls-asm.x64.asm file to Microsoft Macro Assembler, otherwise we will get an unresolved symbol error in the context of the native APIs used in our LLA dropper. 
<details>
 
<p align="center">
<img width="1237" alt="image" src="https://user-images.githubusercontent.com/50073731/235458968-e330799e-51ff-46bf-97ab-c7d3be7ea079.png">
<img width="778" alt="image" src="https://user-images.githubusercontent.com/50073731/235459219-4387dc48-56f8-481c-b978-1b786843a836.png">
    
</details>


