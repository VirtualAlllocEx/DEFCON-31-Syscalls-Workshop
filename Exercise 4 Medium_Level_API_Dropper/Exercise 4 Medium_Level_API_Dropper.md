## Introduction: Exercise 3 High_Level_API_Dropper
In this exercise, we will make the first modification to the reference dropper and replace the Windows APIs (Kernel32.dll) with native APIs (Ntdll.dll).
We create a **medium-level API shellcode dropper** in short **MLA-dropper** based on native APIs. 
![medium_level_dropper_principal](https://user-images.githubusercontent.com/50073731/235372969-4d24ddec-7ee5-443e-966a-24b3d70dc3a8.png)



## Workshop tasks: Exercise 3 High_Level_API_Dropper
1. Create a new C++ POC in Visual Studio 2019 and use the provided code for the MLA Dropper.
2. Create staged x64 meterpreter shellcode with msfvenom and copy it to the C++ MLA Dropper POC. 
3. Compile the MLA Dropper as release or debug x64. 
4. Create and run a staged x64 meterpreter listener with msfconsole.
5. Run your compiled .exe and verify that a stable command and control channel opens. 
6. Use the Visual Studio dumpbin to verify that the Windows APIs are no longer being imported by kernel32.dll. 
7. Use the API Monitor tool to verify that there are no more transitions from Windows APIs to Native APIs related to the MLA dropper. 
8. Use x64 dbg and check where the syscall execution of each used native API comes from ? Module? Location? 


## Visual Studio
Same procedure as in the high-level API dropper exercise, take a look to follow the necessary steps.
We replace all Windows APIs with the corresponding native APIs and create our MLA dropper.
- VirtualAlloc -> NtAllocateVirtualMemory
- WriteProcessMemory -> NtWriteVirtualMemory
- CreateThread -> CreateThreadEx
- WaitForSingleObject -> NtWaitForSingleObject
