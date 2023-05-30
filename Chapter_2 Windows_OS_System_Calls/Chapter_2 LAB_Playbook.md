## LAB Exercise 1: Warm-Up
In **Exercise 1** we will get a feel for native functions, syscalls, syscall stub etc. Therefore we have the following tasks to set up. 

## Exercise 1 tasks:
### Debug Syscall IDs
1. Use WindDbg on your DEV/LAB machine and open or attach to a process like x64 **notepad.exe**.
2. Debug the syscall IDss for the following four native API's that we will need later in the Direct Syscalls chapter.
     - NtAllocateVirtualMemory
     - NtWriteVirtualMemory
     - NtCreateThreadEx
     - NtWaitForSingleObject
3. Write down the syscalls ID's, we will need them later 

### Analyse privilege mode switching
4. Open Procmon and open a new instance of notepad.exe
5. Type some text into notepad.exe and save the file to disk.
6. Using Procmon, search for the operation WriteFile and analyse the call stack for:
     - Win32-API CreateFile in user mode
     - Privilege mode switching by going from user mode to kernel via syscall 
     - Native API NtCreateFile in kernel mode   


## WinDbg
In the first step we will use WinDbg and want to debug the syscall ID's for ``NtAllocateVirtualMemory``, ``NtWriteVirtualMemory``, ``NtCreateThreadEx`` and ``NtWaitForSingleObject``. So we have to use the ``x`` command to extract the memory address from the native API and then use the ``u`` command to unassemble or dissassemble the address to get the contents of the syscall stub from the native function.
<details>
    
**WinDbg**  
```
x ntdll!NtAPI
u memory address 
```
```
x ntdll!NtAllocateVirtualMemory
u 00007ff8`c318d350
```
</details>
    
<details>
    <summary>Solution</summary>  
     <p align="center">
     <img width="560" alt="debug_NtAllocateVirtualMemory" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/db453543-9c25-44d1-bbb8-ec63bb5bf7f8">
     <img width="563" alt="debug_NtWriteVirtualMemory" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/c4040925-a8de-4347-b93d-fff22d1c4d88">
<img width="559" alt="debug_NtCreateThreadEx" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/8da839bc-656a-4d71-943e-308521e59c77">
<img width="560" alt="debug_NtWaitForSingleObject" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/e590c6af-9d3f-413d-acea-b074704ea09c">
     </p>
</details>


## Procmom
In the secon step we use procmon to analyse the privilege mode switching. Therfore we open notepad.exe, write the file to disk by saving the file and then use Procmon to search for the WriteFile operation in context of notepad.exe
    
<details>
    <summary>Solution</summary>  
     We can use two filters in procmon to make it easier
     - process is notepad.exe
     - operation is WriteFile
     <p align="center">
          <img width="563" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/d520c956-6bf6-429f-bd6a-40cf785fe61a">
     </p>
</details>




    
## Summary: Windows OS System Calls
- No direct system calls at all
- Syscall execution over normal transition from high_level_dropper.exe -> kernel32.dll -> ntdll.dll -> syscall
- Dropper imports VirtualAlloc from kernel32.dll...
- ...then imports NtAllocateVirtualMemory from ntdll.dll...
- ...and finally executes the corresponding syscall or syscall stub


