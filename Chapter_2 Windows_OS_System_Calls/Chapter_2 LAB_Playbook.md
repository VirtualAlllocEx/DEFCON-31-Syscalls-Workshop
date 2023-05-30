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
<img width="696" alt="debug_NtAllocateVirtualMemory" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/c56a082a-1c07-45fa-a2e1-ee3b84a6f3f8">
     </p>
     ![debug_ntwritevirtualmemory](https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/75488770-a0a6-455e-b1a4-57c4f1196307)

</details>




    
## Summary: High-level API Dropper
- No direct system calls at all
- Syscall execution over normal transition from high_level_dropper.exe -> kernel32.dll -> ntdll.dll -> syscall
- Dropper imports VirtualAlloc from kernel32.dll...
- ...then imports NtAllocateVirtualMemory from ntdll.dll...
- ...and finally executes the corresponding syscall or syscall stub


