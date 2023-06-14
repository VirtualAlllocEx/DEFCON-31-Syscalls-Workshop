## What is a System call?
Before we discuss what a direct or indirect system call is and how it is used by attackers (red team), it is important to clarify what a system call or syscall is in general. Technically, the syscall instruction itself is part of the syscall stub within a native API or native function. The syscall stub of a native API is a set of assembly instructions and allows the temporary transition (CPU switch) from user mode to kernel mode after execution. If we look at the syscall stubs of different native APIs, we would see that only the syscall number or system service number (SSN), which is moved into the eax register, differs between them. The syscall is thus the interface between a user-mode process and the task to be executed in the Windows kernel. We could also say that system calls provide the bridge from user mode to kernel mode. 

What are some key facts about the syscall stub from native functions?

- Each native function contains a specific syscall ID or System Service Number (SSN).
- Only the SSN differs from native function to native function, the rest of the syscall stub structure is always the same.  
- Syscall IDs can change from Windows to Windows and from version to version.
- Important, the syscall instruction is a separate instruction and not the syscall ID itself.
- The syscall ID or more precisely the opcode ``mov`` in the codeline ``mov eax SSN`` can be hooked by an EDR, but the syscall instruction ``syscall`` itself can't be hooked by an EDR (important later for indirect syscalls).

In the following screenshot we can see that the ``syscall ID 18`` is related to the native API (NTAPI) ``NtAllocateVirtualMemory``, but as already mentioned, the System Service Number (SSN) can change. 

![syscall_stub](https://github.com/VirtualAlllocEx/DEFCON-31-Workshop-Syscalls/assets/50073731/982234b9-2b33-4b6f-aa34-9689067175d0)

## Why do we need system calls at all?
Because a modern operating system like Windows 10 is divided into user mode and kernel mode, syscalls are necessary or responsible for initialising the transition from user mode to kernel mode. For example, system calls in Windows are needed to
- Access hardware such as scanners and printers 
- Network connections to send and receive packets
- Reading and writing files

As a practical example, in the context of writing a file to disk, if a usermode process such as notepad.exe wants to save content to disk in the form of a file, the process needs temporary 'access' to kernel mode. Why is this necessary? Because the components that need to be accessed or that need to perform the task in kernel mode, such as the file system and the appropriate device drivers, are located in the Windows kernel. The following figure shows the principle and interaction between ``notepad.exe`` -> ``kernel32.dll`` -> ``kernelbase.dll`` -> ``ntdll.dll`` -> ``syscalls`` to write a file to disk.

![Prinicipal_syscalls_transition_notepad](https://github.com/VirtualAlllocEx/DEFCON-31-Workshop-Syscalls/assets/50073731/78da40aa-1ac5-4b59-b1ab-951ea9bbd481)

In order for the save operation to be performed in the context of the user mode process notepad.exe, in the first step it accesses ``kernel32.dll`` and calls the Windows API WriteFile. In the second step, ``kernel32.dll`` accesses ``kernelbase.dll`` in the context of the same Windows API. In the third step, the Windows API or Win32 API ``WriteFile`` calls the Native API ``NtCreateFile`` via ``ntdll.dll``. The Native API contains all the necessary technical instructions in from of the syscall stub (syscall ID (SSN), syscall, etc.) and enables the temporary transition (CPU switch) from user mode (ring 3) to kernel mode (ring 0) after execution.

It then calls the System Service Dispatcher aka KiSystemCall/KiSystemCall64 in the Windows kernel, which is responsible for querying the System Service Descriptor Table (SSDT) for the appropriate function code based on the executed system call ID (index number in the eax register). Once the system service dispatcher and the SSDT have worked together to identify the function code for the system call in question, the task is executed in the Windows kernel. 

It is important to note that ntdll.dll is not the only module in Windows user mode that is used to call native functions and also execute the syscall in the memory region of that module. To interact with the Windows GUI wrapper functions in e.g. ``user32.dll`` or ``gdi32.dll`` can be used to access or execute the native functions in ``win32u.dll``. Why is this important, because later we will see that EDRs set their hooks not only in ntdll.dll, but depending on the EDR they set different hooks in many different modules in user mode. 

![Prinicipal_syscalls_transition_notepad_win32dll](https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/36d74bc2-604b-4908-bf53-b1964b33ede6)

If we use x64dbg to look at the native functions imported from ntdll.dll or win32u.dll, we will see that Nt* and Zw* functions are found in ntdll.dll and NtUser* and NtGdi* functions are found in win32u.dll. Just to check, by comparing the syscall stub of the native functions from ntdll.dll and win32u.dll, we can see that, as expected, the syscall stub is exactly the same, only the SSN differs from function to function. 

<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/ba48a2d7-4073-400a-bcdc-76932e23c931">
</p>
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/2a39fc31-63ef-45d9-8891-2ca8b1dc5c24">
</p>


In Summary and simple terms, **system calls are needed** in Windows to perform the (temporary) **transition** (CPU switch) **from user mode to kernel mode**, or to execute tasks initiated in user mode that require temporary access to kernel mode - such as saving files - as a task in kernel mode.
