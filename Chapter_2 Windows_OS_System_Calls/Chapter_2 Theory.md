## What is a System call?
Before we discuss what a direct or indirect system call is and how it is used by attackers (red team), it is important to clarify what a system call or syscall in general is. Technically, the syscall instruction itself is part of the syscall stub within a native API or native function. The syscall stub of a native API is a set of assembly instructions and allows the temporary transition (CPU switch) from user mode to kernel mode after execution. If we take a look at the syscall stubs of different native APIs, we would see that only the syscall number or system service number (SSN), which is moved into the eax register, differs between them. The syscall is thus the interface between a user-mode process and the task to be executed in the Windows kernel. Whar are some key facts about the syscall stub from native functions?
- Each native function contains a specific syscall ID or system service number (SSN) 
- Syscalls IDs can change from Windows to Windows and from version to version
- Important, the syscall instruction is separate instruction and not the syscall ID itself
- The syscall ID or more precise the opcode ```mov``` in the codeline ```mov eax SSN``` can be hooked by an EDR, but the syscall instruction ```syscall``` itself can't be hooked by an EDR (Later on important at indirect syscalls)

In the following screenshot we can see that the ```syscall ID 18``` is related to the native API (NTAPI) ```NtAllocateVirtualMemory```, but as already mentionted, the system service number (SSN) can change. 

![syscall_stub](https://github.com/VirtualAlllocEx/DEFCON-31-Workshop-Syscalls/assets/50073731/982234b9-2b33-4b6f-aa34-9689067175d0)

## Why do we need system calls at all?
Because a modern operating system like Windows 10 is divided into user mode and kernel mode, syscalls are necessary or responsible for initializing the transition from user mode to kernel mode. For example, system alls in Windows are necessary for:
- Access hardware such as scanners and printers 
- Network connections to send and receive data packets
- Reading and writing files

A practical example in the context of writing a file to disk, the usermode process like notepad.exe wants to save content to disk in the form of a file, the process needs temporary "access" to kernelmode. Why is this necessary? Because the components that need to be accessed or that need to perform the task in kernel mode, such as the file system and the appropriate device drivers, are located in the Windows kernel. The following figure shows the principle and interaction between ```notepad.exe -> kernel32.dll -> ntdll.dll and syscalls``` to write a file to disk.

![Prinicipal_syscalls_transition_notepad](https://github.com/VirtualAlllocEx/DEFCON-31-Workshop-Syscalls/assets/50073731/78da40aa-1ac5-4b59-b1ab-951ea9bbd481)

In order for the save operation to be performed in the context of the user mode process notepad.exe, in the first step it accesses ```kernel32.dll``` and calls the Windows API WriteFile. In the second step, ```kernel32.dll``` accesses ```kernelbase.dll``` in the context of the same Windows API. In the third step, the Windows API or Win32 API ```WriteFile``` accesses the Native API ```NtCreateFile``` via ```ntdll.dll```. The Native API contains all the necessary technical instructions in from of the syscall stub (syscall ID (SSN), syscall, etc.) and enables the temporary transition (CPU switch) from user mode (ring 3) to kernel mode (ring 0) after execution.

It then calls the System Service Dispatcher aka KiSystemCall/KiSystemCall64 in the Windows kernel, which is responsible for querying the System Service Descriptor Table (SSDT) for the appropriate function code based on the executed system call ID (index number in the eax register). Once the system service dispatcher and the SSDT have worked together to identify the function code for the system call in question, the task is executed in the Windows kernel. Thanks to **@re_and_more** for the cool explanation of the System Service Dispatcher.

In simple terms, system calls are needed in Windows to perform the temporary transition (CPU switch) from user mode to kernel mode, or to execute tasks initiated in user mode that require temporary access to kernel mode - such as saving files - as a task in kernel mode.
