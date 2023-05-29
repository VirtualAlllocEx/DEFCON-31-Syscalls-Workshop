## What is a System call?
Before we discuss what a direct or indirect system call is and how it is used by attackers (red team), it is important to clarify what a system call or syscall is. Technically, the syscall instruction itself is part of a syscall stub within a native API or native function. The syscall stub of a native API is a set of assembly instructions and allows the temporary transition (CPU switch) from user mode to kernel mode after execution. If we take a look at the syscall stubs of different native APIs, we would see that only the syscall number or system service number (SSN), which is moved into the eax register, differs between them. The syscall is thus the interface between a user-mode process and the task to be executed in the Windows kernel. What are some of the interesting features of a system call in the Windows operating system for us?
- Each syscall is associated contains a specific syscall ID (syscall number or system service number (SSN)).
- Each syscall or syscall number is associated with a specific native API (NTAPI)
In the following screenshot we can see that the syscall ID 18 is related to the NTAPI ZwAllocateVirtualMemory, but very important, syscall numbers can change from one Windows version to another. 

      ![syscall_stub_ID](https://github.com/VirtualAlllocEx/DEFCON-31-Workshop-Syscalls/assets/50073731/9e046ae0-79aa-43d7-acbd-3db912c9b966)


## Why do we need system calls at all?
Because a modern operating system like Windows 10 is divided into user mode and kernel mode, syscalls are necessary or responsible for initializing the transition from user mode to kernel mode. For example, system alls in Windows are necessary for:
- Access hardware such as scanners and printers 
- Network connections to send and receive data packets
- Reading and writing files

A practical example in the context of writing a file to disk, the usermode process like notepad.exe wants to save content to disk in the form of a file, the process needs temporary "access" to kernelmode. Why is this necessary? Because the components that need to be accessed or that need to perform the task in kernel mode, such as the file system and the appropriate device drivers, are located in the Windows kernel. The following figure shows the principle and interaction between notepad.exe -> kernel32.dll -> ntdll.dll and syscalls to write a file to disk.

![Prinicipal_syscalls_transition_notepad](https://github.com/VirtualAlllocEx/DEFCON-31-Workshop-Syscalls/assets/50073731/78da40aa-1ac5-4b59-b1ab-951ea9bbd481)


The figure above shows the technical principle of system calls using the above example with notepad. In order for the save operation to be performed in the context of the user mode process notepad.exe, in the first step it accesses Kernel32.dll and calls the Windows API WriteFile. In the second step, Kernel32.dll accesses Kernelbase.dll in the context of the same Windows API. In the third step, the Windows API WriteFile accesses the Native API NtCreateFile via the Ntdll.dll. The Native API contains the technical instruction to initiate the system call (system call ID) and enables the temporary transition (CPU switch) from user mode (ring 3) to kernel mode (ring 0) after execution.

It then calls the System Service Dispatcher aka KiSystemCall/KiSystemCall64 in the Windows kernel, which is responsible for querying the System Service Descriptor Table (SSDT) for the appropriate function code based on the executed System Call ID (index number in the EAX register). Once the system service dispatcher and the SSDT have worked together to identify the function code for the system call in question, the task is executed in the Windows kernel. Thanks to **@re_and_more** for the cool explanation of the System Service Dispatcher.

In simple terms, system calls are needed in Windows to perform the temporary transition (CPU switch) from user mode to kernel mode, or to execute tasks initiated in user mode that require temporary access to kernel mode - such as saving files - as a task in kernel mode.
