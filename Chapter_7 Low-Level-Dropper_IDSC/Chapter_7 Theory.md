## What is an Indirect System Call?
The indirect syscall technique is more or less an evolution of the direct syscall technique. By using indirect syscalls we are able to execute the syscall instruction itself and the return instruction from the memory of ntdll.dll instead of the memory of the assembly iteself as with direct syscalls. Compared to direct syscalls, indirect syscalls can solve the following EDR evasion problems 

- Firstly, the execution of the syscall command takes place within the memory of the ntdll.dll and is therefore legitimate for the EDR. 
- On the other hand, the execution of the return statement takes place within the memory of the ntdll.dll and points from the memory of the ntdll.dll to the memory of the indirect syscall assembly.

As we will see later, compared to the direct syscall POC, simplified, only a part of the stub from the Native API is implemented and executed directly in the indirect syscall assembly itself, while the syscall statement and return are executed in the ntdll.dll memory. More on this later. The following diagram should help you to understand the concept of indirect syscalls, bearing in mind that it is a simplified representation.

![image](https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/573dc07e-3aed-48c2-b661-6c1e70d71087)
