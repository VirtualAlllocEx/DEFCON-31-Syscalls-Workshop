## Architecture of Windows NT
Before we begin our journey into syscalls, direct syscalls and indirect syscalls, we need to understand some basics about the architecture of Windows NT.
Introduced in 1993, the Microsoft Windows New Technology (NT) operating system marked a pivotal moment in the evolution of Microsoft's operating systems. It represented a significant departure from its predecessors, providing a robust, secure and versatile platform tailored for enterprise applications.

Understanding the nature of this transition requires a brief look back at the state of Windows before NT. The pre-NT versions of Windows were essentially 16-bit systems that functioned more as graphical shells on top of MS-DOS. They had limitations such as limited memory usage and a lack of memory protection between processes. Security and networking features were minimal and often rudimentary. This architectural design often led to system instability and inefficiencies that hindered the overall performance of the operating system.

Windows NT, released in 1993 with Windows NT 3.1 brought a paradigm shift with its 32-bit architecture and a host of advanced features. Unlike its predecessors, NT was a completely new operating system designed from the ground up to run on multiple hardware platforms. It introduced cutting-edge features such as symmetric multiprocessing, improved memory management and comprehensive networking support.

## User Mode and Kernel Mode
One of the major changes to the Windows NT architecture was to split it into user mode and kernel mode. The decision to split Windows into user mode and kernel mode was primarily driven by the need to increase system stability, reliability and security.

<p align="center">
<img width="409" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Workshop-Syscalls/assets/50073731/2c9c1d23-1917-487f-9b6e-4194c430dbf3">
</p>

1. **Stability**: By separating user mode from kernel mode, any bugs, crashes, or malfunctions that occur in user mode programs will not directly affect the kernel or other system components. In other words, a crashing user-mode application won't bring down the entire system because the kernel remains isolated and protected.

2. **Security**: The separation also increases the security of the system. User-mode applications cannot directly access the hardware or memory of other applications or kernel processes. Any access must be through system calls, which can be controlled and monitored, making unauthorised or malicious actions much more difficult.

3. **Control and resource management**: The kernel, running in kernel mode, has complete control over the machine's resources. This allows better and more efficient management of these resources. It decides when and how to allocate resources, such as CPU time or memory, to user mode processes.

4. **Isolation and abstraction**: Kernel mode also provides an abstraction layer between the hardware and the user mode software. This means that applications can be written to interact with the kernel, rather than being written specifically for a particular hardware configuration.

By maintaining a clear boundary between user mode and kernel mode, Windows ensures that both system stability and security are less likely to be compromised by faulty or malicious applications. It's a design principle common to many modern operating systems, not just Windows.

### User Mode
Key components in user mode include the Win32 subsystem, which provides the API used by most Windows applications, and the security subsystem, which handles logins and permissions. At the heart of the NT architecture, User Mode provides a controlled, secure environment in which most software operates. Applications running in this mode do not have direct access to system hardware or memory, but instead interact with the hardware through system calls and APIs, ensuring that system-level resources are protected from potentially damaging operations. User mode is the domain of third-party software, user interfaces, and many of the built-in Windows components such as the shell and Windows services. Key elements within this mode include the Win32 subsystem, which provides the API used by most Windows applications, and the security subsystem, which is responsible for critical security functions such as logins and permissions.

### Kernel Mode
In contrast, kernel mode is a privileged realm reserved for the core functions of the operating system. Here, code has unrestricted access to the system's hardware and memory, facilitating direct and efficient interaction with the system's resources. It's where the Windows kernel, the hardware abstraction layer (HAL), device drivers, and certain system services reside. Core components in this space include the executive, which manages vital system tasks such as I/O, object security and more; the Windows kernel itself; and the HAL, which abstracts hardware specifics and provides a consistent, platform-independent interface for the kernel.

### References 
- "Windows Internals, Part 1: System architecture, processes, threads, memory management, and more (7th Edition)" by Pavel Yosifovich, David A. Solomon, and Alex Ionescu
- "Windows Internals, Part 2 (7th Edition)" by Pavel Yosifovich, David A. Solomon, and Alex Ionescu
- "Programming Windows, 5th Edition" by Charles Petzold
- "Windows System Architecture" available on Microsoft Docs
- "Windows Kernel Programming" by Pavel Yosifovich
