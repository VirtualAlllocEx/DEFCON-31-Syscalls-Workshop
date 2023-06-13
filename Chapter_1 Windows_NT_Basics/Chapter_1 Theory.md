## Introduction to Windows NT
Before we begin our journey into syscalls, direct syscalls and indirect syscalls, we need to understand some basics about the architecture of Windows NT.
Introduced in 1993, the Microsoft Windows New Technology (NT) operating system marked a pivotal moment in the evolution of Microsoft's operating systems. It represented a significant departure from its predecessors, providing a robust, secure and versatile platform tailored for enterprise applications.

Understanding the nature of this transition requires a brief look back at the state of Windows before NT. The pre-NT versions of Windows were essentially 16-bit systems that functioned more as graphical shells on top of MS-DOS. They had limitations such as limited memory usage and a lack of memory protection between processes. Security and networking features were minimal and often rudimentary. This architectural design often led to system instability and inefficiencies that hindered the overall performance of the operating system.

Windows NT, released in 1993 with Windows NT 3.1 brought a paradigm shift with its 32-bit architecture and a host of advanced features. Unlike its predecessors, NT was a completely new operating system designed from the ground up to run on multiple hardware platforms. It introduced cutting-edge features such as symmetric multiprocessing, improved memory management and comprehensive networking support.

## User Mode and Kernel Mode
One of the major changes to the Windows NT architecture was to split the operating system into a user mode (ring 3) and kernel mode (ring 0). The decision to split Windows into user mode and kernel mode was primarily driven by the need to increase system stability, reliability and security.

<p align="center">  
  <img src="https://github.com/VirtualAlllocEx/DEFCON-31-Workshop-Syscalls/assets/50073731/2c9c1d23-1917-487f-9b6e-4194c430dbf3" width="45%"/>
  <img src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/ccf34725-1268-4acd-877b-e4867a83f4e4" width="45%"/>
</p>


<p align="center">
<img width="500" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Workshop-Syscalls/assets/50073731/2c9c1d23-1917-487f-9b6e-4194c430dbf3">
</p>

1. **Stability**: By separating user mode from kernel mode, any bugs, crashes, or malfunctions that occur in user mode programs will not directly affect the kernel or other system components. In other words, a crashing user-mode application won't bring down the entire system because the kernel remains isolated and protected.

2. **Security**: The separation also increases the security of the system. User-mode applications cannot directly access the hardware or memory of other applications or kernel processes. Any access must be through system calls, which can be controlled and monitored e.g. by Av/EPP/EDRs, making unauthorised or malicious actions much more difficult.

3. **Control and resource management**: The kernel, running in kernel mode, has complete control over the machine's resources. This allows better and more efficient management of these resources. It decides when and how to allocate resources, such as CPU time or memory, to user mode processes.

4. **Isolation and abstraction**: Kernel mode also provides an abstraction layer between the hardware and the user mode software. This means that applications can be written to interact with the kernel, rather than being written specifically for a particular hardware configuration.

By maintaining a clear boundary between user mode and kernel mode, Windows ensures that both system stability and security are less likely to be compromised by faulty or malicious applications. It's a design principle common to many modern operating systems.

### User Mode
Key components in user mode include the Win32 subsystem, which provides the API used by most Windows applications, and the security subsystem, which handles logins and permissions. At the heart of the NT architecture, User Mode provides a controlled, secure environment in which most software operates. Applications running in this mode do not have direct access to system hardware or memory, but instead interact with the hardware through system calls and APIs, ensuring that system-level resources are protected from potentially damaging operations. User mode is the domain of third-party software, user interfaces, and many of the built-in Windows components such as the shell and Windows services. Key elements within this mode include the Win32 subsystem, which provides the API used by most Windows applications, and the security subsystem, which is responsible for critical security functions such as logins and permissions.

### Kernel Mode
In contrast, kernel mode is a privileged realm reserved for the core functions of the operating system. Here, code has unrestricted access to the system's hardware and memory, facilitating direct and efficient interaction with the system's resources. It's where the Windows kernel, the hardware abstraction layer (HAL), device drivers, and certain system services reside. Core components in this space include the executive, which manages vital system tasks such as I/O, object security and more; the Windows kernel itself; and the HAL, which abstracts hardware specifics and provides a consistent, platform-independent interface for the kernel.

### Windows APIs
Windows APIs (Application Programming Interfaces), often referred to as Win32 APIs, are a collection of functions and procedures provided by Microsoft that allow developers to interact with the Windows operating system. They are the cornerstone of application development for Windows and form the backbone of most applications running on the platform. The role of Windows APIs is to provide an interface - a contract - between applications and the operating system. They expose a set of services that developers can use to create applications. These services include creating and managing windows, handling user input (such as mouse clicks and keystrokes), managing memory, interacting with hardware devices, and accessing the file system. The reason Windows APIs are necessary is that they abstract away the complexity and variance of working directly with hardware. Instead of writing code to communicate directly with each type of hardware (which would be more complex and unfeasible given the variety of hardware on the market), developers write code that interacts with the APIs. The operating system then handles the interaction with the hardware on behalf of the application. This allows developers to write applications that can run on any hardware configuration that supports Windows, without having to know the specific details of that hardware.

The functions provided by the Windows APIs are located in several dynamic link library (DLL) files that come with the operating system. Some of the most important DLLs are:

| DLL Name         | DLL Tasks                                                                                                                                          | 
| :---:            |     :---:                                                                                                                                          | 
| User32.dll   | This library contains functions for creating windows, handling messages and processing user input.                                                 |    
| Kernel32.dll | This library provides access to a variety of essential system services such as memory management, I/O operations, and process and thread creation. |
| Gdi32.dll    | This library contains functions for drawing graphics and displaying text.                                                                          |
| Comdlg32.dll | This library provides common dialogues such as open and save dialogues.                                                                            |
| Advapi32.dll | This library provides functions for working with the Windows registry and managing user accounts.                                                  |

Using these DLLs and the functions they provide, developers can create a wide variety of applications, from simple command line tools to full-featured graphical user interfaces, that take full advantage of the Windows operating system. In this **workshop** we will **mainly focus** on the **Win32 APIs** that can be accessed through the **kernel32.dll**.

### Native APIs
Native APIs in Windows are a collection of functions and procedures that offer a lower-level interface to the operating system than the Windows API (Win32 API). Although not officially documented for public use, they are used internally by the Windows operating system and can provide deeper, more direct access to system resources and services. The primary role of Native APIs is to provide interfaces for system-level operations and to facilitate certain features and functions of the Win32 subsystem. They are essentially the "building blocks" of the Windows kernel mode, and perform tasks related to low-level system management, including process and thread management, memory management, and object manipulation. The reason Native APIs are needed stems from the layered architecture of the Windows operating system. At the core of Windows is the kernel, which directly interacts with the hardware. The kernel provides services to the rest of the operating system via the Native API. The Win32 subsystem, which includes the Win32 API, is built on top of the Native API. When a Win32 API function is called, it often results in one or more Native API functions being called in the background.

Native API functions are **located in ntdll.dll**. This dynamic-link library is loaded into every user mode process, providing those processes with the ability to make system calls to the kernel. Here are some examples of what the Native APIs can do:

| NTAPI Name                    | NTAPI Tasks                                                                               | 
| :---:                         |     :---:                                                                                 | 
| NtCreateFile              | These function is used to create a file.                                                  |
| NtOpenFile                | These function is used to open a file.                                                    |
| NtQueryInformationProcess | This function can be used to retrieve various types of information about a process.       |
| NtReadVirtualMemory       | These function allows for reading the virtual memory of a process.                        |
| NtWriteVirtualMemory      | These function allows for writing to the virtual memory of a process.                     |

While the Native APIs provide powerful functionality, they should be used with caution. As they are not intended for public use, they can change between different versions of Windows, potentially leading to compatibility issues. They are also more complex to use than the Win32 API and have fewer protections against errors, so incorrect usage can cause system instability or other problems. For these reasons, most developers will interact with the Windows operating system primarily through the Win32 API. However, understanding the Native API can still be valuable, particularly for tasks such as system programming, debugging, and reverse engineering.
