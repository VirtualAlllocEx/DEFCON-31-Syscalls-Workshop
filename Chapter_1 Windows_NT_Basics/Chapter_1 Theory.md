## Architecture of Windows NT
Before we begin our journey into syscalls, direct syscalls and indirect syscalls, we need to understand some basics about the architecture of Windows NT.
Introduced in 1993, the Microsoft Windows New Technology (NT) operating system marked a pivotal moment in the evolution of Microsoft's operating systems. It represented a significant departure from its predecessors, providing a robust, secure and versatile platform tailored for enterprise applications.

Understanding the nature of this transition requires a brief look back at the state of Windows before NT. The pre-NT versions of Windows were essentially 16-bit systems that functioned more as graphical shells on top of MS-DOS. They had limitations such as limited memory usage and a lack of memory protection between processes. Security and networking features were minimal and often rudimentary. This architectural design often led to system instability and inefficiencies that hindered the overall performance of the operating system.

Windows NT brought a paradigm shift with its 32-bit architecture and a host of advanced features. Unlike its predecessors, NT was a completely new operating system designed from the ground up to run on multiple hardware platforms. It introduced cutting-edge features such as symmetric multiprocessing, improved memory management and comprehensive networking support.

## User Mode and Kernel Mode
One of the major changes to the Windows NT architecture was to split it into user mode and kernel mode. The decision to split Windows into user mode and kernel mode was primarily driven by the need to increase system stability, reliability and security.
<p align="center">
![image](https://github.com/VirtualAlllocEx/DEFCON-31-Workshop-Syscalls/assets/50073731/85e4d37e-71c2-425d-a854-42ded6f2533f)
</p>


