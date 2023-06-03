## LAB Exercise 6: Direct Syscalls vs Indirect Syscalls
In this exercise we will compare the techniques of direct and indirect syscalls in the context of EDR evasion. We will look at why direct syscalls may be detected by EDRs (depending on the EDR), how indirect syscalls can help in this case, and the limitations of indirect syscalls. For the tasks in this chapter, you can use the direct syscall and indirect syscall pocs you created in the previous chapters.

The main part of this exercise is about how EDRs can use or **analyse** the callstack of a dropper, or more precisely a function, to check whether the return address appears to be legitimate or not. In this chapter we will analyse the callstack of each dropper (Win32, Native, Direct Syscalls and Indirect Syscalls). You can use **Process Hacker** to analyse the callstack.

## Exercise 6 Tasks: 
1. Run your Win32 dropper poc and analyse the callstack.
2. Run your native dropper poc and analyse the callstack
3. Run your direct syscall dropper poc and analyse the callstack
4. Run your indirect syscall dropper poc, analyse and compare the callstack
5. Run a standard application such as notepad.exe or cmd.exe and analyse the callstack
6. Compare the callstacks and decide which callstack(s) to use.
7. Based on your callstack analysis, why might indirect syscalls help to bypass EDRs that check the return address?
8. Compare the callstack between the native dropper and the indirect syscall dropper. Could the native dropper also be used to bypass EDRs? 




