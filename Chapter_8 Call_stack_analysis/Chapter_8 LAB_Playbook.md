## LAB Exercise 6: Call Stack Analysis
In this exercise we will focus on call stack analysis and compare the call stacks of all the droppers. We will compare the techniques of direct and indirect syscalls in the context of EDR evasion. We will look at why direct syscalls can be detected by EDRs (depending on the EDR), how indirect syscalls can help in this case, and the limitations of indirect syscalls. 

The main part of this exercise is about how EDRs can use or **analyse** the callstack of a dropper, or more precisely a function, to check whether the return address appears to be legitimate or not. In this chapter we will analyse the callstack of each dropper (Win32, Native, Direct Syscalls and Indirect Syscalls). You can use **Process Hacker** to analyse the callstack. For the tasks in this chapter, you can use the droppers you created in the previous chapters. If you were not able to create all the droppers from the previous chapters, you will find all the completed pocs in the code section of this chapter.

## Exercise 6 Tasks: 
1. Run a standard application such as cmd.exe and analyse the call stack.
2. Run all your droppers step by step, analyse the call stacks and compare them. Which one do you think has the most legitimate call stack?
4. Compare the call stack of the droppers with the call stack of cmd.exe.  
5. Run your direct syscall dropper poc and analyse the call stack.
6. Based on your call stack analysis, why might indirect syscalls help bypass return address checking EDRs compared to direct syscall droppers?
7. Compare the callstack between the native dropper and the indirect syscall dropper. Could the native dropper also be used to bypass EDRs? 


## Default Application vs Win32 Dropper
As a first step, we want to compare the call stack of a standard application like cmd.exe with the call stack of the Win32 dropper. So we need to run an instance of cmd.exe and the win32 dropper and take a look at the call stack, more specifically we want to take a look at the stack frames from the main function. As mentioned earlier, we want to use Process Hacker to analyse the call stack. To see how Process Hacker can be used for call stack analysis, check out the detail section below. 
<details>
<p align="center">
<img width="453" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/7aebe38f-7cfe-4bc3-9c61-df700636ea9f"></p>
You can double-click cmd.exe or right-click and select Properties.
</details>





