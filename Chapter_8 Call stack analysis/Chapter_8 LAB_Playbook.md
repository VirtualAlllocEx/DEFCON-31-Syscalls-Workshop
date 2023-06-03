## LAB Exercise 6: Call Stack Analysis
In this exercise we will focus on call stack analysis and compare the call stacks of all the droppers. We will compare the techniques of direct and indirect syscalls in the context of EDR evasion. We will look at why direct syscalls can be detected by EDRs (depending on the EDR), how indirect syscalls can help in this case, and the limitations of indirect syscalls. 

The main part of this exercise is about how EDRs can use or **analyse** the callstack of a dropper, or more precisely a function, to check whether the return address appears to be legitimate or not. In this chapter we will analyse the callstack of each dropper (Win32, Native, Direct Syscalls and Indirect Syscalls). You can use **Process Hacker** to analyse the callstack. For the tasks in this chapter, you can use the droppers you created in the previous chapters. If you were not able to create all the droppers from the previous chapters, you will find all the completed pocs in the code section of this chapter.

## Exercise 6 Tasks: 
1. Run a standard application such as notepad.exe or cmd.exe and analyse the call stack.
2. Run all your droppers step by step, analyse the call stacks and compare them. Which one do you think has the most legitimate call stack?
4. Compare the call stack of the droppers with the call stack of cmd.exe or notepad.exe.  
5. Run your direct syscall dropper poc and analyse the call stack.
6. Based on your call stack analysis, why might indirect syscalls help bypass return address checking EDRs compared to direct syscall droppers?
7. Compare the callstack between the native dropper and the indirect syscall dropper. Could the native dropper also be used to bypass EDRs? 


## Default Application: Call Stack
As a first step, we want to run notepad.exe and have a look at what a normal or legitimate call stack should look like on Windows.




