## LAB Exercise 6: Stack or Memory Analysis
In this exercise we will focus on call stack analysis and compare the call stacks of all the droppers. We will compare the techniques of direct and indirect syscalls in the context of EDR evasion. We will look at why direct syscalls can be detected by EDRs (depending on the EDR), how indirect syscalls can help in this case, and the limitations of indirect syscalls. 

The main part of this exercise is about how EDRs can use or **analyse** the callstack of a dropper, or more precisely a function, to check whether the return address appears to be legitimate or not. In this chapter we will analyse the callstack of each dropper (Win32, Native, Direct Syscalls and Indirect Syscalls). You can use **Process Hacker** to analyse the callstack. For the tasks in this chapter, you can use the droppers you created in the previous chapters. If you were not able to create all the droppers from the previous chapters, you will find all the completed pocs in the code section of this chapter.

## Exercise 6 Tasks: 
### Analyse and Compare Droppers
- Run a standard application such as cmd.exe and analyse the call stack.
- Run your win32, native, direct syscall and indirect syscall droppers. Compare their call stacks with each other, and also with cmd.exe's stack. Which do you think has the most legitimate call stack? 
- Based on your call stack analysis, why might indirect syscalls help bypass return address checking EDRs compared to direct syscall droppers?
- Compare the callstack between the native dropper and the indirect syscall dropper. Could the native dropper also be used to bypass EDRs? 

### Reference IOCs
Before we start the call stack analysis exercises, what are the Indicators of Compromise (IOCs) that might help us identify malware in memory, or that might be used by EDR vendors to identify malware? You can use these IOCs as a guide to identify IOCs in your droppers.

- The syscall and return statement should always be executed from a memory region in ntdll.dll, so that when the shellcode execution is complete, ``ntdll.dll`` is placed on top of the stack as the last element with the lowest memory address.

- If a native function, for example ``ZwWaitForSingleObject``, is executed outside of a memory region in ``ntdll.dll``. Native functions are part of ``ntdll.dll`` and should always be executed from memory in ``ntdll.dll``.


As additional information, not directly an IOC in the context of the call stack itself, but in the context of not legitimate memory regions, also look for unbacked memory regions in the context of the meterpreter payload. For additional information, an unbacked memory region, sometimes referred to as "anonymous memory", is a region of memory that is not associated with a file on disk. This means that it's not backed up by a specific file, such as an executable (.exe) or dynamic link library (.dll) file. For example, if you look at legitimate memory areas with Process Hacker, you will see that they are of the type 'image' and also point to the associated image. If you look at a meterpreter payload in memory, you will see that there are also some memory areas of type "private" that do not point to an image. For example, the 4kB meterpreter stager can be identified. These types of memory areas are called "unbacked executable sections" and are usually classified as malicious by EDRs. Similarly, from an EDR's point of view, it is rather unusual for a thread to have, for example, memory areas in the .text (code) section marked as read (R), write (W) and executable (X) at the same time. By default, the .text section is a read-only section in the PE structure. When using a Meterpreter payload, this is not entirely true, because by using the Windows API VirtualAlloc, certain areas are additionally marked as write (W) and executable (X), or the affected memory area is marked as ``RWX`` in its entirety (``PAGE_EXECUTE_READWRITE``). See the following section for more details.

<details>
<p align="center">
<img width="800" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/fc279e98-b700-46f2-9995-02738febd3bd">
</p>
</details>



## Default Application Call Stack
As a first step, we want to compare the call stack of a standard application like cmd.exe with the call stack of the Win32 dropper. So we need to run an instance of cmd.exe and the win32 dropper and take a look at the call stack, more specifically we want to take a look at the stack frames from the main function. As mentioned earlier, we want to use Process Hacker to analyse the call stack. To see how Process Hacker can be used for call stack analysis, check out the detail section below. 

<details>
<p align="center">
<img width="500" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/d104651a-be2e-4e91-b276-e93c9a00919d">
</p>
  
You can double-click cmd.exe or right-click and select Properties.
<p align="center"> 
  <img width="600" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/3c5154c8-988c-42e3-8442-d0d866e56b19">
</p>
  
Then we select a thread, again we can double click or right click and select Inspect.
<p align="center">
<img width="500" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/c554c323-ed19-45fd-afb9-523344a41b1d">
</p>
Next we can see the stack frames of the thread. At the top of the stack we can see the last element, and at the bottom the first element. When we say that the stack "grows down", it's important to understand that we're talking about the direction in memory addresses, not a physical direction. On most systems, including Windows, the stack grows from higher to lower memory addresses. This is often described as "down" because if you think of memory addresses laid out from lowest to highest (as in a memory map), then the stack grows from the bottom of this diagram to the top.To be clear, the stack in Windows grows from higher to lower memory addresses. This can be described as the stack growing "down" in memory. However, the "top" of the stack is the current end where operations are taking place, which is at a lower memory address than the "bottom" of the stack.

### Default Application Results
When analysing the win32 dropper with Process Hacker, we were **unable to identify any IOCs**. This sounds logical, but let's write down our findings anyway. 
- No native functions executed outside of ``ntdll.dll`` memory
- The ntdll.dll is on top of the call stack and is an indicator of a legitimate stack.
- No unbacked memory regions 
- No RWX regions in the .text section   
  
These results from analysing the default application can be used as a **reference or guide** when analysing your shellcode droppers.  
</details>

## Win32 Dropper Analysis 
In this step we want to analyse the call stack from the win32 dropper and compare it with the call stack from cmd.exe in the previous step. Remember that in the win32 dropper the control flow is ``dropper.exe`` -> ``kernel32.dll`` -> ``kernelbase.dll`` -> ``ntdll.dll`` -> ``syscall``, based on that what to expect or how the order of the stack frames should look like? In case of the win32 dropper we want to analyse the main thread (mainCRTStartup). By analysing the win32 dropper and comparing it to cmd.exe, the following results can be observed. 

<details>
<summary>Results</summary>
<p align="center">  
  <img src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/b8e7bd90-976a-4551-bf05-6d8763053f4e" width="45%"/>
  <img src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/4a45355e-07fb-4c4e-a1f6-1132fdf72f77" width="45%"/>
</p>
  
Due to the technical principle of the Win32 dropper, the call stack or the order of the stack frames looks legitimate. The ``ntdll.dll`` is placed on top of the stack and is an indicator that the return is being executed from memory of the ntdll.dll. Also, the Win32 API is executed from memory of ``kernel32.dll`` or ``kernelbase.dll`` and the native function ``ZwWaitForSingleObject`` is executed from memory of ``ntdll.dll``. Both of these observations are indicators of non-malicious behaviour. 
  
From this point of view we could say that this is a stack with high legitimacy and should be good to go to bypass an EDR in the context of the return address check in the call stack. But don't forget that as soon as an EDR uses use mode hooking or a similar mechanism to analyse executed code in the context of APIs - and this is more or less always the case today - your win32 dropper will normally be detected by the EDR.
  
  
<p align="center">  
  <img width="900" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/cd55fb15-ee6e-4788-b429-ff113cd9c141">
</p> 
  
Looking at the memory regions of the win32 api dropper, things get more interesting. Perhaps not a strong indicator, but still useful, we can identify the meterpreter payload in memory. The default meterpreter stage is about 4kb and the stage loaded afterwards is about 200kb. By analysing these in-memory regions, we will see that we could identify two clear IOCs that lead to two malicious in-memory behaviours.
- Unbacked memory regions
- RWX commited private memory in .text section
</details>

  
  
## Native Dropper Analysis
In this step we want to analyse the call stack from the native dropper and compare it with the call stack from the win32 dropper in the previous step. Remember that in the native dropper the control flow is ``dropper.exe`` -> ``ntdll.dll`` -> ``syscall``, based on that what to expect or how the order of the stack frames should look like? Also in this case we want to analyse the main thread (``mainCRTStartup``). When analysing the native dropper, the following results can be observed.  
<details>
<summary>Results</summary>
<p align="center">  
  <img src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/53805b67-b49c-47b7-8d10-d8d6c43fc51e" width="45%"/>
  <img src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/3bd91e9f-4c08-4dd5-b277-abeeeec52e59" width="45%"/>
</p>
  
Comparing the call stack from the native dropper with the stack from the Win32 dropper or the default application, the call stack doesn't look totally weird in this case either. In my opinion a possible IOC could be that ``ZwWaitForSingleObject`` is executed directly without or before using the corresponding Win32 API ``WaitForSingleObject``. In the context of ``ZwWaitForSingleObject`` I would say it could be a possible IOC. But in general, it's not uncommon for some native Windows function to be executed directly from ``ntdll.dll`` memory.
  
Also in this case I would say, from this point of view we could say that this is a stack with high legitimacy and should be good to go to bypass an EDR in the context of the return address check in the call stack. But don't forget that as soon as an EDR uses use mode hooking or a similar mechanism to analyse executed code in the context of APIs - and this is more or less always the case today - also your native dropper will normally be detected by the EDR.  
       
<p align="center">  
  <img width="900" alt="image" src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/11674eba-ac6a-46d3-b312-7f51194cc04a">
</p> 
  
Also in case of the native dropper, in context of the memory regions we could identify the same IOCs as with the win32 dropper.The default meterpreter stage is about 4kb and the stage loaded afterwards is about 200kb. By analysing these in-memory regions, we will see that we could identify two clear IOCs that lead to two malicious in-memory behaviours.
- Unbacked memory regions
- RWX commited private memory in .text section
</details>  




## Direct Syscall Dropper Analysis
In this step we want to analyse the call stack from the direct syscall dropper and compare it. Remember that in the direct syscall dropper the whole syscall stub from the used native function is directly implemented in to the dropper itself and because of this the control flow is ``dropper.exe`` -> ``syscall``. Based on that what to expect or how the order of the stack frames should look like? Also in this case we want to analyse the main thread (``mainCRTStartup``). When analysing the direct syscall dropper, the following results can be observed.  

<details>
<summary>Results</summary>
<p align="center">  
  <img src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/80a11784-546d-4ff6-adb2-b8da194c1047" width="45%"/>
  <img src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/c5f94181-119a-4164-aeb2-07b1b333a6e1" width="45%"/>
</p>
<p align="center">  
  <img src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/866ce5bb-2693-4945-baa7-fefeb2ca8e18" width="45%"/>
  <img src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/c5f94181-119a-4164-aeb2-07b1b333a6e1" width="45%"/>
</p>  
  
Comparing the call stack from the direct syscall dropper with the call stack from the win32 dropper or the native dropper, we could observe that the call stack from the direct syscall dropper looks totally weird. The following clear IOCs can be observed.
  
- The return from the native function ``ZwWaitForSingleObject`` is not executed in the memory of ntdll.dll, otherwise we would find ``ntdll.dll`` at the top of the stack, or more precisely we would find the stack frame ``ntdll.dll!ZwWaitForSingleObject`` at the top of the call stack. Instead, the return comes from a memory region in the assembly (.exe) itself, which is a 100% IOC for illegitimate behaviour.
  
- Furthermore in context of ``ZwWaitForSingleObject`` we are not able to identify the usage from corresponding Win32 API ``WaitForSingleObject`` before the native function is ``ZwWaitForSingleObject`` is executed. 
  
Based on these IOCs, and depending on the EDR you are facing, your payload will be detected in memory with a very high probability.  
As we also use the same x64 staged meterpreter payload for the direct syscall dropper, we have the same IOCs in the context of analysing the memory regions. 
- Unbacked memory regions
- RWX commited private memory in .text section
</details>  



## Indirect Syscall Dropper Analysis
In this step we want to analyse and compare the call stack from the indirect syscall dropper. Remember that in the indirect syscall dropper only part of the syscall stub from a native function is implemented directly into the dropper itself. The ``syscall`` instruction is replaced by ``jmp qwrd ptr``, so we jump into memory from ``ntdll.dll`` and execute the syscall and return instruction from that memory region. Based on this, what should we expect or how should the order of the stack frames look like? Again, we want to analyse the main thread (``mainCRTStartup``). When analysing the direct syscall dropper, the following results can be observed.

<details>
<summary>Results</summary>
  <img src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/c5f94181-119a-4164-aeb2-07b1b333a6e1" width="45%"/>
  <img src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/ed5d7acb-3020-4e48-8ae3-5dbcfe86b984" width="45%"/>
</p>
<p align="center">  
  <img src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/34dc1d3f-81ac-40b9-ae18-0972ea300e39" width="45%"/>
  <img src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/ed5d7acb-3020-4e48-8ae3-5dbcfe86b984" width="45%"/>
</p>  
  
If we compare the call stack from the indirect syscall dropper with the call stack from the direct syscall dropper, we can see that the call stack looks completely different. Furthermore, if we compare the indirect syscall call stack with the legitimate stack from cmd.exe, we can see that the stack from the indirect syscall dropper has a good level of legitimacy. Compared to the direct syscall dropper we got rid of the following IOCs. 

  - The return from the native function ``ZwWaitForSingleObject`` is executed in the memory of ``ntdll.dll``, so this puts ``ntdll.dll`` at the top of the stack and leads to legitimate behaviour compared to the legitimate stack of cmd.exe.

This means that by replacing direct syscalls with indirect syscalls, we can successfully fake or spoof the return address of a native function that we use in our indirect syscall dropper, and based on that, and depending on the EDR, we can bypass the return address check of an EDR.
 
Don`t forget in the context of the meterpreter payload used you will still be using a high proabality detected by the EDR, based on the memory region IOCs from before. 
- Unbacked memory regions
- RWX commited private memory in .text section
</details>  


## Indirect Syscalls Limitations
Based on the results of our analysis, I think we would say that indirect syscalls are a sensible development compared to direct syscalls. However, indirect syscalls are not a panacea and have their limitations. 

- The first limitation is that we are able to spoof the return address of a native function, but despite this if an EDR uses full stack analysis the EDR would probably be able to identify malicious behaviour. 

- Furthermore, by looking at the stack frame order, we should be able to see that the native function ``ZwWaitForSingleObject`` was executed directly without using the corresponding Win32 API ``WaitForSingleObject``. Depending on the API this may not be an IOC, but in the context of e.g. ``ZwWaitForSingleObject`` it is.

So indirect syscalls might help to make the call stack a bit more logical or legitimate, but regardless we still have the problem of unbacked memory regions and RWX committing memory pages. The latter is more a problem of the meterpreter payload itself, in this case it might help to switch the memory pages from RWX to RW or RX using the ``VirtualProtectAPI``. The unbacked memory problem is a bit more complicated and cannot be solved directly by using indirect syscalls. To get rid of these unbacked regions you need to use a technique like module stomping, thanks to [@NinjaParanoid](https://twitter.com/NinjaParanoid/status/1665457580817395717) and [@KlezVirus](https://twitter.com/KlezVirus) and [@ShitSecure](https://twitter.com/ShitSecure) for the great [discussion](https://twitter.com/VirtualAllocEx/status/1665363389906923524) about this and teaching me about this.
<details>
<p align="center">
  <img src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/16d09c97-18e2-41e7-aef5-30d9db4b4ff5">
  <img src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/bd106f41-74c3-4db6-bd00-1d6498dcbd13">
  <img src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/1c5ba0b7-7129-4c6c-974e-6a2100963420">
  <img src="https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/assets/50073731/d7b979ee-d61f-4a0f-a943-c2f72532426b">
</p>
</details>  

