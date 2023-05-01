## Exercise 5: Low_Level_API_Dropper
In this exercise, we will make the second modification compared to the reference dropper and replace the Windows APIs (kernel32.dll) with native APIs (ntdll.dll).
We create a **low-level API shellcode dropper** in short **LLA-Dropper** based on native APIs. 
![low_level_dropper_principal](https://user-images.githubusercontent.com/50073731/235438881-e4af349a-0109-4d8e-80e2-730915c927f6.png)

## Exercice 4 tasks: 
1. Create a new C++ POC in Visual Studio 2019 and use the provided code for the LLA-Dropper.
2. Create staged x64 meterpreter shellcode with msfvenom and copy it to the C++ LLA-Dropper poc. 
3. Compile the LLA-Dropper as release or debug x64. 
4. Create and run a staged x64 meterpreter listener with msfconsole.
5. Run your compiled .exe and verify that a stable command and control channel opens. 
6. Use the Visual Studio tool dumpbin to verify that the user Windows APIs in the LLA-Dropper not being imported by kernel32.dll. 
7. Use API Monitor to verfiy that there are 
8. Use the API Monitor tool to verify that there are no more transitions from Windows APIs to native APIs related to the MLA-Dropper. 
9. Use x64 dbg and check where the syscall execution of each used native API comes from ? Module? Location? 
