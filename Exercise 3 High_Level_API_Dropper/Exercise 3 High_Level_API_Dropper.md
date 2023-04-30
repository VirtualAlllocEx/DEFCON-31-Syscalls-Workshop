## Introduction
In this exercise we want to make the first step in the direction creating our own direct system call dropper. But to understand the principal of a legitimate
sysall itself, we begin creating a high level API (HLA) Shellcode dropper based on Windows APIs, which buils our reference for later modifications. The technical functionality of the high level API is relatively simple and therefore, in my opinion, perfectly suited to gradually develop the high level API dropper into a direct system call dropper. In the HLA dropper we use the following Windows APIs: 
- VirtualAlloc
- WriteProcessMemory
- CreateThread
- WaitForSingleObject
