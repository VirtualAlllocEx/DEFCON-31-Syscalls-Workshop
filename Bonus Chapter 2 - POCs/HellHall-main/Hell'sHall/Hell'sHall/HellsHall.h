#include <Windows.h>


typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
typedef uint32_t UINT32_T;              // im boojie



#ifndef HELLHALL_H
#define HELLHALL_H


// STRING HASHING
uint32_t crc32b(const uint8_t* str);
#define HASH(API)	(crc32b((uint8_t*)API))


typedef struct _SysFunc {

    PVOID       pInst;          // address of a 'syscall' instruction in ntdll.dll
    PBYTE       pAddress;       // address of the syscall 
    WORD        wSSN;           // syscall number
    UINT32_T    uHash;          // syscall name hash value

}SysFunc, * PSysFunc;


// FROM HellsHall.c
BOOL InitilizeSysFunc(IN UINT32_T uSysFuncHash);
VOID getSysFuncStruct(OUT PSysFunc psF);

// FROM AsmHell.asm
extern VOID SetConfig(WORD wSystemCall, PVOID pSyscallInst);
extern HellHall();


//  A MACRO TO MAKE STUFF CLEANER
#define SYSCALL(sF)(SetConfig(sF.wSSN, sF.pInst))


#endif // !HELLHALL_H







