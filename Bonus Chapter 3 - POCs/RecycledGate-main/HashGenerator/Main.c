
#include "windows.h"
#include "stdio.h"

unsigned long djb2(unsigned char* str)
{
    unsigned long hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c;

    return hash;
}


unsigned long xor_hash(unsigned long hash, unsigned long key) {
    return hash ^ key;
}

int main(int argc, char** argv) {

    if (argc < 2)
        return 0;

    unsigned char* name = (unsigned char*)argv[1];
    unsigned long hash = djb2(name);
    unsigned long hash_crypted = xor_hash(hash, 0x41424344);

    printf("%x\n", hash);
    printf("%x\n", hash_crypted);


    return 0;
}

