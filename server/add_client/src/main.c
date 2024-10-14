#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "DeviceConnect_Core.h"

// Should take as input a json-encoded DIDDoc containing a jwk, and create a file containing the associated public key
int main(int argc, char **argv)
{
    printf("Hello, from add_client!\n");
    if (argc != 2)
    {
        printf("Usage: %s <DIDDoc>\n", argv[0]);
        return 1;
    }

    char *did_doc = argv[1];
    printf("DIDDoc: %s\n", did_doc);
}
