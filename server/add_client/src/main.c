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

    DIDDoc *parsed_diddoc = iotex_diddoc_parse(did_doc);
    if (parsed_diddoc == NULL)
    {
        printf("Failed to parse DIDDoc\n");
        return 1;
    }

    VerificationMethod_Info *vm_info = iotex_diddoc_verification_method_get(parsed_diddoc, VM_PURPOSE_VERIFICATION_METHOD, 0);
    if (vm_info == NULL)
    {
        printf("Failed to get verification method\n");
        return 1;
    }

    printf("Verification Method: %s\n", vm_info->id);
}
