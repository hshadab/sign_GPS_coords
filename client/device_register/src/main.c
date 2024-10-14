#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "DeviceConnect_Core.h"
#include "dotenv.h"

uint8_t *datahex(char *hex);

int main(void)
{

    env_load("../../..", false);

    char *secret_hex = getenv("SECRET_KEY_HEX");
    if (NULL == secret_hex)
    {
        printf("Please set the SECRET_KEY_HEX environment variable\n");
    }

    psa_status_t status = psa_crypto_init();
    if (PSA_SUCCESS != status)
        return 0;

    //************************ STEP. 1 ******************************//
    // Generate my own two JWKs
    // One of them is used for signing and the other is used for key exchange

    unsigned int mySignKeyID;

    // 32-bytes secret
    uint8_t *secret = datahex(secret_hex);

    // JWK *mySignJWK = iotex_jwk_generate_by_secret(secret, 32,
    //                                               JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_K256,
    //                                               0x01,                                   //   IOTEX_JWK_LIFETIME_PERSISTENT,
    //                                               0x00001000 | 0x00002000 | 0x00000001,   //   PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT,
    //                                               0x06000600 | (0x02000009 & 0x000000ff), //   PSA_ALG_ECDSA(PSA_ALG_SHA_256),
    //                                               &mySignKeyID);

    // if (NULL == mySignJWK)
    // {
    //     printf("Failed to Generate a our own Sign JWK\n");
    //     goto exit;
    // }

    // //************************ STEP. 2 ******************************//
    // // Based on the JWK generated in Step 1,
    // // generate the corresponding DID and use the "io" method

    // char *mySignDID = iotex_did_generate("io", mySignJWK);
    // if (mySignDID)
    //     printf("My Sign DID : \t\t\t%s\n", mySignDID);
    // else
    //     goto exit;

    //************************ STEP. 3 ******************************//
    // In order to simulate C/S communication,
    // we generate the JWK of the peer's key exchange and the corresponding DID.

    unsigned int peerSignKeyID;

    JWK *peerSignJWK = iotex_jwk_generate_by_secret(secret, 32, JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_K256,
                                                    IOTEX_JWK_LIFETIME_VOLATILE,
                                                    PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT,
                                                    PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                                    &peerSignKeyID);
    if (NULL == peerSignJWK)
    {
        printf("Failed to Generate a peer Sign JWK\n");
        goto exit;
    }

    char *peerSignDID = iotex_did_generate("io", peerSignJWK);
    if (peerSignDID)
        printf("Peer DID : \t\t\t%s\n", peerSignDID);
    else
        goto exit;

    char *peerSignKID = iotex_jwk_generate_kid("io", peerSignJWK);
    if (NULL == peerSignKID)
        goto exit;

    //************************ STEP. 4 ******************************//
    // In order to simulate C/S communication,
    // generate a DIDDoc for the peer.

    did_status_t did_status;

    DIDDoc *peerDIDDoc = iotex_diddoc_new();
    if (NULL == peerDIDDoc)
    {
        printf("Failed to new a peerDIDDoc\n");
        goto exit;
    }

    did_status = iotex_diddoc_property_set(peerDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, "https://www.w3.org/ns/did/v1");
    did_status = iotex_diddoc_property_set(peerDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, "https://w3id.org/security#keyAgreementMethod");
    did_status = iotex_diddoc_property_set(peerDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID, NULL, peerSignDID);
    if (DID_SUCCESS != did_status)
    {
        printf("iotex_diddoc_property_set [%d] ret %d\n", IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID, did_status);
        goto exit;
    }

    // 4.1 Make a verification method [type : authentication]
    DIDDoc_VerificationMethod *vm_authentication = iotex_diddoc_verification_method_new(peerDIDDoc, VM_PURPOSE_AUTHENTICATION, VM_TYPE_DIDURL);
    if (NULL == vm_authentication)
    {
        printf("Failed to iotex_diddoc_verification_method_new()\n");
    }

    did_status = iotex_diddoc_verification_method_set(vm_authentication, VM_TYPE_DIDURL, peerSignKID);
    if (DID_SUCCESS != did_status)
    {
        printf("iotex_diddoc_verification_method_set ret %d\n", did_status);
        goto exit;
    }

    VerificationMethod_Map vm_map_1 = iotex_diddoc_verification_method_map_new();
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID, peerSignKID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE, "JsonWebKey2020");
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON, peerSignDID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK, _did_jwk_json_generate(peerSignJWK));

    // // 4.2 Make a verification method [type : key agreement]
    // DIDDoc_VerificationMethod *vm_agreement = iotex_diddoc_verification_method_new(peerDIDDoc, VM_PURPOSE_KEY_AGREEMENT, VM_TYPE_DIDURL);
    // if (NULL == vm_agreement)
    // {
    //     printf("Failed to iotex_diddoc_verification_method_new()\n");
    // }

    // did_status = iotex_diddoc_verification_method_set(vm_agreement, VM_TYPE_DIDURL, peerKAKID);
    // if (DID_SUCCESS != did_status)
    // {
    //     printf("iotex_diddoc_verification_method_set ret %d\n", did_status);
    //     goto exit;
    // }

    // VerificationMethod_Map vm_map_2 = iotex_diddoc_verification_method_map_new();
    // did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID, peerKAKID);
    // did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE, "JsonWebKey2020");
    // did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON, peerSignDID);
    // did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK, _did_jwk_json_generate(peerKAJWK));

    DIDDoc_VerificationMethod *vm_vm = iotex_diddoc_verification_method_new(peerDIDDoc, VM_PURPOSE_VERIFICATION_METHOD, VM_TYPE_MAP);
    did_status = iotex_diddoc_verification_method_set(vm_vm, VM_TYPE_MAP, vm_map_1);
    // did_status = iotex_diddoc_verification_method_set(vm_vm, VM_TYPE_MAP, vm_map_2);

    char *peerDIDDoc_Serialize = iotex_diddoc_serialize(peerDIDDoc, true);
    if (peerDIDDoc_Serialize)
        printf("DIDdoc : \n%s\n", peerDIDDoc_Serialize);

    FILE *fp = fopen("../../peerDIDDoc.json", "w");

    if (fp)
    {
        fwrite(peerDIDDoc_Serialize, strlen(peerDIDDoc_Serialize), 1, fp);
        fclose(fp);
    }

    iotex_diddoc_destroy(peerDIDDoc);

    // 4.3 Parse a DIDDoc
    DIDDoc *parsed_diddoc = iotex_diddoc_parse(peerDIDDoc_Serialize);

    if (parsed_diddoc)
        iotex_diddoc_destroy(parsed_diddoc);

    //************************ Free Res ****************************//

    if (peerDIDDoc_Serialize)
        free(peerDIDDoc_Serialize);

    if (peerSignDID)
        free(peerSignDID);

    if (peerSignKID)
        free(peerSignKID);

    iotex_jwk_destroy(peerSignJWK);

exit:
    // while(1) {
    //     sleep(1000);
    // }

    return 0;
}

uint8_t *datahex(char *string)
{

    if (string == NULL)
        return NULL;

    size_t slength = strlen(string);
    if ((slength % 2) != 0) // must be even
        return NULL;

    size_t dlength = slength / 2;

    uint8_t *data = malloc(dlength);
    memset(data, 0, dlength);

    size_t index = 0;
    while (index < slength)
    {
        char c = string[index];
        int value = 0;
        if (c >= '0' && c <= '9')
            value = (c - '0');
        else if (c >= 'A' && c <= 'F')
            value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
            value = (10 + (c - 'a'));
        else
        {
            free(data);
            return NULL;
        }

        data[(index / 2)] += value << (((index + 1) % 2) * 4);

        index++;
    }

    return data;
}