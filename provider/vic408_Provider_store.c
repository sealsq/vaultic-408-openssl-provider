/*=======================================
SEAL SQ 2025
SealSQ OpenSSL Provider for VaultIC 408
Advanced Projects Team
=======================================

SPDX-License-Identifier: Apache-2.0*/

/* ********************** Include files ********************** */
#include "vic408_Provider_main.h"
#include <openssl/core_object.h>
#include <openssl/store.h>

/* -----------------------------
 *   Fonctions du STORE
 * ----------------------------- */

#define CHECK_STATUS(label, a)                             \
    {                                                      \
        VIC_LOGD(label);                                   \
        int ret_status = (a);                              \
        if (ret_status != VLT_OK)                          \
        {                                                  \
            VIC_LOGE("%s error %4.4x", label, ret_status); \
            return -1;                                     \
        }                                                  \
    }

static void *sealsq_VIC408_store_open(void *provctx,
                                      const char *uri)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    sealsq_VIC408_provider_store_obj_t *ctx;
    char *baseuri = NULL;
    char *endptr = NULL;
    unsigned long value = 0;

    if ((ctx = OPENSSL_zalloc(sizeof(sealsq_VIC408_provider_store_obj_t))) == NULL)
        return NULL;

    baseuri = OPENSSL_strdup(uri);
    ctx->load_done = -1;
    ctx->pub_key_len = -1;
    ctx->has_public = 0;
    ctx->keytype = KEYTYPE_UNKNOWN;
    ctx->privkey_index = -1;
    ctx->cert_Index = -1;
    ctx->pub_key_n;
    ctx->pub_key_e;
    char *copy;
    if (!baseuri)
    {
        OPENSSL_free(ctx);
        return NULL;
    }
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "uri %s ", uri);

    if (strncmp(baseuri, "vaulticKey:", 11) == 0)
    {
        // Duplication obligatoire si input est const ou doit être préservé
        copy = strdup(baseuri);
        if (!copy) {
            perror("strdup");
        }

        char *token;
        char *saveptr;
        sealsq_VIC408_Prov_Print(LOG_DBG_ON,"baseuri=%d",baseuri);

        token = strtok_r(copy, ":", &saveptr); // "key"
        token = strtok_r(NULL, ":", &saveptr); // "rsa"
        char *type = token;

        token = strtok_r(NULL, ":", &saveptr); // "0x01"
        int group = (int)strtol(token, NULL, 0);

        token = strtok_r(NULL, ":", &saveptr); // "0x02"
        int privindex = (int)strtol(token, NULL, 0);

        token = strtok_r(NULL, ":", &saveptr); // "0x02"
        int pubindex = (int)strtol(token, NULL, 0);

        sealsq_VIC408_Prov_Print(LOG_DBG_ON,"Type  : %s", type);
        sealsq_VIC408_Prov_Print(LOG_DBG_ON,"Group : %d (0x%X)", group, group);
        sealsq_VIC408_Prov_Print(LOG_DBG_ON,"privIndex : %d (0x%X)", privindex, privindex);
        sealsq_VIC408_Prov_Print(LOG_DBG_ON,"PubIndex : %d (0x%X)", pubindex, pubindex);


        ctx->pProvCtx = provctx;

        if(strncmp(type,"rsa",3)==0)
        {
            ctx->keytype = KEYTYPE_RSA;

        }
        else if (strncmp(type,"ecc",3)==0)
        {
            ctx->keytype = KEYTYPE_ECC;
        }
        
        ctx->key_group = group;
        ctx->privkey_index = privindex;
        ctx->pubkey_index = pubindex;

        free(copy);
        OPENSSL_free(baseuri);

        sealsq_VIC408_Prov_Print(LOG_DBG_ON, "success find key at id %lu !", ctx->privkey_index);
        ctx->load_done = 0;

        return ctx;
    }

    if (strncmp(baseuri, "vaulticCert:0x", 12) == 0)
    {
        value = strtoul(baseuri + 12, &endptr, 16);

        if (*endptr != '\0' || value > UINT32_MAX || (value == 0 && endptr == baseuri))
        {
            sealsq_VIC408_Prov_Print(LOG_ERR_ON, "invalid CertId ");
            OPENSSL_free(baseuri);
            OPENSSL_free(ctx);
            return NULL;
        }

        ctx->pProvCtx = provctx;
        ctx->cert_Index = value;
        ctx->load_done = 0;

        OPENSSL_free(baseuri);

        return ctx;
    }

    // URI non reconnue → retourner NULL
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "KEY/Cert NOT FOUND", baseuri);
    OPENSSL_free(baseuri);
    OPENSSL_free(ctx);
    return NULL;
}

static int sealsq_VIC408_store_load(
    void *ctx, OSSL_CALLBACK *object_cb, void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    sealsq_VIC408_provider_store_obj_t *obj = (sealsq_VIC408_provider_store_obj_t *)ctx;
    unsigned char pubkey_x[P256_BYTE_SZ]; // coordonnée X
    unsigned char pubkey_y[P256_BYTE_SZ];
    unsigned char pubkey_e[2048];
    unsigned char pubkey_n[2048];
    int object_type;
    OSSL_PARAM params[5];
    int i = 0;
    int sizeof_device_cert = 0;
    unsigned char *device_cert = NULL;

    if (obj->pubkey_index > 0)
    {
        // Créer une référence vers ta clé (passée ensuite au keymgmt)

        object_type = OSSL_OBJECT_PKEY;

        sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Keygroup keyid - %d %d ", obj->key_group ,obj->pubkey_index);

        VLT_KEY_OBJECT structprivKeyObj = {0};
        VLT_KEY_OBJECT structKeyObj = {0};

        if ((pubkey_x == NULL) || (pubkey_y == NULL))
        {
            VIC_LOGE("vlt_tls_read_pub_key_P256 error: Invalid input params");
            return -1;
        }

        if(obj->keytype == KEYTYPE_ECC)
        {
            sealsq_VIC408_Prov_Print(LOG_DBG_ON,"ECC Key");
            structKeyObj.enKeyID = VLT_KEY_ECC_PUB;
            structKeyObj.data.EcdsaPubKey.u16QLen = P256_BYTE_SZ;
            structKeyObj.data.EcdsaPubKey.pu8Qx = pubkey_x;
            structKeyObj.data.EcdsaPubKey.pu8Qy = pubkey_y;
            params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, "EC", 0);        
        }

        if(obj->keytype == KEYTYPE_RSA)
        {
          sealsq_VIC408_Prov_Print(LOG_DBG_ON,"RSA Key");
          structKeyObj.enKeyID = VLT_KEY_RSASSA_PUB;  
          structKeyObj.data.RsaPubKey.u16NLen =0x100;
          structKeyObj.data.RsaPubKey.pu8N =pubkey_n;
          structKeyObj.data.RsaPubKey.u16ELen = 0x04;
          structKeyObj.data.RsaPubKey.pu8E = pubkey_e;
          params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, "RSA", 0);
        }
        int usActualSW;


        if((usActualSW=VltReadKey(obj->key_group, obj->pubkey_index, &structKeyObj))!=VLT_OK)
        {
            sealsq_VIC408_Prov_Print(LOG_ERR_ON,"Error reading Public Key in VaultIC %x",usActualSW);
            obj->load_done=1;
            return 0;
        }

        sealsq_VIC408_Prov_Print(LOG_DBG_ON, "publicKey");

        if(obj->keytype == KEYTYPE_ECC)
        {
            memset(obj->pub_key, 0x04, 1);
            memcpy(obj->pub_key + 1, pubkey_x, P256_BYTE_SZ);
            memcpy(obj->pub_key + 1 + P256_BYTE_SZ, pubkey_y, P256_BYTE_SZ);

            obj->pub_key_len = (P256_BYTE_SZ * 2) + 1;
        }

        if(obj->keytype == KEYTYPE_RSA)
        {
            memcpy(obj->pub_key_n, pubkey_n, 0x100);
            memcpy(obj->pub_key_e, pubkey_e, 0x04);

            obj->pub_key_len =  0x100+0x04+ 1;        
        }

        obj->has_public = 1;

    }
    if (obj->cert_Index > -1)
    {            
        sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Certificate id - %d ", obj->cert_Index);
        sizeof_device_cert = vlt_tls_get_cert_size(obj->cert_Index);
        if (sizeof_device_cert > 0)
        {
            sealsq_VIC408_Prov_Print(LOG_DBG_ON, "sizeof_device_cert = %d", sizeof_device_cert);
            device_cert = OPENSSL_malloc(sizeof_device_cert);
            vlt_tls_read_cert(device_cert, obj->cert_Index);

            sealsq_VIC408_Prov_Print(LOG_DBG_ON, "[Device certificate]");
            object_type = OSSL_OBJECT_CERT;
            params[i++] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA, (char *)device_cert, sizeof_device_cert);
        }
        else
        {
            VIC_LOGE("(no Device Certificate found in VaultIC)\n");
        }
    }

    params[i++] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &obj, sizeof(obj));
    params[i++] = OSSL_PARAM_construct_end();

    obj->load_done = 1;

    return object_cb(params, object_cbarg);
}

static int sealsq_VIC408_store_close(void *vctx)
{
    // OPENSSL_free(vctx);
    return 1;
}

static int sealsq_VIC408_store_eof(void *vctx)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    sealsq_VIC408_provider_store_obj_t *sctx = (sealsq_VIC408_provider_store_obj_t *)vctx;
    return sctx->load_done;
}

/* -----------------------------
 *   Tables de fonctions
 * ----------------------------- */

const OSSL_DISPATCH sealsq_VIC408_store_functions[] = {
    {OSSL_FUNC_STORE_OPEN, (void (*)(void))sealsq_VIC408_store_open},
    {OSSL_FUNC_STORE_LOAD, (void (*)(void))sealsq_VIC408_store_load},
    {OSSL_FUNC_STORE_EOF, (void (*)(void))sealsq_VIC408_store_eof},
    {OSSL_FUNC_STORE_CLOSE, (void (*)(void))sealsq_VIC408_store_close},
    {0, NULL}};