/*=======================================
SEAL SQ 2025
SealSQ OpenSSL Provider for VaultIC 408
Advanced Projects Team
=======================================

SPDX-License-Identifier: Apache-2.0*/

/* ********************** Include files ********************** */
#include "vic408_Provider_main.h"
#include <string.h>

/* ********************** Defines **************************** */

/* ********************** Global Variables ******************* */

/* ********************** Private funtions ******************* */

static void *sealsq_VIC408_rsa_keymgmt_new(void *provctx)
{
    sealsq_VIC408_provider_store_obj_t *pStoreCtx = OPENSSL_zalloc(sizeof(sealsq_VIC408_provider_store_obj_t));

    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    if (pStoreCtx != NULL)
    {
        pStoreCtx->pProvCtx = provctx;
    }

    return pStoreCtx;
}

static void sealsq_VIC408_rsa_keymgmt_free(void *keydata)
{
    sealsq_VIC408_provider_store_obj_t *pStoreCtx = (sealsq_VIC408_provider_store_obj_t *)keydata;
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);

    if (keydata != NULL)
    {
        OPENSSL_free(keydata);
    }
    return;
}

static void *sealsq_VIC408_rsa_keymgmt_load(const void *reference, size_t reference_sz)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);

    sealsq_VIC408_provider_store_obj_t *pStoreCtx = NULL;

    if (!reference || reference_sz != sizeof(pStoreCtx))
    {
        sealsq_VIC408_Prov_Print(LOG_ERR_ON, "%s failed", __FUNCTION__);
        return NULL;
    }

    pStoreCtx = *(sealsq_VIC408_provider_store_obj_t **)reference;
    *(sealsq_VIC408_provider_store_obj_t **)reference = NULL;

    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "sealsq_VIC408_rsa_keymgmt_load keyLen = %d", pStoreCtx->pub_key_len);
    return pStoreCtx;
}

static int sealsq_VIC408_rsa_keymgmt_has(const void *keydata, int selection)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    sealsq_VIC408_provider_store_obj_t *key = (sealsq_VIC408_provider_store_obj_t *)keydata;
    int ret = 0;

    if (selection == OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
    {
        if ((key->privkey_index > 0x00) & (key->privkey_index < 0x21))
        {
            sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Correct Private Key at key index %x", key->privkey_index);
            return 1;
        }
        else
            return 0;
    }
    if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {
        ret = key->has_public;
        return ret;
    }
    if (selection == OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)
    {
        sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Domain Parametters");
        return 1;
    }
    else
    {
        sealsq_VIC408_Prov_Print(LOG_DBG_ON, "unknown selection %d", selection);
        return 0;
    }
}

static int sealsq_VIC408_rsa_keymgmt_import(void *keydata, int selection, OSSL_PARAM params[])
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s selection %d", __FUNCTION__, selection);
    int ok = 1;
    int include_private;

    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "import %p\n", keydata);
    sealsq_VIC408_provider_store_obj_t *key = (sealsq_VIC408_provider_store_obj_t *)keydata;
    unsigned int magic_num = {0};
    BIGNUM *bn_priv_key = NULL;
    int res = 0;
    unsigned char *value = NULL;
    size_t usedlen = 0;

    OSSL_PARAM *param;


    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {
        sealsq_VIC408_Prov_Print(LOG_DBG_ON, "OSSL_KEYMGMT_SELECT_PUBLIC_KEY");

        param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (param != NULL)
        {
            sealsq_VIC408_Prov_Print(LOG_DBG_ON, "OSSL_PKEY_PARAM_PUB_KEY\n");

            if (!OSSL_PARAM_get_octet_string(param, (void **)&value, 0, &usedlen))
            {
                sealsq_VIC408_Prov_Print(LOG_DBG_ON, "OSSL_PKEY_PARAM_PUB_KEY 0\n");
                return 0;
            }
            else
            {
                sealsq_VIC408_Prov_Print(LOG_DBG_ON, "usedlen %zu", usedlen);
                memcpy(key->pub_key, value, usedlen);
                OPENSSL_free(value);
                key->pub_key_len = usedlen;
            }

            sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Print key \n");
            sealsq_VIC408_Prov_Print(LOG_DBG_ON, "keylen %d", key->pub_key_len);
            key->has_public = 1;
            return 1;
        }

        param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_N);
        if (param != NULL)
        {
            sealsq_VIC408_Prov_Print(LOG_DBG_ON, "OSSL_PKEY_PARAM_RSA_N");

            if (!OSSL_PARAM_get_BN(param, &bn_priv_key))
            {
                return 0;
            }
            else
            {
                BN_bn2bin(bn_priv_key, key->pub_key_n);
                OPENSSL_free(value);
            }

            sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Print key \n");
            sealsq_VIC408_Prov_Print(LOG_DBG_ON, "keylen %d", key->pub_key_len);
            key->has_public = 1;
            return 1;
        }

        param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_E);
        if (param != NULL)
        {
            sealsq_VIC408_Prov_Print(LOG_DBG_ON, "OSSL_PKEY_PARAM_RSA_E\n");

            if (!OSSL_PARAM_get_BN(param, &bn_priv_key))
            {
                sealsq_VIC408_Prov_Print(LOG_DBG_ON, "OSSL_PKEY_PARAM_RSA_E 0\n");
                return 0;
            }
            else
            {
                BN_bn2bin(bn_priv_key, key->pub_key_e);
                OPENSSL_free(value);
            }

            key->has_public = 1;
            return 1;
        }
        else
        {
            sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Key not handled in sssProvider. Fall back to default provider\n");
            return 0;
        }
    }

    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "unknown %d\n", selection);

    return 0;
}

static const OSSL_PARAM *sealsq_VIC408_rsa_keymgmt_import_types(int selection)
{

    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);

    static const OSSL_PARAM types[] = {
        OSSL_PARAM_int(OSSL_OBJECT_PARAM_TYPE, NULL),
        OSSL_PARAM_octet_string(OSSL_OBJECT_PARAM_DATA, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, NULL, 0),
        OSSL_PARAM_END};
    return types;
}

static int sealsq_VIC408_rsa_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    sealsq_VIC408_provider_store_obj_t *key = (sealsq_VIC408_provider_store_obj_t *)keydata;
    OSSL_PARAM params[8];
    memset(params, 0, sizeof(params));

    unsigned char *copy = NULL;
    int ret;
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s selection %d key index - %d", __FUNCTION__,selection, key->privkey_index);
    
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Ask private Key", __FUNCTION__);
        return 0;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {
        sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Ask Public Key", __FUNCTION__, key->pubkey_index);

        OSSL_PARAM params[2];
        memset(params, 0, sizeof(params));

        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY,
            &key->pub_key[0],
            key->pub_key_len);
        params[1] = OSSL_PARAM_construct_end();

        return param_cb(params, cbarg);
    }

    return 0;
}

static const OSSL_PARAM *sealsq_VIC408_rsa_keymgmt_export_types(int selection)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    static const OSSL_PARAM types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END};

    return types;
}

static const char *sealsq_VIC408_rsa_keymgmt_query_operation_name(int operation_id)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s operation_Id = %d", __FUNCTION__, operation_id);
    switch (operation_id)
    {
    case OSSL_OP_SIGNATURE:
        return "vaulticRSASSA";
    default:
        sealsq_VIC408_Prov_Print(LOG_DBG_ON, "operation_Id = %d not supported", operation_id);
        return NULL;
        break;
    }
}

static int sealsq_VIC408_rsa_keymgmt_keymgmt_match(const void *keydata1, const void *keydata2, int selection)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    sealsq_VIC408_provider_store_obj_t *key = (sealsq_VIC408_provider_store_obj_t *)keydata1;
    sealsq_VIC408_provider_store_obj_t *key2 = (sealsq_VIC408_provider_store_obj_t *)keydata2;

    for (int i = 0; i < 256; i++)
    {
        if (key->pub_key_n[i] != key2->pub_key_n[i])
        {
            sealsq_VIC408_Prov_Print(LOG_DBG_ON, "keyid - %d vs key id %d mismatch");
            return 0;
        }
    }

    return 1; 
}

static int vaultic_keymgmt_get_params(void *keydata, OSSL_PARAM params[])
{
    sealsq_VIC408_provider_store_obj_t *key = (sealsq_VIC408_provider_store_obj_t *)keydata;
    OSSL_PARAM *p;

    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    if (params == NULL) {
        return 1;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY); /*Public Key*/
    if (p != NULL) {
        BIGNUM *bn_pub_key = NULL;
        bn_pub_key   = BN_bin2bn(key->pub_key, key->pub_key_len, NULL);
        p->data_size = key->pub_key_len;
        if (!OSSL_PARAM_set_BN(p, bn_pub_key)) {
            BN_free(bn_pub_key);
            return 0;
        }
        BN_free(bn_pub_key);
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST);
    if ((p != NULL) && (!OSSL_PARAM_set_utf8_string(p, "SHA256"))) {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST);
    if ((p != NULL) && (!OSSL_PARAM_set_utf8_string(p, "SHA256"))) {
        return 0;
    }

    return 1;
}

static const OSSL_PARAM *vaultic_keymgmt_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END};
    return gettable;
}

const OSSL_DISPATCH sealsq_VIC408_rsa_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))sealsq_VIC408_rsa_keymgmt_new},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))sealsq_VIC408_rsa_keymgmt_free},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))sealsq_VIC408_rsa_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))sealsq_VIC408_rsa_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))sealsq_VIC408_rsa_keymgmt_import_types},
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))sealsq_VIC408_rsa_keymgmt_export},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))sealsq_VIC408_rsa_keymgmt_export_types},
    {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))sealsq_VIC408_rsa_keymgmt_load},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))sealsq_VIC408_rsa_keymgmt_query_operation_name},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))sealsq_VIC408_rsa_keymgmt_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))vaultic_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))vaultic_keymgmt_gettable_params},
    {0, NULL}};