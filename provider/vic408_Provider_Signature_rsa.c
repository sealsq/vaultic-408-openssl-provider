/*=======================================
SEAL SQ 2025
SealSQ OpenSSL Provider for VaultIC 408
Advanced Projects Team
=======================================

SPDX-License-Identifier: Apache-2.0*/

/* ********************** Include files ********************** */
#include "vic408_Provider_main.h"
#include "vaultic_digest.h"
#include <openssl/x509.h>

/* ********************** Constants ************************** */
#define MAX_DIGEST_INPUT_DATA 1024

/* ********************** structure definition *************** */
typedef struct
{
    void *keyctx;
    VLT_U8 digest[64]; /* MAX SHA512 */
    size_t digestLen;
    VLT_U8 message[32768];
    size_t messageLen;
    VLT_ALG_DIG_ID hashalgo;
    sealsq_VIC408_provider_store_obj_t *pStoreObjCtx;
    sealsq_VIC408_provider_context_t *pProvCtx;
} sealsq_VIC408_signature_ctx;

/* ********************** Private funtions ******************* */

#define CloseAndExit(status, exitMessage)           \
    {                                               \
        printf("");                                 \
        if (VLT_OK != status)                       \
            printf("*** ERROR ");                   \
        printf("%s", exitMessage);                  \
        if (VLT_OK != status)                       \
            VltPrintStatus("*** status: ", status); \
        VltApiClose();                              \
        return (0);                                 \
    }

static void *sealsq_VIC408_rsa_sign_newctx(void *provctx, const char *propq)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    sealsq_VIC408_signature_ctx *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->keyctx = provctx;

    return ctx;
}

static void sealsq_VIC408_rsa_sign_freectx(void *vctx)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    sealsq_VIC408_signature_ctx *ctx = vctx;
    OPENSSL_free(ctx);
}

static void *sealsq_VIC408_rsa_sign_dupctx(void *vctx)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    sealsq_VIC408_signature_ctx *src = vctx;
    sealsq_VIC408_signature_ctx *dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst)
        memcpy(dst, src, sizeof(*dst));
    return dst;
}

static int sealsq_VIC408_rsa_sign_init(void *vctx, void *keyctx, const OSSL_PARAM params[])
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    sealsq_VIC408_signature_ctx *pEcdsaCtx = (sealsq_VIC408_signature_ctx *)vctx;
    (void)(params);
    int status = -1;

    if (pEcdsaCtx != NULL)
    {
        return 1;

    }
    return 0;
}

static int sealsq_VIC408_rsa_sign_sign(void *vctx,
                                   unsigned char *sig, size_t *siglen, size_t sigsize,
                                   const unsigned char *tbs, size_t tbslen)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    int status;
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "tbslen = %d sigsize %d siglen %d  ", tbslen, sigsize, *siglen);
    if (!sig)
        sealsq_VIC408_Prov_Print(LOG_DBG_ON, "sig is NULL");

    VLT_U8 signature[2 * MAX_ECC_KEY_BYTES_SIZE];
    VLT_U16 signatureLen;

    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "tbsign = %s", tbs);

    if (VLT_OK != (status = VltGenerateSignature(tbslen,
                                                 tbs,
                                                 &signatureLen,
                                                 sizeof(signature),
                                                 signature)))
        CloseAndExit(status, "Generate Signature failed");

    printf("[Signature] [%d]", *siglen);
}

static int sealsq_VIC408_signature_digest_init(void *ctx, const char *mdname, void *provkey, const OSSL_PARAM params[])
{
    int status = 0;
    sealsq_VIC408_signature_ctx *pEcdsaCtx = ctx;
    pEcdsaCtx->pStoreObjCtx = provkey;
    pEcdsaCtx->digestLen = sizeof(pEcdsaCtx->digest);


    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s %s", __FUNCTION__, mdname);

    if ((OPENSSL_strcasecmp(mdname, "SHA2-256") == 0) || (OPENSSL_strcasecmp(mdname, "SHA256") == 0))
        pEcdsaCtx->hashalgo = VLT_ALG_DIG_SHA256;
    else if ((OPENSSL_strcasecmp(mdname, "SHA2-384") == 0) || (OPENSSL_strcasecmp(mdname, "SHA384") == 0))
        pEcdsaCtx->hashalgo = VLT_ALG_DIG_SHA384;
    else
    {
        sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Unsupported algorythm - %s", mdname);
        return 0;
    }

    if (VLT_OK != (status = DigestInit((VLT_ALG_DIG_ID)pEcdsaCtx->hashalgo)))
    {
        CloseAndExit(status, "DigestInit failed");
    }

    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "mdname = %s hashalgo %d", mdname, pEcdsaCtx->hashalgo);
    return 1;
}

static int sealsq_VIC408_signature_digest_update(void *ctx, const unsigned char *pu8Message, size_t u32MessageLength)
{
    sealsq_VIC408_signature_ctx *pEcdsaCtx = ctx;
    size_t offset = 0;
    size_t templen = 0;
    int status = 0;

    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);

    if (VLT_OK != (status = DigestUpdate(pu8Message, u32MessageLength)))
    {
        CloseAndExit(status, "DigestUpdate failed");
    }

    return 1;
}


static int sealsq_VIC408_signature_digest_sign_final(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    int status = 0;
    sealsq_VIC408_signature_ctx *pEcdsaCtx = ctx;

    EVP_PKEY_CTX *evpCtx = NULL;
    const EVP_MD *md = NULL;
    int maxSize = 0;

    VLT_U8 hash[32]; 
    VLT_U8 au8Tmp_Signature[256];
    VLT_U16 u16Tmp_SignatureLen;


    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);

    if (sigsize == 0)
    {
        *siglen = 512;
        return 1;
    }
    else
    {
        sealsq_VIC408_Prov_Print(LOG_DBG_ON,"sigsize = %d",sigsize);    
    }

    if (VLT_OK != (status = DigestDoFinal((VLT_U8 *)&(pEcdsaCtx->digest),
                                          (int *)&(pEcdsaCtx->digestLen),
                                          sizeof(pEcdsaCtx->digest))))
    {
        CloseAndExit(status, "DigestDoFinal failed");
    }


    VLT_ALGO_PARAMS strctAlgoParms = {0};
    strctAlgoParms.u8AlgoID = VLT_ALG_SIG_RSASSA_PKCS;
    strctAlgoParms.data.RsassaPkcs.enDigestId = pEcdsaCtx->hashalgo + 0x80;

    if (VLT_OK != (status = VltInitializeAlgorithm(
                       pEcdsaCtx->pStoreObjCtx->key_group,
                       pEcdsaCtx->pStoreObjCtx->privkey_index,
                       VLT_SIGN_MODE,
                       &strctAlgoParms)))
    {
        CloseAndExit(status, "Initialize algo failed");
        return 0;
    }

    sealsq_VIC408_Prov_Print(LOG_DBG_ON,"Signing ...");    

    if (VLT_OK != (status = VltGenerateSignature(pEcdsaCtx->digestLen,
                                                 pEcdsaCtx->digest,
                                                 (VLT_U16*)siglen,
                                                 sigsize,
                                                 sig)))

    sealsq_VIC408_Prov_Print(LOG_DBG_ON,"signature before %d",sigsize);    

    return 1;
}

static int sealsq_VIC408_signature_set_ctx_params(void *vctx,const OSSL_PARAM params[])
{
    sealsq_VIC408_signature_ctx *pEcdsaCtx = vctx;
    const OSSL_PARAM *p;



    return 1;
}

static int sealsq_VIC408_signature_get_ctx_params(void *vctx,
                                    OSSL_PARAM params[])
{
    sealsq_VIC408_signature_ctx *pEcdsaCtx = vctx;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(
            params, OSSL_SIGNATURE_PARAM_PAD_MODE)) != NULL) {
        OSSL_PARAM_set_int(p,RSA_PKCS1_PADDING );
    }

    if ((p = OSSL_PARAM_locate(
            params, OSSL_SIGNATURE_PARAM_DIGEST)) != NULL) {
        OSSL_PARAM_set_utf8_string(
            p, "SHA256");
    }

    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *sealsq_VIC408_signature_gettable_ctx_params(ossl_unused void *vprsactx, ossl_unused void *provctx)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    return known_gettable_ctx_params;
}


/* --------------------------
 *  Table de dispatch
 * -------------------------- */

const OSSL_DISPATCH sealsq_VIC408_sig_rsa_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))sealsq_VIC408_rsa_sign_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))sealsq_VIC408_rsa_sign_freectx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))sealsq_VIC408_rsa_sign_dupctx},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))sealsq_VIC408_signature_digest_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))sealsq_VIC408_signature_digest_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))sealsq_VIC408_signature_digest_sign_final},
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,(void (*)(void))sealsq_VIC408_signature_get_ctx_params },
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))sealsq_VIC408_signature_gettable_ctx_params},



    {0, NULL}};