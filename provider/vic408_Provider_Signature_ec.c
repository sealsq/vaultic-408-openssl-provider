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
    sealsq_VIC408_provider_store_obj_t *pStoreObjCtx;
    sealsq_VIC408_provider_context_t *pProvCtx;
} sealsq_VIC408_ecc_sign_ctx;

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

static void *sealsq_VIC408_ecc_sign_newctx(void *provctx, const char *propq)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    sealsq_VIC408_ecc_sign_ctx *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->keyctx = provctx;

    return ctx;
}

static void sealsq_VIC408_ecc_sign_freectx(void *vctx)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    sealsq_VIC408_ecc_sign_ctx *ctx = vctx;
    OPENSSL_free(ctx);
}

static void *sealsq_VIC408_ecc_sign_dupctx(void *vctx)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    sealsq_VIC408_ecc_sign_ctx *src = vctx;
    sealsq_VIC408_ecc_sign_ctx *dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst)
        memcpy(dst, src, sizeof(*dst));
    return dst;
}


static const OSSL_PARAM *sealsq_VIC408_ecc_sign_gettable_ctx_params(void *vctx, void *provctx)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_END};
    return known_gettable_ctx_params;
}

static int sealsq_VIC408_ecc_sign_digest_init(void *ctx, const char *mdname, void *provkey, const OSSL_PARAM params[])
{
    int status = 0;
    sealsq_VIC408_ecc_sign_ctx *pEccCtx = ctx;
    pEccCtx->pStoreObjCtx = provkey;
    pEccCtx->digestLen = sizeof(pEccCtx->digest);
    VLT_ALG_DIG_ID hashalgo;

    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s %s", __FUNCTION__, mdname);

    (void)(params);

    if ((OPENSSL_strcasecmp(mdname, "SHA2-256") == 0) || (OPENSSL_strcasecmp(mdname, "SHA256") == 0))
        hashalgo = VLT_ALG_DIG_SHA256;
    else if ((OPENSSL_strcasecmp(mdname, "SHA2-384") == 0) || (OPENSSL_strcasecmp(mdname, "SHA384") == 0))
        hashalgo = VLT_ALG_DIG_SHA384;
    else
    {
        sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Unsupported algorythm - %s", mdname);
        return 0;
    }

    if (VLT_OK != (status = DigestInit((VLT_ALG_DIG_ID)hashalgo)))
    {
        CloseAndExit(status, "DigestInit failed");
    }

    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "2 use mdname = %s hashalgo %d hash = %02X and hash len %d", mdname, hashalgo, pEccCtx->digest, pEccCtx->digestLen);

    return 1;
}

static int sealsq_VIC408_ecc_sign_digest_update(void *ctx, const unsigned char *pu8Message, size_t u32MessageLength)
{
    sealsq_VIC408_ecc_sign_ctx *pEccCtx = ctx;
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

static int sealsq_VIC408_ecc_sign_digest_sign_final(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    int status = 0;
    sealsq_VIC408_ecc_sign_ctx *pEccCtx = ctx;

    EVP_PKEY_CTX *evpCtx = NULL;
    const EVP_MD *md = NULL;
    int maxSize = 0;
    VLT_U8 au8Tmp_Signature[2 * P256_BYTE_SZ];
    VLT_U16 u16Tmp_SignatureLen;

    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);

    if (sigsize == 0)
    {
        *siglen = 100;
        return 1;
    }
    if (VLT_OK != (status = DigestDoFinal((VLT_U8 *)&(pEccCtx->digest),
                                          (int *)&(pEccCtx->digestLen),
                                          sizeof(pEccCtx->digest))))
    {
        CloseAndExit(status, "DigestDoFinal failed");
    }

    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "use key group %X and keyindex %X", pEccCtx->pStoreObjCtx->key_group, pEccCtx->pStoreObjCtx->privkey_index);

    VLT_ALGO_PARAMS strctAlgoParms = {0};
    strctAlgoParms.u8AlgoID = VLT_ALG_SIG_ECDSA_GFP;
    strctAlgoParms.data.EcdsaDsa.enDigestId = (VLT_ALG_DIG_SHA256 + 0x80);

    if (VLT_OK != (status = VltInitializeAlgorithm(
                       pEccCtx->pStoreObjCtx->key_group,
                       pEccCtx->pStoreObjCtx->privkey_index,
                       VLT_SIGN_MODE,
                       &strctAlgoParms)))
    {
        CloseAndExit(status, "Initialize algo failed");
        return 0;
    }

    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "digestLen %d", pEccCtx->digestLen);

    if (VLT_OK != (status = VltGenerateSignature(pEccCtx->digestLen,
                                                 (VLT_U8 *)&(pEccCtx->digest),
                                                 &u16Tmp_SignatureLen,
                                                 sigsize,
                                                 au8Tmp_Signature)))
        CloseAndExit(status, "Generate Signature failed");

    printf("[Signature] [%d] ", u16Tmp_SignatureLen);

    unsigned char *pu8SigR;
    unsigned char *pu8SigS;

    pu8SigR = malloc(P256_BYTE_SZ);
    pu8SigS = malloc(P256_BYTE_SZ);

    host_memcpy(pu8SigR, au8Tmp_Signature, P256_BYTE_SZ);
    host_memcpy(pu8SigS, au8Tmp_Signature + P256_BYTE_SZ, P256_BYTE_SZ);

    int len;
    if (!pu8SigR || !pu8SigS)
    {
        sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Missing R or S");
        return 0;
    }

    BIGNUM *r = BN_bin2bn(pu8SigR, P256_BYTE_SZ, NULL);
    BIGNUM *s = BN_bin2bn(pu8SigS, P256_BYTE_SZ, NULL);

    ECDSA_SIG *signature_obj = NULL;
    signature_obj = ECDSA_SIG_new();
    if (!signature_obj)
    {
        sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Missing obj");
        return 0;
    }

    if (ECDSA_SIG_set0(signature_obj, r, s) != 1)
    {
        sealsq_VIC408_Prov_Print(LOG_DBG_ON, "error ECDSA_SIG_set0");
        return 0;
    }
    pu8SigR = pu8SigS = NULL;

    len = i2d_ECDSA_SIG(signature_obj, &sig);
    if (len <= 0)
    {
        sealsq_VIC408_Prov_Print(LOG_DBG_ON, "error len=%d", len);
        return 0;
    }

    *siglen = len;
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "siglen/len %d/%d", *siglen, len);

    ECDSA_SIG_free(signature_obj);

    free(pu8SigR);
    free(pu8SigS);

    return 1;
}

#define AID_ECDSA_WITH_SHA256 \
    {                         \
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}

static int sealsq_VIC408_ecc_sign_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    int ret = 0;
    sealsq_VIC408_ecc_sign_ctx *pEccCtx = ctx;
    OSSL_PARAM *p;

    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);

    uint8_t aid_sha256[] = AID_ECDSA_WITH_SHA256;
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL && !OSSL_PARAM_set_octet_string(p, aid_sha256, sizeof(aid_sha256)))
    {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 64))
    {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, "SHA256"))
    {
        return 0;
    }

    ret = 1;
cleanup:
    return ret;
}

/* --------------------------
 *  Table de dispatch
 * -------------------------- */

const OSSL_DISPATCH sealsq_VIC408_sig_ecc_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))sealsq_VIC408_ecc_sign_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))sealsq_VIC408_ecc_sign_freectx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))sealsq_VIC408_ecc_sign_dupctx},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))sealsq_VIC408_ecc_sign_digest_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))sealsq_VIC408_ecc_sign_digest_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))sealsq_VIC408_ecc_sign_digest_sign_final},
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))sealsq_VIC408_ecc_sign_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))sealsq_VIC408_ecc_sign_gettable_ctx_params},
    {0, NULL}};