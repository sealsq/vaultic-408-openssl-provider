/*=======================================
SEAL SQ 2025
SealSQ OpenSSL Provider for VaultIC 408
Advanced Projects Team
=======================================

SPDX-License-Identifier: Apache-2.0*/

/* ********************** Include files ********************** */
#include "vic408_Provider_main.h"
#include <openssl/core_names.h>

/* ********************** Constants ************************** */
#define MAX_RND_REQUEST 512

/* ********************** structure definition *************** */
typedef struct
{
    sealsq_VIC408_provider_context_t *pProvCtx;
} sealsq_VIC408_rand_ctx_st;

/* ********************** Private funtions ******************* */

static void *sealsq_VIC408_rand_newctx(void *provctx, void *parent, const OSSL_DISPATCH *parent_calls)
{
    sealsq_VIC408_rand_ctx_st *pRandCtx = OPENSSL_zalloc(sizeof(sealsq_VIC408_rand_ctx_st));
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    (void)(parent);
    (void)(parent_calls);
    if (pRandCtx != NULL)
    {
        pRandCtx->pProvCtx = provctx;
    }
    return pRandCtx;
}

static void sealsq_VIC408_rand_freectx(void *ctx)
{
    sealsq_VIC408_rand_ctx_st *randCtx = ctx;
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    if (randCtx != NULL)
    {
        OPENSSL_clear_free(randCtx, sizeof(sealsq_VIC408_rand_ctx_st));
    }
    return;
}

static int sealsq_VIC408_rand_generate(void *ctx,
                                       unsigned char *out,
                                       size_t outlen,
                                       unsigned int strength,
                                       int prediction_resistance,
                                       const unsigned char *adin,
                                       size_t adinlen)
{
    sealsq_VIC408_rand_ctx_st *pRandCtx = (sealsq_VIC408_rand_ctx_st *)ctx;
    int ret = 0;

    (void)(strength);
    (void)(prediction_resistance);
    (void)(adin);
    (void)(adinlen);

    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s outlen = %d", __FUNCTION__, outlen);
    VltGenerateRandom(outlen, out);

    ret = 1;
}

static const OSSL_PARAM *sealsq_VIC408_rand_gettable_ctx_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL), OSSL_PARAM_END};
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    (void)(ctx);
    (void)(provctx);
    return known_gettable_ctx_params;
}

static int sealsq_VIC408_rand_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);

    (void)(ctx);

    if (params == NULL)
    {
        return 1;
    }

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, MAX_RND_REQUEST))
    {
        return 0;
    }

    return 1;
}

static int sealsq_VIC408_rand_instantiate(void *ctx,
                                          unsigned int strength,
                                          int prediction_resistance,
                                          const unsigned char *pstr,
                                          size_t pstr_len,
                                          const OSSL_PARAM params[])
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    (void)(ctx);
    (void)(strength);
    (void)(prediction_resistance);
    (void)(pstr);
    (void)(pstr_len);
    (void)(params);
    return 1;
}

static int sealsq_VIC408_rand_uninstantiate(void *ctx)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    (void)(ctx);
    return 1;
}

static int sealsq_VIC408_rand_enable_locking(void *ctx)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    (void)(ctx);
    return 1;
}

const OSSL_DISPATCH sealsq_VIC408_rand_functions[] = {{OSSL_FUNC_RAND_NEWCTX, (void (*)(void))sealsq_VIC408_rand_newctx},
                                                      {OSSL_FUNC_RAND_FREECTX, (void (*)(void))sealsq_VIC408_rand_freectx},
                                                      {OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))sealsq_VIC408_rand_instantiate},
                                                      {OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))sealsq_VIC408_rand_uninstantiate},
                                                      {OSSL_FUNC_RAND_GENERATE, (void (*)(void))sealsq_VIC408_rand_generate},
                                                      {OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))sealsq_VIC408_rand_enable_locking},
                                                      {OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void))sealsq_VIC408_rand_gettable_ctx_params},
                                                      {OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))sealsq_VIC408_rand_get_ctx_params},
                                                      {0, NULL}};