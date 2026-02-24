/*=======================================
SEAL SQ 2025
SealSQ OpenSSL Provider for VaultIC 408
Advanced Projects Team
=======================================

SPDX-License-Identifier: Apache-2.0*/

/* ********************** Include files ********************** */
#include "vic408_Provider_main.h"
#include "vaultic_common.h"
#include "vaultic_tls.h"
#include <string.h>

/* ********************** Constants ************************** */
#define SEALSQ_VIC408_PROVIDER_NAME "SealSQ VaultIC 408 Provider"
#define SEALSQ_VIC408_PROVIDER_VERSION "1.0.0"
#define SEALSQ_VIC408_MAX_PRINT_BUF_SIZE (511)

#define CHECK_STATUS(label, a)                             \
    {                                                      \
        VIC_LOGD(label);                                   \
        int ret_status = (a);                              \
        if (ret_status != 0)                               \
        {                                                  \
            VIC_LOGE("%s error %4.4x", label, ret_status); \
            return 1;                                      \
        }                                                  \
    }

/* ********************** Global variables ************************** */
//static int sealsq_VIC408_PROV_LogControl = (LOG_ERR_ON | LOG_DBG_ON | LOG_FLOW_ON | LOG_HIGHLIGHT_ON);
static int sealsq_VIC408_PROV_LogControl = (LOG_ERR_ON); // Only Errors

/* ********************** Private funtions ******************* */

static const OSSL_PARAM *sealsq_VIC408_gettable_params(void *provctx)
{
    static const OSSL_PARAM param_types[] = {OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
                                             OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
                                             OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
                                             OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
                                             OSSL_PARAM_END};
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);
    (void)(provctx);
    return param_types;
}

static int sealsq_VIC408_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);

    (void)(provctx);

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, SEALSQ_VIC408_PROVIDER_NAME))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, SEALSQ_VIC408_PROVIDER_VERSION))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, SEALSQ_VIC408_PROVIDER_VERSION))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

extern int sealsq_VIC408_get_capabilities(const OSSL_PROVIDER *prov, const char *capability, OSSL_CALLBACK *cb, void *arg);

extern const OSSL_DISPATCH sealsq_VIC408_rand_functions[];
static const OSSL_ALGORITHM sealsq_VIC408_rands_algo[] =
    {
        {"CTR-DRBG", "provider=sealsq_vic408_provider,fips=yes,sealsq_vic408_provider.rand=yes", sealsq_VIC408_rand_functions},
        {NULL, NULL, NULL}};

extern OSSL_DISPATCH sealsq_VIC408_ec_keymgmt_functions[];
extern OSSL_DISPATCH sealsq_VIC408_rsa_keymgmt_functions[];
static const OSSL_ALGORITHM sealsq_VIC408_keymgmts_algo[] = {
        {"EC:id-ecPublicKey", "provider=sealsq_vic408_provider", sealsq_VIC408_ec_keymgmt_functions},
        {"RSA:RSASSA", "provider=sealsq_vic408_provider", sealsq_VIC408_rsa_keymgmt_functions},
        {NULL, NULL, NULL}};

extern OSSL_DISPATCH sealsq_VIC408_sig_ecc_functions[];
extern OSSL_DISPATCH sealsq_VIC408_sig_rsa_functions[];
static const OSSL_ALGORITHM sealsq_VIC408_sig_algo[] = {
    {"EC:vaulticECDSA", "provider=sealsq_vic408_provider", sealsq_VIC408_sig_ecc_functions},
    {"vaulticRSASSA:rsa_pkcs1_sha256", "provider=sealsq_vic408_provider,sealsq_vic408_provider.signature=yes,sealsq_vic408_provider.signature.rsa=yes,sealsq_vic408_provider.signature.padding=pkcs1", sealsq_VIC408_sig_rsa_functions},
    {NULL, NULL, NULL}};

extern OSSL_DISPATCH sealsq_VIC408_store_functions[];
extern OSSL_DISPATCH vic408_file_store_object_functions[];
static const OSSL_ALGORITHM sealsq_VIC408_store_algo[] = {
    {"vaulticKey", "provider=sealsq_vic408_provider", sealsq_VIC408_store_functions, "Simple demo public key loader"},
    {"vaulticCert", "provider=sealsq_vic408_provider", sealsq_VIC408_store_functions, "Simple demo public key loader"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM *sealsq_VIC408_query_operation(void *provctx, int operation_id, int *no_cache)
{
    *no_cache = 0;
    (void)(provctx);
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "sealsq_VIC408_query_operation %d ", operation_id, OSSL_OP_KEYMGMT);

    switch (operation_id)
    {
    case OSSL_OP_RAND:
        return sealsq_VIC408_rands_algo;
    case OSSL_OP_KEYMGMT:
        return sealsq_VIC408_keymgmts_algo;
    case OSSL_OP_SIGNATURE:
        return sealsq_VIC408_sig_algo;
    case OSSL_OP_STORE:
        return sealsq_VIC408_store_algo;
    default:
        sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Operation= %d not implemented ", operation_id);
        return NULL;
        break;
    }
}

static void sealsq_VIC408_teardown(void *provctx)
{
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);

    vlt_tls_close();

    if (provctx != NULL)
    {
        OPENSSL_free(provctx);
    }
    return;
}

static const OSSL_DISPATCH sealsq_VIC408_dispatch_table[] = {
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))sealsq_VIC408_query_operation},
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))sealsq_VIC408_teardown},
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))sealsq_VIC408_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))sealsq_VIC408_get_params},
    {OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))sealsq_VIC408_get_capabilities},
    {0, NULL}};

OPENSSL_EXPORT int OSSL_provider_init(
    const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx)
{
    char *portName;

    sealsq_VIC408_provider_context_t *sealsq_VIC408_ProvCtx = OPENSSL_zalloc(sizeof(sealsq_VIC408_provider_context_t));
    if (sealsq_VIC408_ProvCtx == NULL)
    {
        return 0;
    }
    sealsq_VIC408_Prov_Print(LOG_DBG_ON, "Enter - %s ", __FUNCTION__);

    /* Open session with VaultIC */
    CHECK_STATUS("vlt_tls_init", vlt_tls_init());

    (void)(in);

    sealsq_VIC408_ProvCtx->core = handle;
    *out = sealsq_VIC408_dispatch_table;
    *provctx = sealsq_VIC408_ProvCtx;

    return 1;
cleanup:
    if (sealsq_VIC408_ProvCtx != NULL)
    {
        OPENSSL_free(sealsq_VIC408_ProvCtx);
    }
    return 0;
}

OPENSSL_EXPORT int sealsq_VIC408_Provider_init(
    const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx)
{
    return OSSL_provider_init(handle, in, out, provctx);
}

void sealsq_VIC408_Prov_Print(int flag, const char *format, ...)
{
    unsigned char buffer[SEALSQ_VIC408_MAX_PRINT_BUF_SIZE + 1];
    int active = 0;
    va_list vArgs;

    if ((flag & sealsq_VIC408_PROV_LogControl & LOG_FLOW_MASK) == LOG_FLOW_ON)
    {
        active = 1;
        printf("\r\nVaultIC 408 PROV flow: ");
    }
    else if ((flag & sealsq_VIC408_PROV_LogControl & LOG_DBG_MASK) == LOG_DBG_ON)
    {
        active = 1;
        printf("\r\n\033[97;44mVaultIC 408 PROV debug: ");
    }
    else if ((flag & sealsq_VIC408_PROV_LogControl & LOG_ERR_MASK) == LOG_ERR_ON)
    {
        active = 1;
        printf("\r\n\033[5;97;41mVaultIC 408 PROV Error: ");
    }

    else if ((flag & sealsq_VIC408_PROV_LogControl & LOG_HIGHLIGHT_MASK) == LOG_HIGHLIGHT_ON)
    {
        active = 1;
        printf("\r\n\033[43mVaultIC 408 PROV Hilghtlight: ");
    }

    if (active == 1)
    {
        va_start(vArgs, format);
        if (vsnprintf((char *)buffer, SEALSQ_VIC408_MAX_PRINT_BUF_SIZE, (char const *)format, vArgs) < 0)
        {
            printf("vsnprintf error");
            return;
        }
        va_end(vArgs);
        printf("%s \e[0m", buffer);
    }
    return;
}