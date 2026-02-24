/*=======================================
SEAL SQ 2025
SealSQ OpenSSL Provider for VaultIC 408
Advanced Projects Team
=======================================

SPDX-License-Identifier: Apache-2.0*/

/* ********************** Include files ********************** */
#include "vic408_Provider_main.h"
#include <openssl/prov_ssl.h>

/* ********************** Constants ************************** */
#define OSSL_TLS_GROUP_ID_secp256r1 0x0017

#define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))

typedef struct tls_group_constants_st
{
    unsigned int group_id; /* Group ID */
    unsigned int secbits;  /* Bits of security */
    int mintls;            /* Minimum TLS version, -1 unsupported */
    int maxtls;            /* Maximum TLS version (or 0 for undefined) */
    int mindtls;           /* Minimum DTLS version, -1 unsupported */
    int maxdtls;           /* Maximum DTLS version (or 0 for undefined) */
} TLS_GROUP_CONSTANTS;

static const TLS_GROUP_CONSTANTS group_list[] = {
    {OSSL_TLS_GROUP_ID_secp256r1, 128, TLS1_VERSION, 0, DTLS1_VERSION, 0},
};

#define TLS_GROUP_ENTRY(tlsname, realname, algorithm, idx)              \
    {                                                                   \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME,          \
                               tlsname,                                 \
                               sizeof(tlsname)),                        \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, \
                               realname,                                \
                               sizeof(realname)),                       \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG,           \
                               algorithm,                               \
                               sizeof(algorithm)),                      \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID,                   \
                        (unsigned int *)&group_list[idx].group_id),     \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,        \
                        (unsigned int *)&group_list[idx].secbits),      \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS,               \
                       (unsigned int *)&group_list[idx].mintls),        \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS,               \
                       (unsigned int *)&group_list[idx].maxtls),        \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS,              \
                       (unsigned int *)&group_list[idx].mindtls),       \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS,              \
                       (unsigned int *)&group_list[idx].maxdtls),       \
        OSSL_PARAM_END}

static const OSSL_PARAM tls_param_group_list[][10] = {
    TLS_GROUP_ENTRY("secp256r1", "prime256v1", "EC", 0),
};

typedef struct tls_sigalg_constants_st
{
    unsigned int code_point;
    unsigned int sec_bits; /* Bits of security */
    int min_tls;           /* Minimum TLS version, -1 unsupported */
    int max_tls;           /* Maximum TLS version (or 0 for undefined) */
    int min_dtls;          /* Minimum DTLS version, -1 unsupported */
    int max_dtls;          /* Maximum DTLS version (or 0 for undefined) */
} TLS_SIGALG_CONSTANTS;

static const TLS_SIGALG_CONSTANTS sigalg_constants_list[] = {
    {0x0403, 128, TLS1_2_VERSION, 0, -1, -1},
};

#define TLS_SIGALG_ENTRY(tlsname, algorithm, oid, idx)                           \
    {                                                                            \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME,             \
                               tlsname, sizeof(tlsname)),                        \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_NAME,                  \
                               algorithm, sizeof(algorithm)),                    \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_OID,                   \
                               oid, sizeof(oid)),                                \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT,                   \
                        (unsigned int *)&sigalg_constants_list[idx].code_point), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS,                \
                        (unsigned int *)&sigalg_constants_list[idx].sec_bits),   \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS,                       \
                       (unsigned int *)&sigalg_constants_list[idx].min_tls),     \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS,                       \
                       (unsigned int *)&sigalg_constants_list[idx].max_tls),     \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS,                      \
                       (unsigned int *)&sigalg_constants_list[idx].min_dtls),    \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS,                      \
                       (unsigned int *)&sigalg_constants_list[idx].max_dtls),    \
        OSSL_PARAM_END}

static const OSSL_PARAM param_sigalg_list[][10] = {
    TLS_SIGALG_ENTRY("ecdsa_secp256r1_sha256", "EC", "2.16.840.1.101.3.4.2.1", 0),
};

static int tls_group_capability(OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(tls_param_group_list); i++)
        if (!cb(tls_param_group_list[i], arg))
            return 0;

    return 1;
}

static int tls_sigalg_capability(OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(param_sigalg_list); i++)
        if (!cb(param_sigalg_list[i], arg))
            return 0;
    return 1;
}

int sealsq_VIC408_get_capabilities(const OSSL_PROVIDER *prov, const char *capability, OSSL_CALLBACK *cb, void *arg)
{
    if (OPENSSL_strcasecmp(capability, "TLS-GROUP") == 0)
        return tls_group_capability(cb, arg);
    if (OPENSSL_strcasecmp(capability, "TLS-SIGALG") == 0)
        return tls_sigalg_capability(cb, arg);
    return 0;
}