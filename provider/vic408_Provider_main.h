/*=======================================
SEAL SQ 2025
SealSQ OpenSSL Provider for VaultIC 408
Advanced Projects Team
=======================================

SPDX-License-Identifier: Apache-2.0*/

#ifndef sealsq_VIC408_PROVIDER_MAIN_H
#define sealsq_VIC408_PROVIDER_MAIN_H

/* ********************** Include files ********************** */
#include "vaultic_common.h"
#include "vaultic_tls_config.h"
#include "vaultic_tls.h"
#include "vaultic_api.h"

/* Openssl includes */
#include <openssl/core_names.h>
#include <openssl/evp.h>

/* ********************** Constants ************************** */
/* Debug macros */
#define LOG_FLOW_MASK 0x01
#define LOG_DBG_MASK 0x02
#define LOG_ERR_MASK 0x04
#define LOG_HIGHLIGHT_MASK 0x08

#define LOG_FLOW_ON 0x01
#define LOG_DBG_ON 0x02
#define LOG_ERR_ON 0x04
#define LOG_HIGHLIGHT_ON 0x08

typedef struct sealsq_VIC408_type_key_mapping_st
{
    uint32_t cipherType;
    uint32_t keyBitLen;
    char *curve_name;
} sealsq_VIC408_TYPE_KEY_MAP_ST;

#define MAX_sealsq_VIC408_TYPE_KEY_MAP_ENTRIES 32
static const sealsq_VIC408_TYPE_KEY_MAP_ST sealsq_VIC408_type_key_map[MAX_sealsq_VIC408_TYPE_KEY_MAP_ENTRIES] = {
    {0, 0, ""},
};

/* Algorith identifiers */

/* ********************** structure definition *************** */

typedef struct
{
    const OSSL_CORE_HANDLE *core;
} sealsq_VIC408_provider_context_t;

enum keytype {KEYTYPE_RSA,KEYTYPE_ECC,KEYTYPE_UNKNOWN};

typedef struct
{
    sealsq_VIC408_provider_context_t *pProvCtx;
    size_t pub_key_len;
    enum keytype keytype;
    unsigned long key_group;
    unsigned long privkey_index;
    unsigned long pubkey_index;
    int cert_Index;
    uint8_t pub_key[256];
    int has_public;
    int load_done;
    uint8_t pub_key_n[256];
    uint8_t pub_key_e[4];
} sealsq_VIC408_provider_store_obj_t;

/* ********************** Function Prototypes **************** */

OPENSSL_EXPORT int sealsq_VIC408_Provider_init(
    const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx);

void sealsq_VIC408_Prov_Print(int flag, const char *format, ...);

int sealsq_VIC408_CMP_STR(const char *s1, const char *s2);

#endif /* sealsq_VIC408_PROVIDER_H */