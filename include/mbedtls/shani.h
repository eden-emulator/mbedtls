#pragma once

#include <stdint.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_HAVE_ASM) && defined(__GNUC__) && \
    (defined(__amd64__) || defined(__x86_64__)) &&    \
    !defined(MBEDTLS_HAVE_X86_64)
#define MBEDTLS_HAVE_X86_64
#endif

#if defined(_MSC_VER) && defined(_M_X64) && !defined(MBEDTLS_HAVE_X86_64)
#define MBEDTLS_HAVE_X86_64
#endif

#if defined(MBEDTLS_HAVE_X86_64)

#ifdef __cplusplus
extern "C" {
#endif

int mbedtls_shani_has_support(void);

int mbedtls_internal_sha256ni_process(uint32_t state[8],
                                      const unsigned char data[64]);

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_HAVE_X86_64 */
