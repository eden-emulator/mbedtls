#include "mbedtls/shani.h"

#if defined(MBEDTLS_HAVE_X86_64)

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>

#ifndef asm
#define asm __asm
#endif

#if defined(__DragonFly__) || defined(__FreeBSD__)
// clang-format off
#include <sys/types.h>
#include <machine/cpufunc.h>
// clang-format on
#endif

static inline void __cpuidex(int info[4], int function_id, int subfunction_id) {
#if defined(__DragonFly__) || defined(__FreeBSD__)
    // Despite the name, this is just do_cpuid() with ECX as second input.
    cpuid_count((u_int)function_id, (u_int)subfunction_id, (u_int *)info);
#else
    info[0] = function_id;    // eax
    info[2] = subfunction_id; // ecx
    asm("cpuid"
        : "=a"(info[0]), "=b"(info[1]), "=c"(info[2]), "=d"(info[3])
        : "a"(function_id), "c"(subfunction_id));
#endif
}

#endif

/*
 * SHA-NI support detection routine
 */
int mbedtls_shani_has_support(void) {
    static int done = 0;
    static unsigned int b = 0;

    if (done != 1) {
        int regs[4]; // eax, ebx, ecx, edx
        __cpuidex(regs, 7, 0);
        b = regs[1];
    }

    done = 1;

    return ((b & (1 << 29)) != 0);
}

int mbedtls_internal_sha256ni_process(uint32_t state[8],
                                      const unsigned char data[64]) {
    // Implementation based from
    // https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html
    __m128i STATE0, STATE1;
    __m128i ABEF_SAVE, CDGH_SAVE;
    __m128i MSG, MSGTEMP;
    __m128i MSGTEMP0, MSGTEMP1, MSGTEMP2, MSGTEMP3;
    __m128i SHUF_MASK;

    // Load initial digest
    STATE0 = _mm_loadu_si128((__m128i *)&state[0]);
    STATE1 = _mm_loadu_si128((__m128i *)&state[4]);

    // CDAB
    MSGTEMP = _mm_shuffle_epi32(STATE0, 0xB1);
    // EFGH
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);
    // ABEF
    STATE0 = _mm_alignr_epi8(MSGTEMP, STATE1, 8);
    // CDGH
    STATE1 = _mm_blend_epi16(STATE1, MSGTEMP, 0xF0);

    SHUF_MASK = _mm_set_epi8(0xC, 0xD, 0xE, 0xF, 0x8, 0x9, 0xA, 0xB,
                             0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3);

    // Save digests
    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    // Rounds 0-3
    MSG = _mm_loadu_si128((__m128i *)&data[0]);
    MSGTEMP0 = _mm_shuffle_epi8(MSG, SHUF_MASK);
    MSG = _mm_add_epi32(MSGTEMP0,
                        _mm_set_epi64x(0xE9B5DBA5B5C0FBCF, 0x71374491428A2F98));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 4-7
    MSGTEMP1 = _mm_loadu_si128((const __m128i *)(data + 16));
    MSGTEMP1 = _mm_shuffle_epi8(MSGTEMP1, SHUF_MASK);
    MSG = _mm_add_epi32(MSGTEMP1,
                        _mm_set_epi64x(0xAB1C5ED5923F82A4, 0x59F111F13956C25B));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSGTEMP0 = _mm_sha256msg1_epu32(MSGTEMP0, MSGTEMP1);

    // Rounds 8-11
    MSGTEMP2 = _mm_loadu_si128((const __m128i *)(data + 32));
    MSGTEMP2 = _mm_shuffle_epi8(MSGTEMP2, SHUF_MASK);
    MSG = _mm_add_epi32(MSGTEMP2,
                        _mm_set_epi64x(0x550C7DC3243185BE, 0x12835B01D807AA98));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSGTEMP1 = _mm_sha256msg1_epu32(MSGTEMP1, MSGTEMP2);

    // Rounds 12-15
    MSGTEMP3 = _mm_loadu_si128((const __m128i *)(data + 48));
    MSGTEMP3 = _mm_shuffle_epi8(MSGTEMP3, SHUF_MASK);
    MSG = _mm_add_epi32(MSGTEMP3,
                        _mm_set_epi64x(0xC19BF1749BDC06A7, 0x80DEB1FE72BE5D74));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSGTEMP = _mm_alignr_epi8(MSGTEMP3, MSGTEMP2, 4);
    MSGTEMP0 = _mm_add_epi32(MSGTEMP0, MSGTEMP);
    MSGTEMP0 = _mm_sha256msg2_epu32(MSGTEMP0, MSGTEMP3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSGTEMP2 = _mm_sha256msg1_epu32(MSGTEMP2, MSGTEMP3);

    // Rounds 16-19
    MSG = _mm_add_epi32(MSGTEMP0,
                        _mm_set_epi64x(0x240CA1CC0FC19DC6, 0xEFBE4786E49B69C1));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSGTEMP = _mm_alignr_epi8(MSGTEMP0, MSGTEMP3, 4);
    MSGTEMP1 = _mm_add_epi32(MSGTEMP1, MSGTEMP);
    MSGTEMP1 = _mm_sha256msg2_epu32(MSGTEMP1, MSGTEMP0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSGTEMP3 = _mm_sha256msg1_epu32(MSGTEMP3, MSGTEMP0);

    // Rounds 20-23
    MSG = _mm_add_epi32(MSGTEMP1,
                        _mm_set_epi64x(0x76F988DA5CB0A9DC, 0x4A7484AA2DE92C6F));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSGTEMP = _mm_alignr_epi8(MSGTEMP1, MSGTEMP0, 4);
    MSGTEMP2 = _mm_add_epi32(MSGTEMP2, MSGTEMP);
    MSGTEMP2 = _mm_sha256msg2_epu32(MSGTEMP2, MSGTEMP1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSGTEMP0 = _mm_sha256msg1_epu32(MSGTEMP0, MSGTEMP1);

    // Rounds 24-27
    MSG = _mm_add_epi32(MSGTEMP2,
                        _mm_set_epi64x(0xBF597FC7B00327C8, 0xA831C66D983E5152));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSGTEMP = _mm_alignr_epi8(MSGTEMP2, MSGTEMP1, 4);
    MSGTEMP3 = _mm_add_epi32(MSGTEMP3, MSGTEMP);
    MSGTEMP3 = _mm_sha256msg2_epu32(MSGTEMP3, MSGTEMP2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSGTEMP1 = _mm_sha256msg1_epu32(MSGTEMP1, MSGTEMP2);

    // Rounds 28-31
    MSG = _mm_add_epi32(MSGTEMP3,
                        _mm_set_epi64x(0x1429296706CA6351, 0xD5A79147C6E00BF3));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSGTEMP = _mm_alignr_epi8(MSGTEMP3, MSGTEMP2, 4);
    MSGTEMP0 = _mm_add_epi32(MSGTEMP0, MSGTEMP);
    MSGTEMP0 = _mm_sha256msg2_epu32(MSGTEMP0, MSGTEMP3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSGTEMP2 = _mm_sha256msg1_epu32(MSGTEMP2, MSGTEMP3);

    // Rounds 32-35
    MSG = _mm_add_epi32(MSGTEMP0,
                        _mm_set_epi64x(0x53380D134D2C6DFC, 0x2E1B213827B70A85));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSGTEMP = _mm_alignr_epi8(MSGTEMP0, MSGTEMP3, 4);
    MSGTEMP1 = _mm_add_epi32(MSGTEMP1, MSGTEMP);
    MSGTEMP1 = _mm_sha256msg2_epu32(MSGTEMP1, MSGTEMP0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSGTEMP3 = _mm_sha256msg1_epu32(MSGTEMP3, MSGTEMP0);

    // Rounds 36-39
    MSG = _mm_add_epi32(MSGTEMP1,
                        _mm_set_epi64x(0x92722C8581C2C92E, 0x766A0ABB650A7354));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSGTEMP = _mm_alignr_epi8(MSGTEMP1, MSGTEMP0, 4);
    MSGTEMP2 = _mm_add_epi32(MSGTEMP2, MSGTEMP);
    MSGTEMP2 = _mm_sha256msg2_epu32(MSGTEMP2, MSGTEMP1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSGTEMP0 = _mm_sha256msg1_epu32(MSGTEMP0, MSGTEMP1);

    // Rounds 40-43
    MSG = _mm_add_epi32(MSGTEMP2,
                        _mm_set_epi64x(0xC76C51A3C24B8B70, 0xA81A664BA2BFE8A1));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSGTEMP = _mm_alignr_epi8(MSGTEMP2, MSGTEMP1, 4);
    MSGTEMP3 = _mm_add_epi32(MSGTEMP3, MSGTEMP);
    MSGTEMP3 = _mm_sha256msg2_epu32(MSGTEMP3, MSGTEMP2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSGTEMP1 = _mm_sha256msg1_epu32(MSGTEMP1, MSGTEMP2);

    // Rounds 44-47
    MSG = _mm_add_epi32(MSGTEMP3,
                        _mm_set_epi64x(0x106AA070F40E3585, 0xD6990624D192E819));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSGTEMP = _mm_alignr_epi8(MSGTEMP3, MSGTEMP2, 4);
    MSGTEMP0 = _mm_add_epi32(MSGTEMP0, MSGTEMP);
    MSGTEMP0 = _mm_sha256msg2_epu32(MSGTEMP0, MSGTEMP3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSGTEMP2 = _mm_sha256msg1_epu32(MSGTEMP2, MSGTEMP3);

    // Rounds 48-51
    MSG = _mm_add_epi32(MSGTEMP0,
                        _mm_set_epi64x(0x34B0BCB52748774C, 0x1E376C0819A4C116));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSGTEMP = _mm_alignr_epi8(MSGTEMP0, MSGTEMP3, 4);
    MSGTEMP1 = _mm_add_epi32(MSGTEMP1, MSGTEMP);
    MSGTEMP1 = _mm_sha256msg2_epu32(MSGTEMP1, MSGTEMP0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSGTEMP3 = _mm_sha256msg1_epu32(MSGTEMP3, MSGTEMP0);

    // Rounds 52-55
    MSG = _mm_add_epi32(MSGTEMP1,
                        _mm_set_epi64x(0x682E6FF35B9CCA4F, 0x4ED8AA4A391C0CB3));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSGTEMP = _mm_alignr_epi8(MSGTEMP1, MSGTEMP0, 4);
    MSGTEMP2 = _mm_add_epi32(MSGTEMP2, MSGTEMP);
    MSGTEMP2 = _mm_sha256msg2_epu32(MSGTEMP2, MSGTEMP1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 56-59
    MSG = _mm_add_epi32(MSGTEMP2,
                        _mm_set_epi64x(0x8CC7020884C87814, 0x78A5636F748F82EE));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSGTEMP = _mm_alignr_epi8(MSGTEMP2, MSGTEMP1, 4);
    MSGTEMP3 = _mm_add_epi32(MSGTEMP3, MSGTEMP);
    MSGTEMP3 = _mm_sha256msg2_epu32(MSGTEMP3, MSGTEMP2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 60-63
    MSG = _mm_add_epi32(MSGTEMP3,
                        _mm_set_epi64x(0xC67178F2BEF9A3F7, 0xA4506CEB90BEFFFA));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

    // FEBA
    MSGTEMP = _mm_shuffle_epi32(STATE0, 0x1B);
    // DCHG
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);
    // DCBA
    STATE0 = _mm_blend_epi16(MSGTEMP, STATE1, 0xF0);
    // ABEF
    STATE1 = _mm_alignr_epi8(STATE1, MSGTEMP, 8);

    // Store digests
    _mm_storeu_si128((__m128i *)&state[0], STATE0);
    _mm_storeu_si128((__m128i *)&state[4], STATE1);

    return 0;
}

#endif // MBEDTLS_HAVE_X86_64
