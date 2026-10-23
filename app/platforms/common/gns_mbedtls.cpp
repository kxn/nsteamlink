/* GNS crypto-provider interface over the project's existing mbedTLS runtime.
 * The SDK's unchanged Donna implementation supplies Ed25519/X25519. */
#include "crypto.h"
#include <tier0/dbg.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <cstdlib>
#include <climits>

void CCrypto::Init() {}
void CCrypto::GenerateRandomBlock(void *out, int size) {
    VerifyFatal(size >= 0);
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context random;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&random);
    static const unsigned char context[] = "nsteamlink/SNS";
    int result = mbedtls_ctr_drbg_seed(&random, mbedtls_entropy_func, &entropy, context, sizeof(context) - 1);
    auto *p = static_cast<unsigned char *>(out);
    for (size_t remaining = size; !result && remaining;) {
        size_t count = remaining > MBEDTLS_CTR_DRBG_MAX_REQUEST ? MBEDTLS_CTR_DRBG_MAX_REQUEST : remaining;
        result = mbedtls_ctr_drbg_random(&random, p, count);
        p += count;
        remaining -= count;
    }
    mbedtls_ctr_drbg_free(&random);
    mbedtls_entropy_free(&entropy);
    VerifyFatal(result == 0);
}
static void digest(mbedtls_md_type_t type, const void *data, size_t size, unsigned char *out) {
    auto *md = mbedtls_md_info_from_type(type);
    VerifyFatal(md != nullptr);
    VerifyFatal(mbedtls_md(md, static_cast<const unsigned char *>(data), size, out) == 0);
}
void CCrypto::GenerateMD5Digest(const void *data, size_t size, MD5Digest_t *out) {
    digest(MBEDTLS_MD_MD5, data, size, *out);
}
void CCrypto::GenerateSHA256Digest(const void *data, size_t size, SHA256Digest_t *out) {
    digest(MBEDTLS_MD_SHA256, data, size, *out);
}
void CCrypto::GenerateHMAC256(const uint8 *data, uint32 size, const uint8 *key, uint32 key_size, SHA256Digest_t *out) {
    auto *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    VerifyFatal(md != nullptr && mbedtls_md_hmac(md, key, key_size, data, size, *out) == 0);
}
void CCrypto::GenerateHMAC(const uint8 *data, uint32 size, const uint8 *key, uint32 key_size, SHADigest_t *out) {
    auto *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    VerifyFatal(md != nullptr && mbedtls_md_hmac(md, key, key_size, data, size, *out) == 0);
}
SymmetricCryptContextBase::SymmetricCryptContextBase() : m_ctx(nullptr), m_cbIV(0), m_cbTag(0) {}
void SymmetricCryptContextBase::Wipe() {
    if (m_ctx) {
        mbedtls_gcm_free(static_cast<mbedtls_gcm_context *>(m_ctx));
        free(m_ctx);
        m_ctx = nullptr;
    }
    m_cbIV = m_cbTag = 0;
}
bool AES_GCM_CipherContext::InitCipher(const void *key, size_t size, size_t iv_size, size_t tag_size, bool) {
    Wipe();
    if (!key || (size != 16 && size != 24 && size != 32) || !iv_size || iv_size > UINT32_MAX ||
        tag_size < 4 || tag_size > 16)
        return false;
    auto *ctx = static_cast<mbedtls_gcm_context *>(calloc(1, sizeof(mbedtls_gcm_context)));
    if (!ctx)
        return false;
    mbedtls_gcm_init(ctx);
    if (mbedtls_gcm_setkey(ctx, MBEDTLS_CIPHER_ID_AES, static_cast<const unsigned char *>(key), unsigned(size * 8))) {
        mbedtls_gcm_free(ctx);
        free(ctx);
        return false;
    }
    m_ctx = ctx;
    m_cbIV = uint32(iv_size);
    m_cbTag = uint32(tag_size);
    return true;
}
bool AES_GCM_EncryptContext::Encrypt(const void *input, size_t size, const void *iv, void *output,
    uint32 *output_size, const void *aad, size_t aad_size) {
    if (!m_ctx || !output_size || !output || !iv || size > UINT32_MAX - m_cbTag ||
        *output_size < size + m_cbTag)
        return false;
    auto *out = static_cast<unsigned char *>(output);
    int result = mbedtls_gcm_crypt_and_tag(static_cast<mbedtls_gcm_context *>(m_ctx), MBEDTLS_GCM_ENCRYPT,
        size, static_cast<const unsigned char *>(iv), m_cbIV,
        static_cast<const unsigned char *>(aad), aad_size, static_cast<const unsigned char *>(input), out,
        m_cbTag, out + size);
    *output_size = result ? 0 : uint32(size + m_cbTag);
    if (result)
        SecureZeroMemory(out, size + m_cbTag);
    return result == 0;
}
bool AES_GCM_DecryptContext::Decrypt(const void *input, size_t size, const void *iv, void *output,
    uint32 *output_size, const void *aad, size_t aad_size) {
    if (!m_ctx || !output_size || !output || !iv || size < m_cbTag || size - m_cbTag > *output_size)
        return false;
    auto *in = static_cast<const unsigned char *>(input);
    size_t plain_size = size - m_cbTag;
    int result = mbedtls_gcm_auth_decrypt(static_cast<mbedtls_gcm_context *>(m_ctx), plain_size,
        static_cast<const unsigned char *>(iv), m_cbIV, static_cast<const unsigned char *>(aad), aad_size,
        in + plain_size, m_cbTag, in, static_cast<unsigned char *>(output));
    *output_size = result ? 0 : uint32(plain_size);
    if (result)
        SecureZeroMemory(output, plain_size);
    return result == 0;
}
