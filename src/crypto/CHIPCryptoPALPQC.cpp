/*
 * Minimal PQC stubs implementation.
 * Real implementations should call into a PQC library (liboqs, vendor lib, or bundled source).
 */

#include "CHIPCryptoPALPQC.h"
#include "CHIPCryptoPAL.h"
#include <lib/support/logging/CHIPLogging.h>
#include <algorithm>
#include <cstring>
#include <cstdlib>

#if defined(__has_include)
#if __has_include(<oqs/oqs.h>)
#define HAVE_OQS 1
#include <oqs/oqs.h>
#else
#define HAVE_OQS 0
#endif
#else
#define HAVE_OQS 0
#endif

namespace chip {
namespace Crypto {

CHIP_ERROR KyberKeypair::Initialize()
{
#if HAVE_OQS
    ChipLogProgress(Crypto, "[PQC] Kyber-768 Initialize() - generating keypair");
    
    // Generate Kyber KEM keypair using liboqs
    OQS_KEM * kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == nullptr)
    {
        ChipLogError(Crypto, "[PQC] Kyber-768 Initialize() - OQS_KEM_new failed");
        return CHIP_ERROR_INTERNAL;
    }

    uint8_t *pub = reinterpret_cast<uint8_t *>(malloc(kem->length_public_key));
    uint8_t *priv = reinterpret_cast<uint8_t *>(malloc(kem->length_secret_key));
    if (!pub || !priv)
    {
        OQS_KEM_free(kem);
        free(pub);
        free(priv);
        ChipLogError(Crypto, "[PQC] Kyber-768 Initialize() - malloc failed");
        return CHIP_ERROR_NO_MEMORY;
    }

    if (OQS_KEM_keypair(kem, pub, priv) != OQS_SUCCESS)
    {
        free(pub);
        free(priv);
        OQS_KEM_free(kem);
        ChipLogError(Crypto, "[PQC] Kyber-768 Initialize() - keypair generation failed");
        return CHIP_ERROR_INTERNAL;
    }

    // Store keys (truncate/copy into internal buffers)
    size_t copy_pub = std::min<size_t>(kem->length_public_key, sizeof(mPublic));
    size_t copy_priv = std::min<size_t>(kem->length_secret_key, sizeof(mPrivate));
    memcpy(mPublic, pub, copy_pub);
    memcpy(mPrivate, priv, copy_priv);

    free(pub);
    free(priv);
    OQS_KEM_free(kem);
    ChipLogProgress(Crypto, "[PQC] Kyber-768 Initialize() - SUCCESS (pk=%zu, sk=%zu)", copy_pub, copy_priv);
    return CHIP_NO_ERROR;
#else
    (void)mPublic;
    (void)mPrivate;
    ChipLogError(Crypto, "[PQC] Kyber-768 Initialize() - HAVE_OQS not defined");
    return CHIP_ERROR_UNSUPPORTED_CHIP_FEATURE;
#endif
}

CHIP_ERROR KyberKeypair::Encapsulate(const KyberPublicKey & pub, uint8_t * ciphertext, size_t ciphertext_len,
                                     KyberSharedSecret & out_secret) const
{
#if HAVE_OQS
    ChipLogProgress(Crypto, "[PQC] Kyber-768 Encapsulate() - ct_len=%zu", ciphertext_len);
    
    // Use Kyber-768 KEM
    OQS_KEM * kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == nullptr)
    {
        ChipLogError(Crypto, "[PQC] Kyber-768 Encapsulate() - OQS_KEM_new failed");
        return CHIP_ERROR_INTERNAL;
    }

    if (ciphertext_len < static_cast<size_t>(kem->length_ciphertext))
    {
        OQS_KEM_free(kem);
        ChipLogError(Crypto, "[PQC] Kyber-768 Encapsulate() - buffer too small (need %d, have %zu)",
                     kem->length_ciphertext, ciphertext_len);
        return CHIP_ERROR_BUFFER_TOO_SMALL;
    }

    uint8_t *shared = reinterpret_cast<uint8_t *>(malloc(kem->length_shared_secret));
    if (!shared)
    {
        OQS_KEM_free(kem);
        ChipLogError(Crypto, "[PQC] Kyber-768 Encapsulate() - malloc failed");
        return CHIP_ERROR_NO_MEMORY;
    }

    if (OQS_KEM_encaps(kem, ciphertext, shared, pub.ConstBytes()) != OQS_SUCCESS)
    {
        free(shared);
        OQS_KEM_free(kem);
        ChipLogError(Crypto, "[PQC] Kyber-768 Encapsulate() - encapsulation failed");
        return CHIP_ERROR_INTERNAL;
    }

    // copy shared secret into out_secret
    size_t copy_len = std::min<size_t>(kem->length_shared_secret, out_secret.Capacity());
    CHIP_ERROR setLenErr = out_secret.SetLength(copy_len);
    if (setLenErr != CHIP_NO_ERROR)
    {
        free(shared);
        OQS_KEM_free(kem);
        ChipLogError(Crypto, "[PQC] Kyber-768 Encapsulate() - SetLength failed");
        return setLenErr;
    }
    memcpy(out_secret.Bytes(), shared, copy_len);

    free(shared);
    OQS_KEM_free(kem);
    ChipLogProgress(Crypto, "[PQC] Kyber-768 Encapsulate() - SUCCESS (shared_secret=%zu)", copy_len);
    return CHIP_NO_ERROR;
#else
    (void)pub;
    (void)ciphertext;
    (void)ciphertext_len;
    (void)out_secret;
    ChipLogError(Crypto, "[PQC] Kyber-768 Encapsulate() - HAVE_OQS not defined");
    return CHIP_ERROR_UNSUPPORTED_CHIP_FEATURE;
#endif
}

CHIP_ERROR KyberKeypair::Decapsulate(const uint8_t * ciphertext, size_t ciphertext_len, KyberSharedSecret & out_secret) const
{
#if HAVE_OQS
    ChipLogProgress(Crypto, "[PQC] Kyber-768 Decapsulate() - ct_len=%zu", ciphertext_len);
    
    OQS_KEM * kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == nullptr)
    {
        ChipLogError(Crypto, "[PQC] Kyber-768 Decapsulate() - OQS_KEM_new failed");
        return CHIP_ERROR_INTERNAL;
    }

    uint8_t *shared = reinterpret_cast<uint8_t *>(malloc(kem->length_shared_secret));
    if (!shared)
    {
        OQS_KEM_free(kem);
        ChipLogError(Crypto, "[PQC] Kyber-768 Decapsulate() - malloc failed");
        return CHIP_ERROR_NO_MEMORY;
    }

    if (OQS_KEM_decaps(kem, shared, ciphertext, mPrivate) != OQS_SUCCESS)
    {
        free(shared);
        OQS_KEM_free(kem);
        ChipLogError(Crypto, "[PQC] Kyber-768 Decapsulate() - decapsulation failed");
        return CHIP_ERROR_INTERNAL;
    }

    size_t copy_len = std::min<size_t>(kem->length_shared_secret, out_secret.Capacity());
    CHIP_ERROR setLenErr = out_secret.SetLength(copy_len);
    if (setLenErr != CHIP_NO_ERROR)
    {
        free(shared);
        OQS_KEM_free(kem);
        ChipLogError(Crypto, "[PQC] Kyber-768 Decapsulate() - SetLength failed");
        return setLenErr;
    }
    memcpy(out_secret.Bytes(), shared, copy_len);

    free(shared);
    OQS_KEM_free(kem);
    ChipLogProgress(Crypto, "[PQC] Kyber-768 Decapsulate() - SUCCESS (shared_secret=%zu)", copy_len);
    return CHIP_NO_ERROR;
#else
    (void)ciphertext;
    (void)ciphertext_len;
    (void)out_secret;
    ChipLogError(Crypto, "[PQC] Kyber-768 Decapsulate() - HAVE_OQS not defined");
    return CHIP_ERROR_UNSUPPORTED_CHIP_FEATURE;
#endif
}

CHIP_ERROR KyberPublicKey::SetBytes(const uint8_t * data, size_t len)
{
#if HAVE_OQS
    VerifyOrReturnError(data != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(len == kKyber_PublicKey_Length, CHIP_ERROR_INVALID_ARGUMENT);

    memcpy(mBytes, data, len);
    ChipLogProgress(Crypto, "[PQC] KyberPublicKey::SetBytes() - SUCCESS");
    return CHIP_NO_ERROR;
#else
    (void)data;
    (void)len;
    return CHIP_ERROR_UNSUPPORTED_CHIP_FEATURE;
#endif
}

CHIP_ERROR KyberKeypair::Pubkey(KyberPublicKey & out_pub) const
{
    return out_pub.SetBytes(mPublic, sizeof(mPublic));
}

void KyberKeypair::Clear()
{
    ChipLogProgress(Crypto, "[PQC] Kyber-768 Clear() - wiping sensitive keys");
    ClearSecretData(mPrivate);
    ClearSecretData(mPublic);
}

CHIP_ERROR DilithiumKeypair::Initialize()
{
#if HAVE_OQS
    ChipLogProgress(Crypto, "[PQC] Dilithium-3 Initialize() - generating keypair");
    
    OQS_SIG * sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == nullptr)
    {
        ChipLogError(Crypto, "[PQC] Dilithium-3 Initialize() - OQS_SIG_new failed");
        return CHIP_ERROR_INTERNAL;
    }

    uint8_t *pub = reinterpret_cast<uint8_t *>(malloc(sig->length_public_key));
    uint8_t *priv = reinterpret_cast<uint8_t *>(malloc(sig->length_secret_key));
    if (!pub || !priv)
    {
        OQS_SIG_free(sig);
        free(pub);
        free(priv);
        ChipLogError(Crypto, "[PQC] Dilithium-3 Initialize() - malloc failed");
        return CHIP_ERROR_NO_MEMORY;
    }

    if (OQS_SIG_keypair(sig, pub, priv) != OQS_SUCCESS)
    {
        free(pub);
        free(priv);
        OQS_SIG_free(sig);
        ChipLogError(Crypto, "[PQC] Dilithium-3 Initialize() - keypair generation failed");
        return CHIP_ERROR_INTERNAL;
    }

    size_t copy_pub = std::min<size_t>(sig->length_public_key, sizeof(mPublic));
    size_t copy_priv = std::min<size_t>(sig->length_secret_key, sizeof(mPrivate));
    memcpy(mPublic, pub, copy_pub);
    memcpy(mPrivate, priv, copy_priv);

    free(pub);
    free(priv);
    OQS_SIG_free(sig);
    ChipLogProgress(Crypto, "[PQC] Dilithium-3 Initialize() - SUCCESS (pk=%zu, sk=%zu)", copy_pub, copy_priv);
    return CHIP_NO_ERROR;
#else
    (void)mPublic;
    (void)mPrivate;
    ChipLogError(chipModule_Crypto, "PQC: Dilithium-3 Initialize() - HAVE_OQS not defined");
    return CHIP_ERROR_UNSUPPORTED_CHIP_FEATURE;
#endif
}

CHIP_ERROR DilithiumPublicKey::SetBytes(const uint8_t * data, size_t len)
{
    ChipLogProgress(Crypto, "[PQC] DilithiumPublicKey::SetBytes() - len=%zu (expected %zu)", len, kDilithium_PublicKey_Length);
    
    VerifyOrReturnError(data != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(len == kDilithium_PublicKey_Length, CHIP_ERROR_INVALID_ARGUMENT);

    memcpy(mBytes, data, len);
    ChipLogProgress(Crypto, "[PQC] DilithiumPublicKey::SetBytes() - SUCCESS");
    return CHIP_NO_ERROR;
}

CHIP_ERROR DilithiumKeypair::Sign(const uint8_t * msg, size_t msg_len, DilithiumSignature & out_sig) const
{
#if HAVE_OQS
    ChipLogProgress(Crypto, "[PQC] Dilithium-3 Sign() - signing %zu-byte message", msg_len);
    
    OQS_SIG * sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == nullptr)
    {
        ChipLogError(Crypto, "[PQC] Dilithium-3 Sign() - OQS_SIG_new failed");
        return CHIP_ERROR_INTERNAL;
    }

    size_t sig_len = sig->length_signature;
    uint8_t *signed_msg = reinterpret_cast<uint8_t *>(malloc(sig_len));
    if (!signed_msg)
    {
        OQS_SIG_free(sig);
        ChipLogError(Crypto, "[PQC] Dilithium-3 Sign() - malloc failed");
        return CHIP_ERROR_NO_MEMORY;
    }

    if (OQS_SIG_sign(sig, signed_msg, &sig_len, msg, msg_len, mPrivate) != OQS_SUCCESS)
    {
        free(signed_msg);
        OQS_SIG_free(sig);
        ChipLogError(Crypto, "[PQC] Dilithium-3 Sign() - signing failed");
        return CHIP_ERROR_INTERNAL;
    }

    size_t copy_len = std::min<size_t>(sig_len, out_sig.Capacity());
    CHIP_ERROR setLenErr = out_sig.SetLength(copy_len);
    if (setLenErr != CHIP_NO_ERROR)
    {
        free(signed_msg);
        OQS_SIG_free(sig);
        ChipLogError(Crypto, "[PQC] Dilithium-3 Sign() - SetLength failed");
        return setLenErr;
    }
    memcpy(out_sig.Bytes(), signed_msg, copy_len);

    free(signed_msg);
    OQS_SIG_free(sig);
    ChipLogProgress(Crypto, "[PQC] Dilithium-3 Sign() - SUCCESS (signature=%zu bytes)", copy_len);
    return CHIP_NO_ERROR;
#else
    (void)msg;
    (void)msg_len;
    (void)out_sig;
    return CHIP_ERROR_UNSUPPORTED_CHIP_FEATURE;
#endif
}

CHIP_ERROR DilithiumKeypair::Verify(const DilithiumPublicKey & pub, const uint8_t * msg, size_t msg_len,
                                    const DilithiumSignature & sig) const
{
#if HAVE_OQS
    ChipLogProgress(Crypto, "[PQC] Dilithium-3 Verify() - verifying %zu-byte message with %zu-byte signature", msg_len, sig.Length());
    
    OQS_SIG * verifier = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (verifier == nullptr)
    {
        ChipLogError(Crypto, "[PQC] Dilithium-3 Verify() - OQS_SIG_new failed");
        return CHIP_ERROR_INTERNAL;
    }

    int rc = OQS_SIG_verify(verifier, msg, msg_len, sig.ConstBytes(), sig.Length(), pub.ConstBytes());
    OQS_SIG_free(verifier);
    
    if (rc == OQS_SUCCESS)
    {
        ChipLogProgress(Crypto, "[PQC] Dilithium-3 Verify() - SUCCESS (signature valid)");
        return CHIP_NO_ERROR;
    }
    else
    {
        ChipLogError(Crypto, "[PQC] Dilithium-3 Verify() - FAILED (signature invalid)");
        return CHIP_ERROR_INVALID_SIGNATURE;
    }
#else
    (void)pub;
    (void)msg;
    (void)msg_len;
    (void)sig;
    return CHIP_ERROR_UNSUPPORTED_CHIP_FEATURE;
#endif
}

CHIP_ERROR DilithiumKeypair::Pubkey(DilithiumPublicKey & out_pub) const
{
    return out_pub.SetBytes(mPublic, sizeof(mPublic));
}

void DilithiumKeypair::Clear()
{
    ClearSecretData(mPrivate);
    ClearSecretData(mPublic);
}

} // namespace Crypto
} // namespace chip
