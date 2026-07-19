/*
 *    Copyright (c) 2026
 *    Minimal PQC stubs for Kyber / Dilithium integration.
 *    This file provides scaffolding only; real implementations must be
 *    provided by linking against a PQC library (liboqs or vendor code).
 */

#pragma once

#include "CHIPCryptoPAL.h"

namespace chip {
namespace Crypto {

// Example sizes (placeholders) — replace with actual algorithm sizes used.
inline constexpr size_t kKyber_PublicKey_Length = 1184;
inline constexpr size_t kKyber_PrivateKey_Length = 2400;
inline constexpr size_t kKyber_Ciphertext_Length = 1088;
inline constexpr size_t kKyber_SharedSecret_Length = 32;

inline constexpr size_t kDilithium_PublicKey_Length = 1952;
inline constexpr size_t kDilithium_PrivateKey_Length = 4032;
inline constexpr size_t kDilithium_Signature_Length = 3309;

using KyberSharedSecret = SensitiveDataBuffer<kKyber_SharedSecret_Length>;
using DilithiumSignature = SensitiveDataBuffer<kDilithium_Signature_Length>;

class KyberPublicKey
{
public:
    KyberPublicKey() = default;
    constexpr size_t Length() const { return kKyber_PublicKey_Length; }
    const uint8_t * ConstBytes() const { return mBytes; }
    uint8_t * Bytes() { return mBytes; }
    CHIP_ERROR SetBytes(const uint8_t * data, size_t len);

private:
    uint8_t mBytes[kKyber_PublicKey_Length];
};

class KyberKeypair
{
public:
    KyberKeypair() = default;
    ~KyberKeypair() { Clear(); }

    // Generate or initialize keypair
    CHIP_ERROR Initialize();

    // Encapsulate to a public key: produce ciphertext and shared secret
    CHIP_ERROR Encapsulate(const KyberPublicKey & pub, uint8_t * ciphertext, size_t ciphertext_len,
                           KyberSharedSecret & out_secret) const;

    // Decapsulate: recover shared secret from ciphertext
    CHIP_ERROR Decapsulate(const uint8_t * ciphertext, size_t ciphertext_len, KyberSharedSecret & out_secret) const;

    CHIP_ERROR Pubkey(KyberPublicKey & out_pub) const;

    void Clear();

private:
    uint8_t mPrivate[kKyber_PrivateKey_Length];
    uint8_t mPublic[kKyber_PublicKey_Length];
};

class DilithiumPublicKey
{
public:
    DilithiumPublicKey() = default;
    constexpr size_t Length() const { return kDilithium_PublicKey_Length; }
    const uint8_t * ConstBytes() const { return mBytes; }
    uint8_t * Bytes() { return mBytes; }
    CHIP_ERROR SetBytes(const uint8_t * data, size_t len);

private:
    uint8_t mBytes[kDilithium_PublicKey_Length];
};

class DilithiumKeypair
{
public:
    DilithiumKeypair() = default;
    ~DilithiumKeypair() { Clear(); }

    CHIP_ERROR Initialize();
    CHIP_ERROR Sign(const uint8_t * msg, size_t msg_len, DilithiumSignature & out_sig) const;
    CHIP_ERROR Verify(const DilithiumPublicKey & pub, const uint8_t * msg, size_t msg_len,
                      const DilithiumSignature & sig) const;
    CHIP_ERROR Pubkey(DilithiumPublicKey & out_pub) const;
    void Clear();

private:
    uint8_t mPrivate[kDilithium_PrivateKey_Length];
    uint8_t mPublic[kDilithium_PublicKey_Length];
};

} // namespace Crypto
} // namespace chip
