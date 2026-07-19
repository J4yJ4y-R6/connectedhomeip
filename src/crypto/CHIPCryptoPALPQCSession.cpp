/*
 *    Copyright (c) 2026 Post-Quantum Crypto Integration
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <crypto/CHIPCryptoPALPQCSession.h>
#include <crypto/CHIPCryptoPALPQC.h>
#include <lib/core/CHIPConfig.h>
#include <lib/support/SafeString.h>
#include <string.h>

namespace chip {
namespace Crypto {

bool IsPQCEnabled()
{
#if CHIP_CRYPTO_PQC
    return true;
#else
    return false;
#endif
}

CHIP_ERROR CombineHybridSecrets(const uint8_t * ecdhSecret, size_t ecdhSecretLen,
                                 const uint8_t * kyberSecret, size_t kyberSecretLen,
                                 HybridSharedSecret & outHybridSecret)
{
    VerifyOrReturnError(ecdhSecret != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(kyberSecret != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(ecdhSecretLen == HybridSharedSecret::ECDH_SECRET_SIZE, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(kyberSecretLen == HybridSharedSecret::KYBER_SECRET_SIZE, CHIP_ERROR_INVALID_ARGUMENT);

    // Concatenate: ECDH secret (32B) + Kyber secret (32B) = 64B total
    memcpy(&outHybridSecret.bytes[0], ecdhSecret, HybridSharedSecret::ECDH_SECRET_SIZE);
    memcpy(&outHybridSecret.bytes[HybridSharedSecret::ECDH_SECRET_SIZE], kyberSecret, HybridSharedSecret::KYBER_SECRET_SIZE);

    return CHIP_NO_ERROR;
}

const uint8_t * GetECDHPublicKeyFromHybrid(const HybridPublicKey & hybridKey)
{
    // ECDH public key is first in the buffer
    return &hybridKey.bytes[0];
}

const uint8_t * GetKyberPublicKeyFromHybrid(const HybridPublicKey & hybridKey)
{
    // Kyber public key starts after ECDH pubkey
    return &hybridKey.bytes[HybridPublicKey::ECDH_PUBKEY_SIZE];
}

} // namespace Crypto
} // namespace chip
