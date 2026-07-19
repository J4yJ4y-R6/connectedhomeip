/*
 *    Copyright (c) 2026 Post-Quantum Crypto Integration
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 */

#pragma once

#include <lib/core/CHIPError.h>
#include <lib/support/Span.h>

namespace chip {
namespace Crypto {

/**
 * @brief Hybrid key agreement: combines ECDH (for compatibility) + Kyber (for PQC)
 * 
 * When chip_crypto_pqc=true, the CASE protocol uses this to:
 * 1. Generate ephemeral Kyber keypair alongside ECDH
 * 2. Send both public keys in Sigma1 message
 * 3. Perform both ECDH and Kyber encapsulation in Sigma2
 * 4. Combine both shared secrets for final session key
 * 
 * Result: Quantum-resistant even if ECDH is broken, backwards compatible with non-PQC
 */

/**
 * @brief Hybrid shared secret combining ECDH (32 bytes) + Kyber (32 bytes)
 */
struct HybridSharedSecret
{
    static constexpr size_t ECDH_SECRET_SIZE = 32;
    static constexpr size_t KYBER_SECRET_SIZE = 32;
    static constexpr size_t TOTAL_SIZE = ECDH_SECRET_SIZE + KYBER_SECRET_SIZE; // 64 bytes
    
    uint8_t bytes[TOTAL_SIZE];
};

/**
 * @brief Hybrid public key material: ECDH public key + Kyber public key
 */
struct HybridPublicKey
{
    static constexpr size_t ECDH_PUBKEY_SIZE = 65;      // P-256 uncompressed
    static constexpr size_t KYBER_PUBKEY_SIZE = 1184;   // Kyber-768
    static constexpr size_t TOTAL_SIZE = ECDH_PUBKEY_SIZE + KYBER_PUBKEY_SIZE; // 1249 bytes
    
    uint8_t bytes[TOTAL_SIZE];
};

/**
 * @brief Check if PQC mode is enabled at runtime
 */
bool IsPQCEnabled();

/**
 * @brief Combine ECDH secret and Kyber secret into hybrid secret
 */
CHIP_ERROR CombineHybridSecrets(const uint8_t * ecdhSecret, size_t ecdhSecretLen,
                                 const uint8_t * kyberSecret, size_t kyberSecretLen,
                                 HybridSharedSecret & outHybridSecret);

/**
 * @brief Extract ECDH public key from hybrid public key
 */
const uint8_t * GetECDHPublicKeyFromHybrid(const HybridPublicKey & hybridKey);

/**
 * @brief Extract Kyber public key from hybrid public key
 */
const uint8_t * GetKyberPublicKeyFromHybrid(const HybridPublicKey & hybridKey);

} // namespace Crypto
} // namespace chip
