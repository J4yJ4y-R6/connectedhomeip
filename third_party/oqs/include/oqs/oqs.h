/* Minimal stub header for liboqs to allow builds without the real library.
 * Replace with upstream <oqs/oqs.h> when vendoring real liboqs.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OQS_SUCCESS 0

typedef struct {
    int length_public_key;
    int length_secret_key;
    int length_ciphertext;
    int length_shared_secret;
    const char *method_name;
} OQS_KEM;

typedef struct {
    int length_public_key;
    int length_secret_key;
    int length_signature;
    int length_signature_max;
    const char *method_name;
} OQS_SIG;

/* Algorithm identifiers (placeholders) */
#define OQS_KEM_alg_kyber_768 "KYBER_KEM_768"
#define OQS_SIG_alg_dilithium_3 "DILITHIUM_SIG_3"

/* KEM API (minimal subset) */
OQS_KEM *OQS_KEM_new(const char *method_name);
void OQS_KEM_free(OQS_KEM *kem);
int OQS_KEM_keypair(const OQS_KEM *kem, uint8_t *public_key, uint8_t *secret_key);
int OQS_KEM_encaps(const OQS_KEM *kem, uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
int OQS_KEM_decaps(const OQS_KEM *kem, uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);

/* Signature API (minimal subset) */
OQS_SIG *OQS_SIG_new(const char *method_name);
void OQS_SIG_free(OQS_SIG *sig);
int OQS_SIG_keypair(const OQS_SIG *sig, uint8_t *public_key, uint8_t *secret_key);
int OQS_SIG_sign(const OQS_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len,
                 const uint8_t *secret_key);
int OQS_SIG_verify(const OQS_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len,
                   const uint8_t *public_key);

#ifdef __cplusplus
}
#endif
