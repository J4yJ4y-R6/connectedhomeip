/* Real liboqs API implementation using reference Kyber-768 and Dilithium-3
 * implementations. Both are pure portable C (no BoringSSL dependency).
 *
 * Kyber:    kyber-reference/ref/  (pqcrystals_kyber768_ref_*)
 * Dilithium: dilithium-reference/ref/ compiled with -DDILITHIUM_MODE=3
 *            (pqcrystals_dilithium3_ref_*)
 */

#include "../include/oqs/oqs.h"
#include <stdlib.h>
#include <string.h>

/* ===== Kyber-768 reference implementation ===== */
int pqcrystals_kyber768_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber768_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber768_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

OQS_KEM *OQS_KEM_new(const char *method_name)
{
    OQS_KEM *kem = (OQS_KEM *)malloc(sizeof(OQS_KEM));
    if (!kem) return NULL;

    if (method_name && strcmp(method_name, "KYBER_KEM_768") == 0) {
        kem->length_public_key  = 1184;
        kem->length_secret_key  = 2400;
        kem->length_ciphertext  = 1088;
        kem->length_shared_secret = 32;
    } else {
        free(kem);
        return NULL;
    }
    kem->method_name = method_name;
    return kem;
}

void OQS_KEM_free(OQS_KEM *kem) { free(kem); }

int OQS_KEM_keypair(const OQS_KEM *kem, uint8_t *public_key, uint8_t *secret_key)
{
    if (!kem || kem->length_public_key != 1184 || kem->length_secret_key != 2400)
        return -1;
    return pqcrystals_kyber768_ref_keypair(public_key, secret_key);
}

int OQS_KEM_encaps(const OQS_KEM *kem, uint8_t *ciphertext, uint8_t *shared_secret,
                   const uint8_t *public_key)
{
    if (!kem || kem->length_ciphertext != 1088 || kem->length_shared_secret != 32)
        return -1;
    return pqcrystals_kyber768_ref_enc(ciphertext, shared_secret, public_key);
}

int OQS_KEM_decaps(const OQS_KEM *kem, uint8_t *shared_secret, const uint8_t *ciphertext,
                   const uint8_t *secret_key)
{
    if (!kem || kem->length_ciphertext != 1088 || kem->length_shared_secret != 32)
        return -1;
    return pqcrystals_kyber768_ref_dec(shared_secret, ciphertext, secret_key);
}

/* ===== Dilithium-3 reference implementation ===== */
/* Compiled with -DDILITHIUM_MODE=3; functions are namespaced as
 * pqcrystals_dilithium3_ref_* via the DILITHIUM_NAMESPACE macro in config.h. */
int pqcrystals_dilithium3_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_dilithium3_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk);
int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk);

#define DILITHIUM3_PUBLIC_KEY_BYTES  1952
#define DILITHIUM3_PRIVATE_KEY_BYTES 4032
#define DILITHIUM3_SIGNATURE_BYTES   3309

OQS_SIG *OQS_SIG_new(const char *method_name)
{
    OQS_SIG *sig = (OQS_SIG *)malloc(sizeof(OQS_SIG));
    if (!sig) return NULL;

    if (method_name && strcmp(method_name, "DILITHIUM_SIG_3") == 0) {
        sig->length_public_key    = DILITHIUM3_PUBLIC_KEY_BYTES;
        sig->length_secret_key    = DILITHIUM3_PRIVATE_KEY_BYTES;
        sig->length_signature     = DILITHIUM3_SIGNATURE_BYTES;
        sig->length_signature_max = DILITHIUM3_SIGNATURE_BYTES;
    } else {
        free(sig);
        return NULL;
    }
    sig->method_name = method_name;
    return sig;
}

void OQS_SIG_free(OQS_SIG *sig) { free(sig); }

int OQS_SIG_keypair(const OQS_SIG *sig, uint8_t *public_key, uint8_t *secret_key)
{
    if (!sig || sig->length_public_key != DILITHIUM3_PUBLIC_KEY_BYTES ||
        sig->length_secret_key != DILITHIUM3_PRIVATE_KEY_BYTES)
        return -1;
    return pqcrystals_dilithium3_ref_keypair(public_key, secret_key);
}

int OQS_SIG_sign(const OQS_SIG *sig, uint8_t *signature, size_t *signature_len,
                 const uint8_t *message, size_t message_len, const uint8_t *secret_key)
{
    if (!sig || sig->length_signature != DILITHIUM3_SIGNATURE_BYTES)
        return -1;
    /* ctx=NULL, ctxlen=0: empty context, safe per reference implementation */
    return pqcrystals_dilithium3_ref_signature(signature, signature_len,
                                               message, message_len,
                                               NULL, 0, secret_key);
}

int OQS_SIG_verify(const OQS_SIG *sig, const uint8_t *message, size_t message_len,
                   const uint8_t *signature, size_t signature_len, const uint8_t *public_key)
{
    if (!sig || sig->length_signature != DILITHIUM3_SIGNATURE_BYTES ||
        signature_len != DILITHIUM3_SIGNATURE_BYTES)
        return -1;
    return pqcrystals_dilithium3_ref_verify(signature, signature_len,
                                            message, message_len,
                                            NULL, 0, public_key);
}
