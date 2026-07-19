/* Force-included before every Dilithium source file to rename internal
 * C symbols that conflict with identically-named Kyber reference functions.
 * Applied only to dilithium-reference/ref/*.c via the "dilithium3_ref"
 * GN source_set; Kyber files and oqs_stub.c do NOT include this header.
 *
 * Note: Dilithium public API (keypair/signature/verify) and the shake stream
 * helpers (dilithium_shake128_stream_init etc.) are already namespaced via
 * DILITHIUM_NAMESPACE() in config.h / symmetric.h — no renames needed there.
 */
#ifndef DILITHIUM_NS_H
#define DILITHIUM_NS_H

/* ntt.c — conflicts with Kyber's ntt() */
#define ntt           dil3_ntt
/* invntt_tomont has no Kyber equivalent (Kyber uses invntt()), but prefix for clarity */
#define invntt_tomont dil3_invntt_tomont

/* reduce.c — montgomery_reduce conflicts with Kyber's montgomery_reduce() */
#define montgomery_reduce dil3_montgomery_reduce
#define reduce32          dil3_reduce32
#define caddq             dil3_caddq
#define freeze            dil3_freeze

/* poly.c — poly_ntt / poly_invntt_tomont / poly_add / poly_sub / poly_reduce
 * all conflict with Kyber's poly functions of the same name. */
#define poly_ntt                   dil3_poly_ntt
#define poly_invntt_tomont         dil3_poly_invntt_tomont
#define poly_pointwise_montgomery  dil3_poly_pointwise_montgomery
#define poly_add                   dil3_poly_add
#define poly_sub                   dil3_poly_sub
#define poly_reduce                dil3_poly_reduce
#define poly_caddq                 dil3_poly_caddq
#define poly_shiftl                dil3_poly_shiftl
#define poly_power2round           dil3_poly_power2round
#define poly_decompose             dil3_poly_decompose
#define poly_make_hint             dil3_poly_make_hint
#define poly_use_hint              dil3_poly_use_hint
#define poly_chknorm               dil3_poly_chknorm
#define poly_uniform               dil3_poly_uniform
#define poly_uniform_eta           dil3_poly_uniform_eta
#define poly_uniform_gamma1        dil3_poly_uniform_gamma1
#define poly_challenge             dil3_poly_challenge
#define polyeta_pack               dil3_polyeta_pack
#define polyeta_unpack             dil3_polyeta_unpack
#define polyt1_pack                dil3_polyt1_pack
#define polyt1_unpack              dil3_polyt1_unpack
#define polyt0_pack                dil3_polyt0_pack
#define polyt0_unpack              dil3_polyt0_unpack
#define polyz_pack                 dil3_polyz_pack
#define polyz_unpack               dil3_polyz_unpack
#define polyw1_pack                dil3_polyw1_pack

/* polyvec.c — Dilithium uses polyveck_* / polyvecl_* names (with k/l suffix)
 * so they don't conflict with Kyber's polyvec_* names, but prefix anyway. */
#define polyvec_matrix_expand                dil3_polyvec_matrix_expand
#define polyvec_matrix_pointwise_montgomery  dil3_polyvec_matrix_pointwise_montgomery
#define polyvecl_uniform_eta                 dil3_polyvecl_uniform_eta
#define polyvecl_uniform_gamma1              dil3_polyvecl_uniform_gamma1
#define polyvecl_reduce                      dil3_polyvecl_reduce
#define polyvecl_add                         dil3_polyvecl_add
#define polyvecl_ntt                         dil3_polyvecl_ntt
#define polyvecl_invntt_tomont               dil3_polyvecl_invntt_tomont
#define polyvecl_pointwise_poly_montgomery   dil3_polyvecl_pointwise_poly_montgomery
#define polyvecl_pointwise_acc_montgomery    dil3_polyvecl_pointwise_acc_montgomery
#define polyvecl_chknorm                     dil3_polyvecl_chknorm
#define polyveck_uniform_eta                 dil3_polyveck_uniform_eta
#define polyveck_reduce                      dil3_polyveck_reduce
#define polyveck_caddq                       dil3_polyveck_caddq
#define polyveck_add                         dil3_polyveck_add
#define polyveck_sub                         dil3_polyveck_sub
#define polyveck_shiftl                      dil3_polyveck_shiftl
#define polyveck_ntt                         dil3_polyveck_ntt
#define polyveck_invntt_tomont               dil3_polyveck_invntt_tomont
#define polyveck_pointwise_poly_montgomery   dil3_polyveck_pointwise_poly_montgomery
#define polyveck_chknorm                     dil3_polyveck_chknorm
#define polyveck_power2round                 dil3_polyveck_power2round
#define polyveck_decompose                   dil3_polyveck_decompose
#define polyveck_make_hint                   dil3_polyveck_make_hint
#define polyveck_use_hint                    dil3_polyveck_use_hint
#define polyveck_pack_w1                     dil3_polyveck_pack_w1

/* packing.c */
#define pack_pk    dil3_pack_pk
#define unpack_pk  dil3_unpack_pk
#define pack_sk    dil3_pack_sk
#define unpack_sk  dil3_unpack_sk
#define pack_sig   dil3_pack_sig
#define unpack_sig dil3_unpack_sig

/* rounding.c */
#define power2round dil3_power2round
#define decompose   dil3_decompose
#define make_hint   dil3_make_hint
#define use_hint    dil3_use_hint

#endif /* DILITHIUM_NS_H */
