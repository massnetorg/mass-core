#ifndef __BLS_WRAPPER__
#define __BLS_WRAPPER__

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
// #include <stdio.h>

enum SchemeMPLType
{
  SchemeMPLBasic=1, SchemeMPLAug, SchemeMPLPop
};

// void print_bytes(const char *data, size_t num_bytes) {
//   const unsigned char * bytes = reinterpret_cast<const unsigned char *>(data);
//   printf("[ ");
//   for (size_t i = 0; i < num_bytes; i++) {
//     printf("%*u ", 3, bytes[i]);
//   }
//   printf("]\n");
// }


/* PrivateKey */
size_t bls_PrivateKey_SIZE();
void *bls_PrivateKey_from_bytes(const char *buffer, const size_t size, char **err);
void bls_PrivateKey_to_bytes(const void *key, unsigned char **buffer, int *len);
void *bls_PrivateKey_copy(const void *key);
// void *bls_PrivateKey_get_g1(const void *key);
char *bls_PrivateKey_get_g1(const char *sk_bytes, unsigned char **buffer, int *len);
void *bls_PrivateKey_aggregate(const void **keys, const size_t cnt);

int bls_PrivateKey_cmp_eq(const void *a, const void *b);
int bls_PrivateKey_cmp_ne(const void *a, const void *b);

void bls_PrivateKey_free(void *key);

/* Util */
void bls_Util_hash256(const char *msg, const size_t len, unsigned char **output);

/* Public Key / G1Element */
size_t bls_G1Element_SIZE();
void bls_G1Element(unsigned char **buffer, int *len);
void bls_G1Element_generator(unsigned char **buffer, int *len);
void *bls_G1Element_from_bytes(const char *bytes, const size_t size, char **err);
void bls_G1Element_to_bytes(const void *g1, unsigned char **buffer, int *len);
void *bls_G1Element_from_message(const char *msg, size_t msg_len, const char *dst, size_t dst_len);
void *bls_G1Element_negate(const void *g1);
uint32_t bls_G1Element_get_fingerprint(const void *g1);
int bls_G1Element_cmp_eq(const void *a, const void *b);
int bls_G1Element_cmp_ne(const void *a, const void *b);
void *bls_G1Element_copy(const void *g1);
// void *bls_G1Element_add(const void *a, const void *b);
char *bls_G1Element_add(const char *e1_bytes, const char *e2_bytes, unsigned char **buffer, int *len);
// void *bls_G1Element_mul(const void *a, int d);
void bls_G1Element_free(void *g1);

/* G2Element / Signature */
size_t bls_G2Element_SIZE();
void bls_G2Element(unsigned char **buffer, int *len);
void bls_G2Element_generator(unsigned char **buffer, int *len);
void *bls_G2Element_from_bytes(const char *bytes, const size_t size, char **err);
void bls_G2Element_to_bytes(const void *g2, unsigned char **buffer, int *len);
void *bls_G2Element_from_message(const char *msg, size_t msg_len, const char *dst, size_t dst_len);
void *bls_G2Element_negate(const void *g2);
int bls_G2Element_cmp_eq(const void *a, const void *b);
int bls_G2Element_cmp_ne(const void *a, const void *b);
void *bls_G2Element_copy(const void *g2);
// void *bls_G2Element_add(const void *a, const void *b);
char *bls_G2Element_add(const char *e1_bytes, const char *e2_bytes, unsigned char **buffer, int *len);
// void *bls_G2Element_mul(const void *a, int d);
void bls_G2Element_free(void *g2);

/* SchemeMPL Common */
char *bls_SchemeMPL_sk_to_g1(size_t mpl, const char *sk_bytes, unsigned char **buffer, int *len);
char *bls_SchemeMPL_key_gen(size_t mpl, const char *seed, size_t seed_len, unsigned char **buffer, int *len);
char *bls_SchemeMPL_derive_child_sk(size_t mpl, size_t unhardened, const char *sk_bytes, int index, unsigned char **buffer, int *len);
char *bls_SchemeMPL_derive_child_pk_unhardened(size_t mpl, const char *pk_bytes, int index, unsigned char **buffer, int *len);
char *bls_SchemeMPL_aggregate(size_t mpl, const char **sigs, size_t cnt, unsigned char **buffer, int *len);
char *bls_SchemeMPL_sign(size_t mpl, const char *sk_bytes, const char *msg, size_t msg_len, unsigned char **buffer, int *buf_len);
char *bls_SchemeMPL_verify(size_t mpl, const char *pk_bytes, const char *msg, size_t len, const char *sig_bytes, int *ok);
char *bls_SchemeMPL_aggregate_verify(
  size_t mpl, 
  size_t pk_bytes_arr_len,
  const char **pk_bytes_arr,
  const char **msgs,
  size_t *msg_lens,
  const char *sig_bytes,
  int *ok
);


/* BasicSchemeMPL */
// char *bls_BasicSchemeMPL_sk_to_g1(const char *sk_bytes, unsigned char **buffer, int *len);
// void bls_BasicSchemeMPL_key_gen(const char *seed, size_t seed_len, unsigned char **buffer, int *len);
// char *bls_BasicSchemeMPL_derive_child_sk(const char *sk_bytes, int index, unsigned char **buffer, int *len);
// char *bls_BasicSchemeMPL_derive_child_sk_unhardened(const char *sk_bytes, int index, unsigned char **buffer, int *len);
// char *bls_BasicSchemeMPL_derive_child_pk_unhardened(const char *pk_bytes, int index, unsigned char **buffer, int *len);
// char *bls_BasicSchemeMPL_aggregate(const char **sigs, size_t cnt, unsigned char **buffer, int *len);
// char *bls_BasicSchemeMPL_sign(const char *sk_bytes, const char *msg, size_t msg_len, unsigned char **buffer, int *buf_len);
// int bls_BasicSchemeMPL_verify(const char *pk_bytes, const char *msg, size_t len, const char *sig_bytes, char **err);
// int bls_BasicSchemeMPL_aggregate_verify(
//   size_t pk_bytes_arr_len,
//   const char **pk_bytes_arr,
//   const char **msgs,
//   size_t *msg_lens,
//   const char *sig_bytes,
//   char **err
// );

/* AugSchemeMPL */
// char *bls_AugSchemeMPL_sk_to_g1(const char *sk_bytes, unsigned char **buffer, int *len);
// void bls_AugSchemeMPL_key_gen(const char *seed, size_t seed_len, unsigned char **buffer, int *len);
// char *bls_AugSchemeMPL_derive_child_sk(const char *sk_bytes, int index, unsigned char **buffer, int *len);
// void *bls_AugSchemeMPL_derive_child_sk_unhardened(const void *key, int index);
// void *bls_AugSchemeMPL_derive_child_pk_unhardened(const void *g1, int index);
// void *bls_AugSchemeMPL_aggregate(const void **g2s, size_t cnt);
// void *bls_AugSchemeMPL_sign(const void *key, const char *msg, size_t len);
// int bls_AugSchemeMPL_verify(const void *g1, const char *msg, size_t len, const void *g2);
// int bls_AugSchemeMPL_aggregate_verify(
//   size_t cnt,
//   const void **g1s,
//   const char **msgs,
//   size_t *lens,
//   const void *g2
// );
char *bls_AugSchemeMPL_sign_prepend(
  const char *sk_bytes, 
  const char *prepend_pk_bytes, 
  const char *msg, size_t len, 
  unsigned char **buffer, int *buf_len
);

/* PopSchemeMPL */
// void *bls_PopSchemeMPL_sk_to_g1(const void *key);
// void *bls_PopSchemeMPL_key_gen(const char *seed, size_t seed_len);
// void *bls_PopSchemeMPL_derive_child_sk(const void *key, int index);
// void *bls_PopSchemeMPL_derive_child_sk_unhardened(const void *key, int index);
// void *bls_PopSchemeMPL_derive_child_pk_unhardened(const void *g1, int index);
// void *bls_PopSchemeMPL_aggregate(const void **g2s, size_t cnt);
// void *bls_PopSchemeMPL_sign(const void *key, const char *msg, size_t len);
// int bls_PopSchemeMPL_verify(const void *g1, const char *msg, size_t len, const void *g2);
// int bls_PopSchemeMPL_aggregate_verify(
//   size_t cnt,
//   const void **g1s,
//   const char **msgs,
//   size_t *lens,
//   const void *g2
// );
char *bls_PopSchemeMPL_pop_prove(const char *sk_bytes, unsigned char **buffer, int *buf_len);
char *bls_PopSchemeMPL_pop_verify(const char *pk_bytes, const char *sig_bytes, int *ok);
char *bls_PopSchemeMPL_fast_aggregate_verify(
  const char **pk_bytes_arr,
  size_t pk_bytes_arr_len,
  const char *msg,
  size_t msg_len,
  const char *sig_bytes,
  int *ok
);

#ifdef __cplusplus
}
#endif

#endif // __BLS_WRAPPER__
