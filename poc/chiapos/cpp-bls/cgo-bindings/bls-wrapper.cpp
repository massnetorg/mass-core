#include "bls-wrapper.h"

#include "../src/bls.hpp"
#include "../src/privatekey.hpp"
#include "../src/elements.hpp"
#include "../src/hdkeys.hpp"
#include "../src/schemes.hpp"

using namespace bls;

size_t bls_PrivateKey_SIZE() {
  return PrivateKey::PRIVATE_KEY_SIZE;
}

void *bls_PrivateKey_from_bytes(const char *buffer, const size_t size, char **err) {
  try
  {
    if (size != PrivateKey::PRIVATE_KEY_SIZE) {
      throw std::invalid_argument("Length of bytes object not equal to PrivateKey size");
    }
    PrivateKey k = PrivateKey::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(buffer), PrivateKey::PRIVATE_KEY_SIZE));
    PrivateKey *pk = new PrivateKey(std::move(k));
    return pk;
  }
  catch(const std::exception& e)
  {
    *err = (char *)malloc(strlen(e.what()));
    strcpy(*err, e.what());
    return NULL;
  }
}

void bls_PrivateKey_to_bytes(const void *key, unsigned char **buffer, int *len) {
  const PrivateKey *pk = reinterpret_cast<const PrivateKey *>(key);

  // uint8_t *output =
  //     Util::SecAlloc<uint8_t>(PrivateKey::PRIVATE_KEY_SIZE);
  // pk->Serialize(output);
  // memcpy(buffer, output, PrivateKey::PRIVATE_KEY_SIZE);
  // Util::SecFree(output);
  uint8_t *output = (uint8_t *)malloc(PrivateKey::PRIVATE_KEY_SIZE);
  pk->Serialize(output);
  *buffer = output;
  *len = PrivateKey::PRIVATE_KEY_SIZE;
}

void *bls_PrivateKey_copy(const void * key) {
  const PrivateKey *pk = reinterpret_cast<const PrivateKey *>(key);

  PrivateKey *copied = new PrivateKey(*pk);
  return copied;
}

// void *bls_PrivateKey_get_g1(const void * key) {
//   const PrivateKey *pk = reinterpret_cast<const PrivateKey *>(key);
//   return new G1Element(pk->GetG1Element());
// }

char *bls_PrivateKey_get_g1(const char *sk_bytes, unsigned char **buffer, int *len) 
{
  try
  {
    PrivateKey k = PrivateKey::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sk_bytes), PrivateKey::PRIVATE_KEY_SIZE));
    vector<uint8_t> out = k.GetG1Element().Serialize();
    *len = out.size();
    *buffer = (uint8_t *)malloc(*len);
    memcpy(*buffer, out.data(), *len);
   
    return NULL;
  }
  catch(const std::exception& e)
  {
    char *err = (char *)malloc(strlen(e.what()));
    strcpy(err, e.what());
    return err;
  }
}

void *bls_PrivateKey_aggregate(const void **keys, const size_t cnt) {
  const PrivateKey **pkeys = reinterpret_cast<const PrivateKey **>(keys);
  std::vector<PrivateKey> collection;
  collection.reserve(cnt);
  for(size_t i = 0; i<cnt; ++i)
    collection.emplace_back(*pkeys[i]);
  
  PrivateKey aggregated = PrivateKey::Aggregate(collection);
  return new PrivateKey(std::move(aggregated));
}

int bls_PrivateKey_cmp_eq(const void *a, const void *b) {
  const PrivateKey *pa = reinterpret_cast<const PrivateKey *>(a);
  const PrivateKey *pb = reinterpret_cast<const PrivateKey *>(b);
  return *pa == *pb ? 1 : 0;
}

int bls_PrivateKey_cmp_ne(const void *a, const void *b) {
  const PrivateKey *pa = reinterpret_cast<const PrivateKey *>(a);
  const PrivateKey *pb = reinterpret_cast<const PrivateKey *>(b);
  return *pa != *pb ? 1 : 0;
}

void bls_PrivateKey_free(void *key) {
  PrivateKey *pk = reinterpret_cast<PrivateKey *>(key);
  delete pk;
}

void bls_Util_hash256(const char *msg, const size_t len, unsigned char **output) {
  uint8_t *outbuf = (uint8_t *)malloc(32);
  Util::Hash256(outbuf, reinterpret_cast<const uint8_t *>(msg), len);
  *output = outbuf;
}

// ===========================  SchemeMPL Common  =======================================
char *bls_SchemeMPL_sk_to_g1(size_t mpl, const char *sk_bytes, unsigned char **buffer, int *len)
{
  try
  {
    PrivateKey sk = PrivateKey::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sk_bytes), PrivateKey::PRIVATE_KEY_SIZE));
    G1Element g1;
    switch (mpl)
    {
      case SchemeMPLBasic:
      {
        g1 = BasicSchemeMPL().SkToG1(sk);
        break;
      }
      case SchemeMPLAug:
      {
        g1 = AugSchemeMPL().SkToG1(sk);
        break;
      }
      case SchemeMPLPop:
      {
        g1 = PopSchemeMPL().SkToG1(sk);
        break;
      }
      default:
        throw std::invalid_argument("unknow scheme mpl type");
    }

    vector<uint8_t> out = g1.Serialize();
    *len = out.size();
    *buffer = (uint8_t *)malloc(*len);
    memcpy(*buffer, out.data(), *len);

    return NULL;
  }
  catch(const std::exception& e)
  {
    char *err = (char *)malloc(strlen(e.what()));
    strcpy(err, e.what());
    return err;
  }
}

char *bls_SchemeMPL_key_gen(size_t mpl, const char *seed, size_t seed_len, unsigned char **buffer, int *len)
{
  try
  {
    uint8_t *output = (uint8_t *)malloc(PrivateKey::PRIVATE_KEY_SIZE);
    *buffer = output;
    *len = PrivateKey::PRIVATE_KEY_SIZE;

    switch (mpl)
    {
      case SchemeMPLBasic:
      {
        PrivateKey sk = BasicSchemeMPL().KeyGen(Bytes(reinterpret_cast<const uint8_t *>(seed), seed_len));
        sk.Serialize(output);
        break;
      }
      case SchemeMPLAug:
      {
        PrivateKey sk = AugSchemeMPL().KeyGen(Bytes(reinterpret_cast<const uint8_t *>(seed), seed_len));
        sk.Serialize(output);
        break;
      }
      case SchemeMPLPop:
      {
        PrivateKey sk = PopSchemeMPL().KeyGen(Bytes(reinterpret_cast<const uint8_t *>(seed), seed_len));
        sk.Serialize(output);
        break;
      }
      default:
        throw std::invalid_argument("unknow scheme mpl type");
    }

    return NULL;
  }
  catch(const std::exception& e)
  {
    char *err = (char *)malloc(strlen(e.what()));
    strcpy(err, e.what());
    return err;
  }
}

char *bls_SchemeMPL_derive_child_sk(size_t mpl, size_t unhardened, const char *sk_bytes, int index, unsigned char **buffer, int *len)
{
  try
  {
    PrivateKey master = PrivateKey::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sk_bytes), PrivateKey::PRIVATE_KEY_SIZE));

    uint8_t *output = (uint8_t *)malloc(PrivateKey::PRIVATE_KEY_SIZE);
    *buffer = output;
    *len = PrivateKey::PRIVATE_KEY_SIZE;

    switch (mpl)
    {
      case SchemeMPLBasic:
      {
        PrivateKey derived = unhardened == 0 ? 
          BasicSchemeMPL().DeriveChildSk(master, index) : BasicSchemeMPL().DeriveChildSkUnhardened(master, index);
        derived.Serialize(output);
        break;
      }
      case SchemeMPLAug:
      {
        PrivateKey derived = unhardened == 0 ? 
          AugSchemeMPL().DeriveChildSk(master, index) : AugSchemeMPL().DeriveChildSkUnhardened(master, index);
        derived.Serialize(output);
        break;
      }
      case SchemeMPLPop:
      {
        PrivateKey derived = unhardened == 0 ? 
          PopSchemeMPL().DeriveChildSk(master, index) : PopSchemeMPL().DeriveChildSkUnhardened(master, index);
        derived.Serialize(output);
        break;
      }
      default:
        throw std::invalid_argument("unknow scheme mpl type");
    }
    return NULL;
  }
  catch(const std::exception& e)
  {
    char *err = (char *)malloc(strlen(e.what()));
    strcpy(err, e.what());
    return err;
  }
}

char *bls_SchemeMPL_derive_child_pk_unhardened(size_t mpl, const char *pk_bytes, int index, unsigned char **buffer, int *len)
{
  try
  {
    G1Element master = G1Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(pk_bytes), G1Element::SIZE));
    G1Element pk;

    switch (mpl)
    {
      case SchemeMPLBasic:
      {
        pk = BasicSchemeMPL().DeriveChildPkUnhardened(master, index);
        break;
      }
      case SchemeMPLAug:
      {
        pk = AugSchemeMPL().DeriveChildPkUnhardened(master, index);
        break;
      }
      case SchemeMPLPop:
      {
        pk = PopSchemeMPL().DeriveChildPkUnhardened(master, index);
        break;
      }
      default:
        throw std::invalid_argument("unknow scheme mpl type");
    }

    vector<uint8_t> out = pk.Serialize();
    *len = out.size();
    *buffer = (uint8_t *)malloc(*len);
    memcpy(*buffer, out.data(), *len);
    return NULL;
  }
  catch(const std::exception& e)
  {
    char *err = (char *)malloc(strlen(e.what()));
    strcpy(err, e.what());
    return err;
  }
}

char *bls_SchemeMPL_aggregate(size_t mpl, const char **sigs, size_t cnt, unsigned char **buffer, int *len)
{
  try
  {
    std::vector<G2Element> vsigs;
    vsigs.reserve(cnt);
    for(size_t i = 0; i < cnt; ++i)
    {
      G2Element g2 = G2Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sigs[i]), G2Element::SIZE));
      vsigs.emplace_back(g2);
    }

    G2Element aggregated;
    switch (mpl)
    {
      case SchemeMPLBasic:
      {
        aggregated = BasicSchemeMPL().Aggregate(vsigs);
        break;
      }
      case SchemeMPLAug:
      {
        aggregated = AugSchemeMPL().Aggregate(vsigs);
        break;
      }
      case SchemeMPLPop:
      {
        aggregated = PopSchemeMPL().Aggregate(vsigs);
        break;
      }
      default:
        throw std::invalid_argument("unknow scheme mpl type");
    }

    vector<uint8_t> out = aggregated.Serialize();
    *len = out.size();
    *buffer = (uint8_t *)malloc(*len);
    memcpy(*buffer, out.data(), *len);

    return NULL;
  }
  catch(const std::exception& e)
  {
    char *err = (char *)malloc(strlen(e.what()));
    strcpy(err, e.what());
    return err;
  }
}

char *bls_SchemeMPL_sign(size_t mpl, const char *sk_bytes, const char *msg, size_t msg_len, unsigned char **buffer, int *buf_len)
{
  try
  {
    PrivateKey sk = PrivateKey::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sk_bytes), PrivateKey::PRIVATE_KEY_SIZE));
    G2Element sig;

    switch (mpl)
    {
      case SchemeMPLBasic:
      {
        sig = BasicSchemeMPL().Sign(sk, Bytes(reinterpret_cast<const uint8_t *>(msg), msg_len));
        break;
      }
      case SchemeMPLAug:
      {
        sig = AugSchemeMPL().Sign(sk, Bytes(reinterpret_cast<const uint8_t *>(msg), msg_len));
        break;
      }
      case SchemeMPLPop:
      {
        sig = PopSchemeMPL().Sign(sk, Bytes(reinterpret_cast<const uint8_t *>(msg), msg_len));
        break;
      }
      default:
        throw std::invalid_argument("unknow scheme mpl type");
    }

    vector<uint8_t> out = sig.Serialize();
    *buf_len = out.size();
    *buffer = (uint8_t *)malloc(*buf_len);
    memcpy(*buffer, out.data(), *buf_len);
    return NULL;
  }
  catch(const std::exception& e)
  {
    char *err = (char *)malloc(strlen(e.what()));
    strcpy(err, e.what());
    return err;
  }
}

char *bls_SchemeMPL_verify(size_t mpl, const char *pk_bytes, const char *msg, size_t len, const char *sig_bytes, int *ok)
{
  try
  {
    G1Element pk = G1Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(pk_bytes), G1Element::SIZE));
    G2Element sig = G2Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sig_bytes), G2Element::SIZE));

    switch (mpl)
    {
      case SchemeMPLBasic:
      {
        *ok = BasicSchemeMPL().Verify(pk, Bytes(
          reinterpret_cast<const uint8_t *>(msg),
          len
        ), sig) ? 1 : 0;
        break;
      }
      case SchemeMPLAug:
      {
        *ok = AugSchemeMPL().Verify(pk, Bytes(
          reinterpret_cast<const uint8_t *>(msg),
          len
        ), sig) ? 1 : 0;
        break;
      }
      case SchemeMPLPop:
      {
        *ok = PopSchemeMPL().Verify(pk, Bytes(
          reinterpret_cast<const uint8_t *>(msg),
          len
        ), sig) ? 1 : 0;
        break;
      }
      default:
        throw std::invalid_argument("unknow scheme mpl type");
    }

    return NULL;
  }
  catch(const std::exception& e)
  {
    char *err = (char *)malloc(strlen(e.what()));
    strcpy(err, e.what());
    return err;
  }
}

char *bls_SchemeMPL_aggregate_verify(
  size_t mpl, 
  size_t pk_bytes_arr_len,
  const char **pk_bytes_arr,
  const char **msgs,
  size_t *msg_lens,
  const char *sig_bytes,
  int *ok
)
{
  try
  {
    std::vector<G1Element> pubkeys;
    std::vector<Bytes> vmsgs;
    pubkeys.reserve(pk_bytes_arr_len);
    vmsgs.reserve(pk_bytes_arr_len);

    for(size_t i = 0; i < pk_bytes_arr_len; ++i) {
      G1Element pk = G1Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(pk_bytes_arr[i]), G1Element::SIZE));
      pubkeys.emplace_back(pk);

      vmsgs.emplace_back(Bytes(reinterpret_cast<const uint8_t *>(msgs[i]), msg_lens[i]));
    }
    G2Element sig = G2Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sig_bytes), G2Element::SIZE));

    switch (mpl)
    {
      case SchemeMPLBasic:
      {
        *ok = BasicSchemeMPL().AggregateVerify(pubkeys, vmsgs, sig) ? 1 : 0;
        break;
      }
      case SchemeMPLAug:
      {
        *ok = AugSchemeMPL().AggregateVerify(pubkeys, vmsgs, sig) ? 1 : 0;
        break;
      }
      case SchemeMPLPop:
      {
        *ok = PopSchemeMPL().AggregateVerify(pubkeys, vmsgs, sig) ? 1 : 0;
        break;
      }
      default:
        throw std::invalid_argument("unknow scheme mpl type");
    }
    return NULL;
  }
  catch(const std::exception& e)
  {
    char *err = (char *)malloc(strlen(e.what()));
    strcpy(err, e.what());
    return err;
  }
}

// char *bls_BasicSchemeMPL_sk_to_g1(const char *sk_bytes, unsigned char **buffer, int *len) {
//   try
//   {
//     PrivateKey sk = PrivateKey::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sk_bytes), PrivateKey::PRIVATE_KEY_SIZE));
//     G1Element g1 = BasicSchemeMPL().SkToG1(sk);
//     vector<uint8_t> out = g1.Serialize();
//     *len = out.size();
//     *buffer = (uint8_t *)malloc(*len);
//     memcpy(*buffer, out.data(), *len);

//     return NULL;
//   }
//   catch(const std::exception& e)
//   {
//     char *err = (char *)malloc(strlen(e.what()));
//     strcpy(err, e.what());
//     return err;
//   }
// }

// void bls_BasicSchemeMPL_key_gen(const char *seed, size_t seed_len, unsigned char **buffer, int *len) {
//   PrivateKey k = BasicSchemeMPL().KeyGen(Bytes(
//     reinterpret_cast<const uint8_t *>(seed),
//     seed_len
//   ));

//   uint8_t *output = (uint8_t *)malloc(PrivateKey::PRIVATE_KEY_SIZE);
//   k.Serialize(output);
//   *buffer = output;
//   *len = PrivateKey::PRIVATE_KEY_SIZE;
// }

// char *bls_BasicSchemeMPL_derive_child_sk(const char *sk_bytes, int index, unsigned char **buffer, int *len)
// {
//   try
//   {
//     PrivateKey master = PrivateKey::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sk_bytes), PrivateKey::PRIVATE_KEY_SIZE));
//     PrivateKey k = BasicSchemeMPL().DeriveChildSk(master, index);
//     uint8_t *output = (uint8_t *)malloc(PrivateKey::PRIVATE_KEY_SIZE);
//     k.Serialize(output);
//     *buffer = output;
//     *len = PrivateKey::PRIVATE_KEY_SIZE;
//     return NULL;
//   }
//   catch(const std::exception& e)
//   {
//     char *err = (char *)malloc(strlen(e.what()));
//     strcpy(err, e.what());
//     return err;
//   }
// }

// char *bls_BasicSchemeMPL_derive_child_sk_unhardened(const char *sk_bytes, int index, unsigned char **buffer, int *len) 
// {
//   try
//   {
//     PrivateKey master = PrivateKey::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sk_bytes), PrivateKey::PRIVATE_KEY_SIZE));
//     PrivateKey k = BasicSchemeMPL().DeriveChildSkUnhardened(master, index);
//     uint8_t *output = (uint8_t *)malloc(PrivateKey::PRIVATE_KEY_SIZE);
//     k.Serialize(output);
//     *buffer = output;
//     *len = PrivateKey::PRIVATE_KEY_SIZE;
//     return NULL;
//   }
//   catch(const std::exception& e)
//   {
//     char *err = (char *)malloc(strlen(e.what()));
//     strcpy(err, e.what());
//     return err;
//   }
// }

// char *bls_BasicSchemeMPL_derive_child_pk_unhardened(const char *pk_bytes, int index, unsigned char **buffer, int *len) 
// {
//   try
//   {
//     G1Element master = G1Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(pk_bytes), G1Element::SIZE));
//     G1Element pk = BasicSchemeMPL().DeriveChildPkUnhardened(master,index);
//     vector<uint8_t> out = pk.Serialize();
//     *len = out.size();
//     *buffer = (uint8_t *)malloc(*len);
//     memcpy(*buffer, out.data(), *len);
//     return NULL;
//   }
//   catch(const std::exception& e)
//   {
//     char *err = (char *)malloc(strlen(e.what()));
//     strcpy(err, e.what());
//     return err;
//   }
// }

// char *bls_BasicSchemeMPL_aggregate(const char **sigs, size_t cnt, unsigned char **buffer, int *len) 
// {
//   try
//   {
//     std::vector<G2Element> vsigs;
//     vsigs.reserve(cnt);
//     for(size_t i = 0; i < cnt; ++i)
//     {
//       G2Element g2 = G2Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sigs[i]), G2Element::SIZE));
//       vsigs.emplace_back(g2);
//     }

//     G2Element aggregated = BasicSchemeMPL().Aggregate(vsigs);
//     vector<uint8_t> out = aggregated.Serialize();
//     *len = out.size();
//     *buffer = (uint8_t *)malloc(*len);
//     memcpy(*buffer, out.data(), *len);
//     return NULL;
//   }
//   catch(const std::exception& e)
//   {
//     char *err = (char *)malloc(strlen(e.what()));
//     strcpy(err, e.what());
//     return err;
//   }
// }

// char *bls_BasicSchemeMPL_sign(const char *sk_bytes, const char *msg, size_t msg_len, unsigned char **buffer, int *buf_len) 
// {
//   try
//   {
//     PrivateKey sk = PrivateKey::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sk_bytes), PrivateKey::PRIVATE_KEY_SIZE));
//     G2Element sig = BasicSchemeMPL().Sign(sk, Bytes(
//       reinterpret_cast<const uint8_t *>(msg),
//       msg_len
//     ));

//     vector<uint8_t> out = sig.Serialize();
//     *buf_len = out.size();
//     *buffer = (uint8_t *)malloc(*buf_len);
//     memcpy(*buffer, out.data(), *buf_len);
//     return NULL;
//   }
//   catch(const std::exception& e)
//   {
//     char *err = (char *)malloc(strlen(e.what()));
//     strcpy(err, e.what());
//     return err;
//   }
// }

// int bls_BasicSchemeMPL_verify(const char *pk_bytes, const char *msg, size_t len, const char *sig_bytes, char **err) 
// {
//   try
//   {
//     G1Element pk = G1Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(pk_bytes), G1Element::SIZE));
//     G2Element sig = G2Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sig_bytes), G2Element::SIZE));
//     return BasicSchemeMPL().Verify(pk, Bytes(
//       reinterpret_cast<const uint8_t *>(msg),
//       len
//     ), sig) ? 1 : 0;
//   }
//   catch(const std::exception& e)
//   {
//     *err = (char *)malloc(strlen(e.what()));
//     strcpy(*err, e.what());
//     return 0;
//   }
// }

// int bls_BasicSchemeMPL_aggregate_verify(
//   size_t pk_bytes_arr_len,
//   const char **pk_bytes_arr,
//   const char **msgs,
//   size_t *msg_lens,
//   const char *sig_bytes,
//   char **err
// )
// {
//   try
//   {
//     std::vector<G1Element> pubkeys;
//     std::vector<Bytes> vmsgs;
//     pubkeys.reserve(pk_bytes_arr_len);
//     vmsgs.reserve(pk_bytes_arr_len);

//     for(size_t i = 0; i < pk_bytes_arr_len; ++i) {
//       G1Element pk = G1Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(pk_bytes_arr[i]), G1Element::SIZE));
//       pubkeys.emplace_back(pk);

//       vmsgs.emplace_back(Bytes(
//         reinterpret_cast<const uint8_t *>(msgs[i]),
//         msg_lens[i]
//       ));
//     }

//     G2Element sig = G2Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sig_bytes), G2Element::SIZE));
//     return BasicSchemeMPL().AggregateVerify(pubkeys, vmsgs, sig) ? 1 : 0;
//   }
//   catch(const std::exception& e)
//   {
//     *err = (char *)malloc(strlen(e.what()));
//     strcpy(*err, e.what());
//     return 0;
//   }
// }

// char *bls_AugSchemeMPL_sk_to_g1(const char *sk_bytes, unsigned char **buffer, int *len) {
//   try
//   {
//     PrivateKey sk = PrivateKey::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sk_bytes), PrivateKey::PRIVATE_KEY_SIZE));
//     G1Element g1 = AugSchemeMPL().SkToG1(sk);
//     vector<uint8_t> out = g1.Serialize();
//     *len = out.size();
//     *buffer = (uint8_t *)malloc(*len);
//     memcpy(*buffer, out.data(), *len);

//     return NULL;
//   }
//   catch(const std::exception& e)
//   {
//     char *err = (char *)malloc(strlen(e.what()));
//     strcpy(err, e.what());
//     return err;
//   }
// }

// void bls_AugSchemeMPL_key_gen(const char *seed, size_t seed_len, unsigned char **buffer, int *len) {
//   PrivateKey sk = AugSchemeMPL().KeyGen(Bytes(
//     reinterpret_cast<const uint8_t *>(seed),
//     seed_len
//   ));

//   uint8_t *output = (uint8_t *)malloc(PrivateKey::PRIVATE_KEY_SIZE);
//   sk.Serialize(output);
//   *buffer = output;
//   *len = PrivateKey::PRIVATE_KEY_SIZE;
// }

// char *bls_AugSchemeMPL_derive_child_sk(const char *sk_bytes, int index, unsigned char **buffer, int *len) {
//   try
//   {
//     PrivateKey master = PrivateKey::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sk_bytes), PrivateKey::PRIVATE_KEY_SIZE));
//     PrivateKey k = AugSchemeMPL().DeriveChildSk(master, index);
//     uint8_t *output = (uint8_t *)malloc(PrivateKey::PRIVATE_KEY_SIZE);
//     k.Serialize(output);
//     *buffer = output;
//     *len = PrivateKey::PRIVATE_KEY_SIZE;
//     return NULL;
//   }
//   catch(const std::exception& e)
//   {
//     char *err = (char *)malloc(strlen(e.what()));
//     strcpy(err, e.what());
//     return err;
//   }
// }

// void *bls_AugSchemeMPL_derive_child_sk_unhardened(const void *key, int index) {
//   const PrivateKey *master = reinterpret_cast<const PrivateKey *>(key);
//   PrivateKey k = AugSchemeMPL().DeriveChildSkUnhardened(
//     *master,
//     index
//   );
//   PrivateKey *pk = new PrivateKey(std::move(k));
//   return pk;
// }

// void *bls_AugSchemeMPL_derive_child_pk_unhardened(const void *g1, int index) {
//   const G1Element *master = reinterpret_cast<const G1Element *>(g1);
//   G1Element pk = AugSchemeMPL().DeriveChildPkUnhardened(
//     *master,
//     index
//   );
//   G1Element *ppk = new G1Element(pk);
//   return ppk;
// }

// void *bls_AugSchemeMPL_aggregate(const void **g2s, size_t cnt) {
//   const G2Element **sigs = reinterpret_cast<const G2Element **>(g2s);
//   std::vector<G2Element> vsigs;
//   vsigs.reserve(cnt);
//   for(size_t i = 0; i < cnt; ++i)
//     vsigs.emplace_back(*sigs[i]);
//   G2Element aggregated = AugSchemeMPL().Aggregate(vsigs);
//   return new G2Element(aggregated);
// }

// void *bls_AugSchemeMPL_sign(const void *key, const char *msg, size_t len) {
//   const PrivateKey *k = reinterpret_cast<const PrivateKey *>(key);
//   G2Element sig = AugSchemeMPL().Sign(*k, Bytes(
//     reinterpret_cast<const uint8_t *>(msg),
//     len
//   ));
//   return new G2Element(sig);
// }

char *bls_AugSchemeMPL_sign_prepend(
  const char *sk_bytes, 
  const char *prepend_pk_bytes, 
  const char *msg, size_t len, 
  unsigned char **buffer, int *buf_len
)
{
  try
  {
    PrivateKey sk = PrivateKey::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sk_bytes), PrivateKey::PRIVATE_KEY_SIZE));
    G1Element prepend_pk = G1Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(prepend_pk_bytes), G1Element::SIZE));

    G2Element sig = AugSchemeMPL().Sign(sk, Bytes(reinterpret_cast<const uint8_t *>(msg), len), prepend_pk);

    vector<uint8_t> out = sig.Serialize();
    *buf_len = out.size();
    *buffer = (uint8_t *)malloc(*buf_len);
    memcpy(*buffer, out.data(), *buf_len);

    return NULL;
  }
  catch(const std::exception& e)
  {
    char *err = (char *)malloc(strlen(e.what()));
    strcpy(err, e.what());
    return err;
  }
}

// int bls_AugSchemeMPL_verify(const void *g1, const char *msg, size_t len, const void *g2) {
//   const G1Element *pk = reinterpret_cast<const G1Element *>(g1);
//   const G2Element *sig = reinterpret_cast<const G2Element *>(g2);
//   return AugSchemeMPL().Verify(*pk, Bytes(
//     reinterpret_cast<const uint8_t *>(msg),
//     len
//   ), *sig) ? 1 : 0;
// }

// int bls_AugSchemeMPL_aggregate_verify(
//   size_t cnt,
//   const void **g1s,
//   const char **msgs,
//   size_t *lens,
//   const void *g2
// ) {
//   std::vector<G1Element> pubkeys;
//   std::vector<Bytes> vmsgs;
//   pubkeys.reserve(cnt);
//   vmsgs.reserve(cnt);

//   for(size_t i = 0; i < cnt; ++i) {
//     pubkeys.emplace_back(*(reinterpret_cast<const G1Element **>(g1s)[i]));
//     vmsgs.emplace_back(Bytes(
//       reinterpret_cast<const uint8_t *>(msgs[i]),
//       lens[i]
//     ));
//   }

//   const G2Element *sig = reinterpret_cast<const G2Element *>(g2);

//   return AugSchemeMPL().AggregateVerify(pubkeys, vmsgs, *sig) ? 1 : 0;
// }

// void *bls_PopSchemeMPL_sk_to_g1(const void *key) {
//   const PrivateKey *pk = reinterpret_cast<const PrivateKey *>(key);
//   G1Element g1 = PopSchemeMPL().SkToG1(*pk);
//   G1Element *pg1 = new G1Element(g1);
//   return pg1;
// }

// void *bls_PopSchemeMPL_key_gen(const char *seed, size_t seed_len) {
//   PrivateKey k = PopSchemeMPL().KeyGen(Bytes(
//     reinterpret_cast<const uint8_t *>(seed),
//     seed_len
//   ));
//   PrivateKey *pk = new PrivateKey(std::move(k));
//   return pk;
// }

// void *bls_PopSchemeMPL_derive_child_sk(const void *key, int index) {
//   const PrivateKey *master = reinterpret_cast<const PrivateKey *>(key);
//   PrivateKey k = PopSchemeMPL().DeriveChildSk(
//     *master,
//     index
//   );
//   PrivateKey *pk = new PrivateKey(std::move(k));
//   return pk;
// }

// void *bls_PopSchemeMPL_derive_child_sk_unhardened(const void *key, int index) {
//   const PrivateKey *master = reinterpret_cast<const PrivateKey *>(key);
//   PrivateKey k = PopSchemeMPL().DeriveChildSkUnhardened(
//     *master,
//     index
//   );
//   PrivateKey *pk = new PrivateKey(std::move(k));
//   return pk;
// }

// void *bls_PopSchemeMPL_derive_child_pk_unhardened(const void *g1, int index) {
//   const G1Element *master = reinterpret_cast<const G1Element *>(g1);
//   G1Element pk = PopSchemeMPL().DeriveChildPkUnhardened(
//     *master,
//     index
//   );
//   G1Element *ppk = new G1Element(pk);
//   return ppk;
// }

// void *bls_PopSchemeMPL_aggregate(const void **g2s, size_t cnt) {
//   const G2Element **sigs = reinterpret_cast<const G2Element **>(g2s);
//   std::vector<G2Element> vsigs;
//   vsigs.reserve(cnt);
//   for(size_t i = 0; i < cnt; ++i)
//     vsigs.emplace_back(*sigs[i]);
//   G2Element aggregated = PopSchemeMPL().Aggregate(vsigs);
//   return new G2Element(aggregated);
// }

// void *bls_PopSchemeMPL_sign(const void *key, const char *msg, size_t len) {
//   const PrivateKey *k = reinterpret_cast<const PrivateKey *>(key);
//   G2Element sig = PopSchemeMPL().Sign(*k, Bytes(
//     reinterpret_cast<const uint8_t *>(msg),
//     len
//   ));
//   return new G2Element(sig);
// }

// int bls_PopSchemeMPL_verify(const void *g1, const char *msg, size_t len, const void *g2) {
//   const G1Element *pk = reinterpret_cast<const G1Element *>(g1);
//   const G2Element *sig = reinterpret_cast<const G2Element *>(g2);
//   return PopSchemeMPL().Verify(*pk, Bytes(
//     reinterpret_cast<const uint8_t *>(msg),
//     len
//   ), *sig) ? 1 : 0;
// }

// int bls_PopSchemeMPL_aggregate_verify(
//   size_t cnt,
//   const void **g1s,
//   const char **msgs,
//   size_t *lens,
//   const void *g2
// ) {
//   std::vector<G1Element> pubkeys;
//   std::vector<Bytes> vmsgs;
//   pubkeys.reserve(cnt);
//   vmsgs.reserve(cnt);

//   for(size_t i = 0; i < cnt; ++i) {
//     pubkeys.emplace_back(*(reinterpret_cast<const G1Element **>(g1s)[i]));
//     vmsgs.emplace_back(Bytes(
//       reinterpret_cast<const uint8_t *>(msgs[i]),
//       lens[i]
//     ));
//   }

//   const G2Element *sig = reinterpret_cast<const G2Element *>(g2);

//   return PopSchemeMPL().AggregateVerify(pubkeys, vmsgs, *sig) ? 1 : 0;
// }

char *bls_PopSchemeMPL_pop_prove(const char *sk_bytes, unsigned char **buffer, int *buf_len)
{
  try
  {
    PrivateKey sk = PrivateKey::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sk_bytes), PrivateKey::PRIVATE_KEY_SIZE));
    G2Element sig = PopSchemeMPL().PopProve(sk);
    vector<uint8_t> out = sig.Serialize();
    *buf_len = out.size();
    *buffer = (uint8_t *)malloc(*buf_len);
    memcpy(*buffer, out.data(), *buf_len);
    return NULL;
  }
  catch(const std::exception& e)
  {
    char *err = (char *)malloc(strlen(e.what()));
    strcpy(err, e.what());
    return err;
  }
}

char *bls_PopSchemeMPL_pop_verify(const char *pk_bytes, const char *sig_bytes, int *ok) 
{
  try
  {
    G1Element pk = G1Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(pk_bytes), G1Element::SIZE));
    G2Element sig = G2Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sig_bytes), G2Element::SIZE));
    
    *ok = PopSchemeMPL().PopVerify(pk, sig) ? 1 : 0;
    return NULL;
  }
  catch(const std::exception& e)
  {
    char *err = (char *)malloc(strlen(e.what()));
    strcpy(err, e.what());
    return err;
  }
}

char *bls_PopSchemeMPL_fast_aggregate_verify(
  const char **pk_bytes_arr,
  size_t pk_bytes_arr_len,
  const char *msg,
  size_t msg_len,
  const char *sig_bytes,
  int *ok
)
{
  try
  {
    std::vector<G1Element> pubkeys;
    pubkeys.reserve(pk_bytes_arr_len);

    for(size_t i = 0; i < pk_bytes_arr_len; ++i) {
      G1Element pk = G1Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(pk_bytes_arr[i]), G1Element::SIZE));
      pubkeys.emplace_back(pk);
    }
    G2Element sig = G2Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(sig_bytes), G2Element::SIZE));

    *ok = PopSchemeMPL().FastAggregateVerify(
      pubkeys, 
      Bytes(
        reinterpret_cast<const uint8_t *>(msg),
        msg_len
      ), 
      sig
    ) ? 1 : 0;

    return NULL;
  }
  catch(const std::exception& e)
  {
    char *err = (char *)malloc(strlen(e.what()));
    strcpy(err, e.what());
    return err;
  }
}

size_t bls_G1Element_SIZE() {
  return G1Element::SIZE;
}

void bls_G1Element(unsigned char **buffer, int *len) {
  G1Element *g1 = new G1Element();
  vector<uint8_t> out = g1->Serialize();
  *len = out.size();
  *buffer = (uint8_t *)malloc(*len);
  memcpy(*buffer, out.data(), *len);

  delete g1;
}

void bls_G1Element_generator(unsigned char **buffer, int *len) {
  G1Element *g1 = new G1Element(G1Element::Generator());
  vector<uint8_t> out = g1->Serialize();
  *len = out.size();
  *buffer = (uint8_t *)malloc(*len);
  memcpy(*buffer, out.data(), *len);

  delete g1;
}

void *bls_G1Element_from_bytes(const char *bytes, const size_t size, char **err) {
  try
  {
    if (size != G1Element::SIZE) {
      throw std::invalid_argument("Length of bytes object not equal to G1Element size");
    }
    G1Element g1 = G1Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(bytes), G1Element::SIZE));
    G1Element *pg1 = new G1Element(std::move(g1));
    return pg1;
  }
  catch(const std::exception& e)
  {
    *err = (char *)malloc(strlen(e.what()));
    strcpy(*err, e.what());
    return NULL;
  }
}

void bls_G1Element_to_bytes(const void *g1, unsigned char **buffer, int *len) {
  const G1Element *pg1= reinterpret_cast<const G1Element *>(g1);
  vector<uint8_t> out = pg1->Serialize();
  *len = out.size();
  *buffer = (uint8_t *)malloc(*len);
  memcpy(*buffer, out.data(), *len);

  delete pg1;
}

void *bls_G1Element_from_message(const char *msg, size_t msg_len, const char *dst, size_t dst_len) {
  G1Element g1 = G1Element::FromMessage(
    Bytes(
      reinterpret_cast<const uint8_t *>(msg),
      msg_len
    ),
    reinterpret_cast<const uint8_t *>(dst),
    dst_len
  );
  return new G1Element(g1);
}

void *bls_G1Element_negate(const void *g1) {
  const G1Element *pg1= reinterpret_cast<const G1Element *>(g1);
  return new G1Element(pg1->Negate());
}

uint32_t bls_G1Element_get_fingerprint(const void *g1) {
  const G1Element *pg1= reinterpret_cast<const G1Element *>(g1);
  return pg1->GetFingerprint();
}

int bls_G1Element_cmp_eq(const void *a, const void *b) {
  const G1Element *pa = reinterpret_cast<const G1Element *>(a);
  const G1Element *pb = reinterpret_cast<const G1Element *>(b);
  return *pa == *pb ? 1 : 0;
}

int bls_G1Element_cmp_ne(const void *a, const void *b) {
  const G1Element *pa = reinterpret_cast<const G1Element *>(a);
  const G1Element *pb = reinterpret_cast<const G1Element *>(b);
  return *pa != *pb ? 1 : 0;
}

void *bls_G1Element_copy(const void *g1) {
  const G1Element *pg1= reinterpret_cast<const G1Element *>(g1);
  return new G1Element(*pg1);
}

// void *bls_G1Element_add(const void *a, const void *b) {
//   const G1Element *pa = reinterpret_cast<const G1Element *>(a);
//   const G1Element *pb = reinterpret_cast<const G1Element *>(b);
//   return new G1Element(*pa + *pb);
// }
char *bls_G1Element_add(const char *e1_bytes, const char *e2_bytes, unsigned char **buffer, int *len) 
{
  try
  {
    G1Element e1 = G1Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(e1_bytes), G1Element::SIZE));
    G1Element e2 = G1Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(e2_bytes), G1Element::SIZE));

    G1Element added = e1 + e2;
    vector<uint8_t> out = added.Serialize();
    *len = out.size();
    *buffer = (uint8_t *)malloc(*len);
    memcpy(*buffer, out.data(), *len);

    return NULL;
  }
  catch(const std::exception& e)
  {
    char *err = (char *)malloc(strlen(e.what()));
    strcpy(err, e.what());
    return err;
  }
}

void bls_G1Element_free(void *g1) {
  const G1Element *pg1= reinterpret_cast<const G1Element *>(g1);
  delete pg1;
}

size_t bls_G2Element_SIZE() {
  return G2Element::SIZE;
}

void bls_G2Element(unsigned char **buffer, int *len) {
  G2Element *g2 = new G2Element();
  vector<uint8_t> out = g2->Serialize();
  *len = out.size();
  *buffer = (uint8_t *)malloc(*len);
  memcpy(*buffer, out.data(), *len);

  delete g2;
}

void bls_G2Element_generator(unsigned char **buffer, int *len) {
  G2Element *g2 = new G2Element(G2Element::Generator());
  vector<uint8_t> out = g2->Serialize();
  *len = out.size();
  *buffer = (uint8_t *)malloc(*len);
  memcpy(*buffer, out.data(), *len);

  delete g2;
}

void *bls_G2Element_from_bytes(const char *bytes, const size_t size, char **err) {
  try
  {
    if (size != G2Element::SIZE) {
      throw std::invalid_argument("Length of bytes object not equal to G2Element size");
    }
    G2Element g2 = G2Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(bytes), G2Element::SIZE));
    G2Element *pg2 = new G2Element(std::move(g2));
    return pg2;
  }
  catch(const std::exception& e)
  {
    *err = (char *)malloc(strlen(e.what()));
    strcpy(*err, e.what());
    return NULL;
  }
}

void bls_G2Element_to_bytes(const void *g2, unsigned char **buffer, int *len) {
  const G2Element *pg2= reinterpret_cast<const G2Element *>(g2);
  vector<uint8_t> out = pg2->Serialize();
  *len = out.size();
  *buffer = (uint8_t *)malloc(*len);
  memcpy(*buffer, out.data(), *len);
}

void *bls_G2Element_from_message(const char *msg, size_t msg_len, const char *dst, size_t dst_len) {
  G2Element g2 = G2Element::FromMessage(
    Bytes(
      reinterpret_cast<const uint8_t *>(msg),
      msg_len
    ),
    reinterpret_cast<const uint8_t *>(dst),
    dst_len
  );
  return new G2Element(g2);
}

void *bls_G2Element_negate(const void *g2) {
  const G2Element *pg2= reinterpret_cast<const G2Element *>(g2);
  return new G2Element(pg2->Negate());
}

int bls_G2Element_cmp_eq(const void *a, const void *b) {
  const G2Element *pa = reinterpret_cast<const G2Element *>(a);
  const G2Element *pb = reinterpret_cast<const G2Element *>(b);
  return *pa == *pb ? 1 : 0;
}

int bls_G2Element_cmp_ne(const void *a, const void *b) {
  const G2Element *pa = reinterpret_cast<const G2Element *>(a);
  const G2Element *pb = reinterpret_cast<const G2Element *>(b);
  return *pa != *pb ? 1 : 0;
}

void *bls_G2Element_copy(const void *g2) {
  const G2Element *pg2= reinterpret_cast<const G2Element *>(g2);
  return new G2Element(*pg2);
}

// void *bls_G2Element_add(const void *a, const void *b) {
//   const G2Element *pa = reinterpret_cast<const G2Element *>(a);
//   const G2Element *pb = reinterpret_cast<const G2Element *>(b);
//   return new G2Element(*pa + *pb);
// }
char *bls_G2Element_add(const char *e1_bytes, const char *e2_bytes, unsigned char **buffer, int *len)
{
 try
  {
    G2Element e1 = G2Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(e1_bytes), G2Element::SIZE));
    G2Element e2 = G2Element::FromBytes(Bytes(reinterpret_cast<const uint8_t *>(e2_bytes), G2Element::SIZE));

    G2Element added = e1 + e2;
    vector<uint8_t> out = added.Serialize();
    *len = out.size();
    *buffer = (uint8_t *)malloc(*len);
    memcpy(*buffer, out.data(), *len);

    return NULL;
  }
  catch(const std::exception& e)
  {
    char *err = (char *)malloc(strlen(e.what()));
    strcpy(err, e.what());
    return err;
  }
}

void bls_G2Element_free(void *g2) {
  const G2Element *pg2= reinterpret_cast<const G2Element *>(g2);
  delete pg2;
}

