#include "prover.h"
#include "src/prover_disk.hpp"
#include "src/plotter_disk.hpp"
#include "src/verifier.hpp"

#include <stdlib.h>
#include <stdio.h>

// void print_bytes(char *name, const unsigned char * bytes, size_t num_bytes) {
//   printf("%*s = [ ", 15, name);
//   for (size_t i = 0; i < num_bytes; i++) {
//     printf("%*u ", 3, bytes[i]);
//   }
//   printf("]\n");
// }

// =================DiskPlotter=================

void *NewDiskPlotter(char **err) {
    try
    {
        return new DiskPlotter();
    }
    catch(const std::exception& e)
    {
        *err = (char *)malloc(strlen(e.what()));
        strcpy(*err, e.what());
    }
    return NULL;
}

char *CreatePlotDisk(
    const void *dp, 
    const char *tmp_dir,
    const char *tmp2_dir,
    const char *final_dir,
    const char *filename,
    uint8_t k,
    const unsigned char *memo,
    uint32_t memo_len,
    const unsigned char *id,
    uint32_t id_len,
    uint32_t buffmegabytes,
    uint32_t num_buckets,
    uint32_t stripe_size,
    uint8_t num_threads,
    uint8_t nobitfield
) 
{
    DiskPlotter *plotter = static_cast<DiskPlotter *>(const_cast<void *>(dp));
    const uint8_t *memo_ptr = reinterpret_cast<const uint8_t *>(memo);
    const uint8_t *id_ptr = reinterpret_cast<const uint8_t *>(id);

    std::string tmp_dir_str(tmp_dir);
    std::string tmp2_dir_str(tmp2_dir);
    std::string final_dir_str(final_dir);
    std::string filename_str(filename);
    try
    {
        plotter->CreatePlotDisk(tmp_dir_str,
                            tmp2_dir_str,
                            final_dir_str,
                            filename_str,
                            k,
                            memo_ptr,
                            memo_len,
                            id_ptr,
                            id_len,
                            buffmegabytes,
                            num_buckets,
                            stripe_size,
                            num_threads,
                            nobitfield > 0);
        return NULL;
    }
    catch(const std::exception& e)
    {
        char *err = (char *)malloc(strlen(e.what()));
        strcpy(err, e.what());
        return err;
    }
}

void DeleteDiskPlotter(void *dp) {
    if (dp != NULL) {
        delete static_cast<DiskPlotter *>(dp);
    }
}

// =================DiskProver=================

void *NewDiskProver(const char *filename, char **err) 
{
    try
    {
        return new DiskProver(filename);
    }
    catch(const std::exception& e)
    {
        *err = (char *)malloc(strlen(e.what()));
        strcpy(*err, e.what());
    }
    return NULL;
}

void GetMemo(const void *dp, unsigned char **out, int *len) 
{ 
    DiskProver *prover = static_cast<DiskProver *>(const_cast<void *>(dp));
    *len = prover->GetMemoSize();
    uint8_t *memo = (uint8_t *)malloc(*len);
    prover->GetMemo(memo);
    *out = memo;
}

void GetID(const void *dp, unsigned char **out, int *len) { 
    DiskProver *prover = static_cast<DiskProver *>(const_cast<void *>(dp));
    *len = kIdLen;
    uint8_t *id = (uint8_t *)malloc(kIdLen);
    prover->GetId(id);
    *out = id;
}

void GetSize(const void *dp, uint8_t *sz) {
    DiskProver *prover = static_cast<DiskProver *>(const_cast<void *>(dp));
    *sz = prover->GetSize();
}

char *GetQualitiesForChallenge(const void *dp,
    const unsigned char *challenge,
    unsigned char **out,
    int *len,
    int *num
) {
    try
    {
        DiskProver *prover = static_cast<DiskProver *>(const_cast<void *>(dp));
        std::vector<LargeBits> qualities = prover->GetQualitiesForChallenge(reinterpret_cast<const uint8_t *>(challenge));

        *num = qualities.size();
        *len = 32*(*num);
        uint8_t *buf = (uint8_t *)malloc(*len);
        memset(buf, 0, *len);
        for(int i = 0; i < *num; ++i) {
            qualities[i].ToBytes(&buf[i*32]);
        }
        *out = buf;
        return NULL;
    }
    catch(const std::exception& e)
    {
        char *err = (char *)malloc(strlen(e.what()));
        strcpy(err, e.what());
        return err;
    }
}

void GetFullProof(const void *dp, 
    const unsigned char *challenge, 
    uint32_t index, 
    unsigned char **out, 
    int *len,
    char **err
) {
    DiskProver *prover = static_cast<DiskProver *>(const_cast<void *>(dp));

    try
    {
        LargeBits proof = prover->GetFullProof(reinterpret_cast<const uint8_t *>(challenge), index);
        *len = Util::ByteAlign(64 * prover->GetSize()) / 8;
        uint8_t *proof_buf = (uint8_t *)malloc(*len);
        memset(proof_buf, 0, *len);
        proof.ToBytes(proof_buf);
        *out = proof_buf;
    }
    catch(const std::exception& e)
    {
        *err = (char *)malloc(strlen(e.what()));
        strcpy(*err, e.what());
    }
}

void DeleteDiskProver(void *dp) {
    if (dp != NULL) {
        delete static_cast<DiskProver *>(dp);
    }
}

/*********verifier***********/
void *NewVerifier(){
    return new Verifier();
}

void ValidateProof(const void *vf, uint8_t k,
    const unsigned char *seed,
    const unsigned char *challenge,
    const unsigned char *proof, size_t plen, 
    unsigned char **out,
    int *len,
    char **err
) {
    Verifier *verifier = static_cast<Verifier *>(const_cast<void *>(vf));

    try
    {
        LargeBits quality = verifier->ValidateProof(
            reinterpret_cast<const uint8_t *>(seed), 
            k, 
            reinterpret_cast<const uint8_t *>(challenge), 
            reinterpret_cast<const uint8_t *>(proof), 
            plen
        );
        if (quality.GetSize() != 0) {
            uint8_t *quality_buf = (uint8_t *)malloc(32);
            quality.ToBytes(quality_buf);
            *out = quality_buf;
            *len = 32;
            // printf("ValidateProof malloc pointer %lu\n", (uintptr_t)quality_buf);
        }
    }
    catch(const std::exception& e)
    {
        *err = (char *)malloc(strlen(e.what()));
        strcpy(*err, e.what());
    }
}

void FreeForWin(void *p)
{
    if (p != NULL) {
        // printf("ValidateProof free pointer %lu\n", (uintptr_t)p);
        free(p);
    }
}

void DeleteVerifier(void *v) 
{
    if (v != NULL) {
        delete static_cast<Verifier *>(v);
    }
}
