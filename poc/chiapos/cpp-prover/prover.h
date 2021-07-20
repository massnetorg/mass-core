#ifndef _GO_DISKPROVER_H_
#define _GO_DISKPROVER_H_

#if defined(_MSC_VER)
#define EXPORT  __declspec(dllexport)
#elif BUILDING_DLL
#define EXPORT __attribute__((__visibility__("default")))
#else
#define EXPORT
#endif

#ifdef __cplusplus
extern "C"{
#endif

#include <stdlib.h>
#include <stdint.h>

// DiskPlotter
EXPORT void *NewDiskPlotter(char **err);
EXPORT char *CreatePlotDisk(
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
);
EXPORT void DeleteDiskPlotter(void *dp);

// disk prover
EXPORT void *NewDiskProver(const char *filename, char **err);
EXPORT void GetMemo(const void *dp, unsigned char **out, int *len);
EXPORT void GetID(const void *dp, unsigned char **out, int *len);
EXPORT void GetSize(const void *dp, uint8_t *sz);
EXPORT char *GetQualitiesForChallenge(const void *dp,
        const unsigned char *challenge,
        unsigned char **out,
        int *len,
        int *num);
EXPORT void GetFullProof(const void *dp,
        const unsigned char *challenge, 
        uint32_t index, 
        unsigned char **out, 
        int *len,
        char **err);
EXPORT void DeleteDiskProver(void *dp);

// verifier
EXPORT void *NewVerifier();
EXPORT void ValidateProof(const void *vf, uint8_t k,
        const unsigned char *seed,
        const unsigned char *challenge,
        const unsigned char *proof, size_t plen, 
        unsigned char **out,
        int *len,
        char **err);
EXPORT void DeleteVerifier(void *dp);

// for chiapos_cgo.dll, which built by MSVC
EXPORT void FreeForWin(void *p);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _GO_DISKPROVER_H_