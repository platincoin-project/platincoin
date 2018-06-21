#ifndef CRYPTONIGHT_H
#define CRYPTONIGHT_H

#include <stddef.h>
#include <stdint.h>

#define CRYPTONIGHT_MEMORY_SIZE   2048 * 1024
#define CRYPTONIGHT_HASH_SIZE     32

#ifdef __cplusplus
extern "C"
{
#endif

// Naming of types and functions was inherited from most common CryptoNight implementations

#pragma pack(push, 16)
struct cryptonight_ctx
{
  uint8_t state0[200];
  uint8_t state1[200];
  uint8_t* memory;
};
#pragma pack(pop)

typedef void (*CryptoNightHashFunction)(const void* input, size_t size, void* output, struct cryptonight_ctx* context);

extern CryptoNightHashFunction cn_hash;

struct cryptonight_ctx* create_cn_ctx();
void free_cn_ctx(struct cryptonight_ctx* context);

#ifdef __cplusplus
}

// scratchpad_memory has partial backgward compatibility with outdated implementation of PlatinCoin scraptchpad

class scratchpad_memory
{
  public:

    struct cryptonight_ctx* context;

    scratchpad_memory();
    ~scratchpad_memory();

    void hash(const void* input, size_t size, void* output);
};
#endif

#endif
