#include "CryptoNight.h"

#define MEMORY  CRYPTONIGHT_MEMORY_SIZE

// Calculation engine has been imported from XMRig project

#if defined(__aarch64__) || defined(__arm__)
#define XMRIG_ARM
#if defined(__arm__)
#define XMRIG_ARMv7
#endif
#include "CryptoNight_arm.h"
#endif

#if defined(__x86_64__) || defined(__i686__)
#include <cpuid.h>
#include "CryptoNight_x86.h"
#endif

#if defined(__MACH__) && defined(__x86_64__) && !defined(bit_AES)
#define bit_AES  (1 << 25)
#endif

CryptoNightHashFunction cn_hash;
static void InitializeCryptoNightHash() __attribute__((constructor(102)));

#if !defined(__arm__)
static void cryptonight_av1_aesni(const void* input, size_t size, void* output, struct cryptonight_ctx* context)
{
  cryptonight_hash<0x80000, MEMORY, 0x1ffff0, false>(input, size, output, context);
}
#endif

static void cryptonight_av3_softaes(const void* input, size_t size, void* output, cryptonight_ctx* context)
{
  cryptonight_hash<0x80000, MEMORY, 0x1ffff0, true>(input, size, output, context);
}

static void InitializeCryptoNightHash()
{
#if defined(__arm__)
  cn_hash = cryptonight_av3_softaes; 
#endif
#if defined(__aarch64__)
  cn_hash = cryptonight_av1_aesni; 
#endif
#if defined(__x86_64__) || defined(__i686__)
  unsigned int features[2];
  unsigned int temporary[2];

  // Check CPU features run-time
  // https://en.wikipedia.org/wiki/CPUID#EAX.3D1:_Processor_Info_and_Feature_Bits
  __get_cpuid(0x01, temporary + 0, temporary + 0, features + 1, features + 0);

  if (features[1] & bit_AES)
  {
    cn_hash = cryptonight_av1_aesni;
    return;
  }

  cn_hash = cryptonight_av3_softaes;

#endif
}

struct cryptonight_ctx* create_cn_ctx()
{
  struct cryptonight_ctx* context = (struct cryptonight_ctx*)_mm_malloc(sizeof(struct cryptonight_ctx), 16);
  context->memory = (uint8_t *)_mm_malloc(MEMORY, 16);
  return context;
}

void free_cn_ctx(struct cryptonight_ctx* context)
{
  _mm_free(context->memory);
  _mm_free(context);
}

scratchpad_memory::scratchpad_memory()
{
  context = create_cn_ctx();
}

scratchpad_memory::~scratchpad_memory()
{
  free_cn_ctx(context);
}

void scratchpad_memory::hash(const void* input, size_t size, void* output)
{
  cn_hash(input, size, output, context);
}
