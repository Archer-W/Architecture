/*!
 \file hash.h
 Describes hash functions used in this project.
 */

#pragma once
#include <functional>
#include <type_traits>
#include <inttypes.h>

//! \brief A hash function that hashes keyType to uint32_t. When SSE4.2 support is found, use sse4.2 instructions, otherwise use default hash function  std::hash.
template<class keyType>
class Hasher32 {
public:
  uint32_t mask; //!< a bitmask for the return value. return value must be within [0..mask]
  uint32_t s;    //!< hash s.

public:
  Hasher32()
      : mask(-1), s(0xe2211) {
  }

  Hasher32(uint32_t _mask, uint32_t _s)
      : mask(_mask), s(_s) {
  }

  //! set bitmask and s
  void setMaskSeed(uint32_t _mask, uint32_t _s) {
    mask = _mask;
    s = _s;
  }

  template<class T = keyType>
  uint32_t operator()(const keyType &k0) const {
    uint64_t crc = 0xFFFFFFFFULL;
    uint64_t *k = (uint64_t *) &k0;
    uint32_t s1 = s;

    if (sizeof(keyType) >= 8) {
      asm("crc32q %2,%0" :"=r"(crc) :"0"(crc), "r" ((*k++) + s1));
//      s1 = ((((uint64_t) s1) * s1 >> 16) ^ (s1 << 2));
    }

    if (sizeof(keyType) >= 16) {
      asm("crc32q %2,%0" :"=r"(crc) :"0"(crc), "r" ((*k++) + s1));
//      s1 = ((((uint64_t) s1) * s1 >> 16) ^ (s1 << 2));
    }

    if (sizeof(keyType) >= 24) {
      asm("crc32q %2,%0" :"=r"(crc) :"0"(crc), "r" ((*k++) + s1));
//      s1 = ((((uint64_t) s1) * s1 >> 16) ^ (s1 << 2));
    }

    if (sizeof(keyType) >= 32) {
      asm("crc32q %2,%0" :"=r"(crc) :"0"(crc), "r" ((*k++) + s1));
//      s1 = ((((uint64_t) s1) * s1 >> 16) ^ (s1 << 2));
    }

    if (sizeof(keyType) >= 40) {
      asm("crc32q %2,%0" :"=r"(crc) :"0"(crc), "r" ((*k++) + s1));
//      s1 = ((((uint64_t) s1) * s1 >> 16) ^ (s1 << 2));
    }

    if (sizeof(keyType) >= 48) {
      asm("crc32q %2,%0" :"=r"(crc) :"0"(crc), "r" ((*k++) + s1));
//      s1 = ((((uint64_t) s1) * s1 >> 16) ^ (s1 << 2));
    }

    if (sizeof(keyType) & 7) {
      uint64_t padded = *k;  // higher bits to zero
      padded = padded & (((unsigned long long) -1) >> (64 - (sizeof(keyType) & 7) * 8));

      asm("crc32q %2,%0" :"=r"(crc) :"0"(crc), "r" (padded + s1));
    }

    return mask & crc;
  }
};
