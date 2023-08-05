#pragma once

#include <random>

inline int IntRand(const int &min, const int &max) { // return [min, max)
  static thread_local std::mt19937 generator(std::random_device{}());
  // Do not use "static thread_local" for distribution object, as this will
  // corrupt objects with different min/max values. Note that this object is
  // extremely cheap.
  std::uniform_int_distribution<int> distribution(min, max);
  return distribution(generator);
}

// Serialize message into format recognized by the server
inline int serialize(uint64_t comm, uint64_t key, int val_len, char* buffer) {
  int pos = 0;
  memcpy(buffer, (void*)&comm, 8);
  pos += 8;

  memcpy(buffer + pos, (void*)&key, 8);
  pos += 8;

  pos += val_len;

  return pos;
}
