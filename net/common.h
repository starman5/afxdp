#pragma once

#include <random>

#define VALUE_SIZE 64

inline int IntRand(const int &min, const int &max) {  // return [min, max)
  static thread_local std::mt19937 generator(std::random_device{}());
  // Do not use "static thread_local" for distribution object, as this will
  // corrupt objects with different min/max values. Note that this object is
  // extremely cheap.
  std::uniform_int_distribution<int> distribution(min, max);
  return distribution(generator);
}

// Serialize message into format recognized by the server
inline int serialize(int8_t comm, uint32_t key, int val_len, char *buffer) {
  int pos = 0;

  memcpy(buffer, (void *)&comm, 1);
  pos += 1;

  memcpy(buffer + pos, (void *)&key, 4);
  pos += 4;

  pos += val_len;
  pos += 4;  // a version number

  return pos;
}
