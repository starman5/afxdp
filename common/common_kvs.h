#pragma once

#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include "common_utils.h"

constexpr int kHashSize = 40000000;
constexpr int kValSize = 40;

struct kvs_entry {
  uint64_t key;
  uint8_t val[kValSize];
  uint32_t ver;
  kvs_entry *next;
};

struct kvs {
  kvs_entry *bucket_heads[kHashSize];
  volatile int locks[kHashSize];
};

static inline void kvs_init(kvs *kvs) {
  memset(kvs->bucket_heads, 0, sizeof(kvs->bucket_heads));
  for (int i = 0; i < kHashSize; i++) kvs->locks[i] = 0;
}

static inline int kvs_hash(uint64_t key) {
  return (int)(fasthash64(&key, sizeof(key), 0xdeadbeef) % (uint64_t)kHashSize);
}

static inline int kvs_get(kvs *kvs, uint64_t key, uint8_t *val, uint32_t *ver) {
  uint32_t hash = kvs_hash(key);
  while (__sync_lock_test_and_set(&kvs->locks[hash], 1));

  kvs_entry *head = kvs->bucket_heads[hash];
  while (head) {
    if (head->key == key) {
      memcpy(val, head->val, kValSize);
      *ver = head->ver;
      __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
      return 0;
    }
    head = head->next;
  }
  __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
  return 1;
}

static inline int kvs_set(kvs *kvs, uint64_t key, uint8_t *val) {
  uint32_t hash = kvs_hash(key);
  while (__sync_lock_test_and_set(&kvs->locks[hash], 1));

  kvs_entry *head = kvs->bucket_heads[hash];
  while (head) {
    if (head->key == key) {
      memcpy(head->val, val, kValSize);
      head->ver++;
      __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
      return 0;
    }
    head = head->next;
  }
  __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
  return 1;
}

static inline void kvs_insert(kvs *kvs, uint64_t key, uint8_t *val) {
  uint32_t hash = kvs_hash(key);
  while (__sync_lock_test_and_set(&kvs->locks[hash], 1));

  kvs_entry *e = new kvs_entry;
  e->key = key;
  memcpy(e->val, val, kValSize);
  e->ver = 0;
  e->next = kvs->bucket_heads[hash];
  kvs->bucket_heads[hash] = e;
  __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
}

static inline void kvs_delete(kvs *kvs, uint64_t key) {
  uint32_t hash = kvs_hash(key);
  while (__sync_lock_test_and_set(&kvs->locks[hash], 1));

  kvs_entry *head = kvs->bucket_heads[hash], *prev = nullptr;
  while (head) {
    if (head->key == key) {
      if (prev) {
        prev->next = head->next;
      } else {
        kvs->bucket_heads[hash] = head->next;
      }
      delete head;
      __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
      return;
    }
    prev = head;
    head = head->next;
  }
  panic("kvs_delete: key not found");
}