// key-value store

#ifndef _KVS_H_
#define _KVS_H_

#include <stdlib.h>
#include <string.h>
#include "utils.h"

#define MAX_LOG_ENTRY_NUM 1000000

struct kvs_entry {
  uint64_t key;
  uint8_t val[VAL_SIZE];
  uint32_t ver;
  struct kvs_entry *next;
};

struct kvs {
  struct kvs_entry *bucket_heads[KVS_HASH_SIZE];
  volatile int locks[KVS_HASH_SIZE];
};

static inline void kvs_init(struct kvs *kvs) {
  memset(kvs->bucket_heads, 0, sizeof(kvs->bucket_heads));
  for (int i = 0; i < KVS_HASH_SIZE; i++) kvs->locks[i] = 0;
}

static inline uint32_t kvs_hash(uint64_t key) {
  return (uint32_t)(fasthash64(&key, sizeof(key), 0xdeadbeef) % (uint64_t)KVS_HASH_SIZE);
}

static inline int kvs_get(struct kvs *kvs, uint64_t key, uint8_t *val, uint32_t *ver) {
  uint32_t hash = kvs_hash(key);
  while (__sync_lock_test_and_set(&kvs->locks[hash], 1));

  struct kvs_entry *head = kvs->bucket_heads[hash];
  while (head) {
    if (head->key == key) {
      memcpy(val, head->val, VAL_SIZE);
      *ver = head->ver;
      __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
      return 0;
    }
    head = head->next;
  }
  __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
  return 1; // not found
}

static inline void kvs_insert(struct kvs *kvs, uint64_t key, uint8_t *val) {
  uint32_t hash = kvs_hash(key);
  while (__sync_lock_test_and_set(&kvs->locks[hash], 1));

  struct kvs_entry *e = calloc(1, sizeof(struct kvs_entry));
  e->key = key;
  memcpy(e->val, val, VAL_SIZE);
  e->ver = 0;
  e->next = kvs->bucket_heads[hash];
  kvs->bucket_heads[hash] = e;
  __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
}

static inline uint32_t kvs_set(struct kvs *kvs, uint64_t key, uint8_t *val, uint32_t ver) {
  uint32_t hash = kvs_hash(key);
  while (__sync_lock_test_and_set(&kvs->locks[hash], 1));

  struct kvs_entry *head = kvs->bucket_heads[hash];
  while (head) {
    if (head->key == key) {
      memcpy(head->val, val, VAL_SIZE);
      if (ver != 0) head->ver = ver;
      else head->ver++;
      __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
      return head->ver;
    }
    head = head->next;
  }
  __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
  kvs_insert(kvs, key, val);
  return 0;
}

static inline void kvs_delete(struct kvs *kvs, uint64_t key) {
  uint32_t hash = kvs_hash(key);
  while (__sync_lock_test_and_set(&kvs->locks[hash], 1));

  struct kvs_entry *head = kvs->bucket_heads[hash], *prev = NULL;
  while (head) {
    if (head->key == key) {
      if (prev) {
        prev->next = head->next;
      } else {
        kvs->bucket_heads[hash] = head->next;
      }
      free(head);
      __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
      return;
    }
    prev = head;
    head = head->next;
  }
  __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
  // panic("kvs_delete: key not found");
}

#endif // _KVS_H_