#ifndef COMMON_HASHTABLE
#define COMMON_HASHTABLE

#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <sched.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#define TABLE_SIZE 7000000
#define VALUE_SIZE 64
#define CACHE_LINE_SIZE 64

typedef struct node {
  uint64_t key;
  char* value;
  struct node* next;
} Node;

typedef Node** HASHTABLE_T;

typedef struct spinlock {
  pthread_spinlock_t lock;
  char padding[CACHE_LINE_SIZE - sizeof(pthread_spinlock_t)];
} Spinlock;

Spinlock* init_spinlocks();

HASHTABLE_T init_hashtable()

uint64_t hash_key(uint64_t key);

void initialize_hashtable(HASHTABLE_T hashtable);

void table_set(HASHTABLE_T hashtable, uint64_t key, char* value, Spinlock* locks);

char* table_get(HASHTABLE_T hashtable, uint64_t key, Spinlock* locks);

void table_delete(HASHTABLE_T** hashtable, uint64_t key, Spinlock* locks);

void cleanup_hashtable(HASHTABLE_T hashtable);

#endif