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
#define NON 5
#define SET 6
#define GET 7
#define DEL 8
#define END 9

typedef struct node {
  uint64_t key;
  char* value;
  struct node* next;
} Node;


uint64_t hash_key(uint64_t key);

void initialize_hashtable(Node** hashtable);

void hashtable_cleanup(Node** hashtable);

void table_set(Node** hashtable, uint64_t key, char* value, Spinlock* locks);

char* table_get(Node** hashtable, uint64_t key, Spinlock* locks);

void table_delete(Node** hashtable, uint64_t key, Spinlock* locks);

#endif