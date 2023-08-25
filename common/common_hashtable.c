#include "../common/common_hashtable.h"

// Initialize a spinlock for each bucket, for minimal lock contention
// Return array of spinlocks
Spinlock* init_spinlocks() {
  void* rawPtr_Spinlock;
  if (posix_memalign(&rawPtr_Spinlock, CACHE_LINE_SIZE,
                     TABLE_SIZE * sizeof(Spinlock)) != 0) {
    perror("posix_memalign error\n");
    exit(EXIT_FAILURE);
  }
  Spinlock* locks = (Spinlock*)rawPtr_Spinlock;

  for (int i = 0; i < TABLE_SIZE; ++i) {
    pthread_spin_init(&locks[i].lock, PTHREAD_PROCESS_PRIVATE);
  }

  return locks;
}

// Create, initialize and return hashtable
HASHTABLE_T init_hashtable() {
  HASHTABLE_T hashtable = (HASHTABLE_T)malloc(TABLE_SIZE * sizeof(Node*));
  for (int i = 0; i < TABLE_SIZE; ++i) {
    hashtable[i] = NULL;
  }
  return hashtable;
}

// Simple hash function for unsigned integers
uint64_t hash_key(uint64_t key) { return key % TABLE_SIZE; }

void cleanup_hashtable(HASHTABLE_T hashtable) {
  for (int i = 0; i < TABLE_SIZE; ++i) {
    Node* head = hashtable[i];
    while (head) {
      Node* tmp = head;
      head = head->next;
      free(tmp->value);
      free(tmp);
    }
  }
}

void table_set(HASHTABLE_T hashtable, uint64_t key, char* value, Spinlock* locks) {
  uint64_t hash = hash_key(key);
  pthread_spin_lock(&locks[hash].lock);
  Node* head = hashtable[hash];

  // Look for key in hashtable
  bool found = false;
  while (head) {
    if (head->key == key) {
      head->value = value;
      found = true;
      break;
    }
    head = head->next;
  }
  if (found) {
    pthread_spin_unlock(&locks[hash].lock);
    return;
  }

  // If we didn't find the key, then add new node to head of linked list in O(1)
  Node* new_node = malloc(sizeof(Node));
  new_node->next = hashtable[hash];
  new_node->key = key;
  new_node->value = value;
  hashtable[hash] = new_node;
  pthread_spin_unlock(&locks[hash].lock);
}

char* table_get(HASHTABLE_T hashtable, uint64_t key, Spinlock* locks) {
  uint64_t hash = hash_key(key);
  pthread_spin_lock(&locks[hash].lock);
  Node* head = hashtable[hash];
  while (head) {
    if (head->key == key) {
      pthread_spin_unlock(&locks[hash].lock);
      return head->value;
    }
    head = head->next;
  }
  pthread_spin_unlock(&locks[hash].lock);
  return NULL;
}

void table_delete(HASHTABLE_T hashtable, uint64_t key, Spinlock* locks) {
  uint64_t hash = hash_key(key);
  pthread_spin_lock(&locks[hash].lock);
  Node* curr = hashtable[hash];
  Node* prev = curr;
  if (!curr) {
    printf("Cannot delete from empty list\n");
  }

  // Delete first node in linked list
  if (curr->key == key) {
    hashtable[hash] = curr->next;
    pthread_spin_unlock(&locks[hash].lock);
    return;
  }

  curr = curr->next;
  while (curr) {
    if (curr->key == key) {
      prev->next = curr->next;
      free(curr);
      pthread_spin_unlock(&locks[hash].lock);
      return;
    }

    curr = curr->next;
    prev = prev->next;
  }
  pthread_spin_unlock(&locks[hash].lock);
}