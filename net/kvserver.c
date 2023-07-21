#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdalign.h>
#include <time.h>
#include <sched.h>

#define MAX_BUFFER_SIZE 64
#define SERVER_PORT 8889
#define NUM_CORES   1
#define TABLE_SIZE  10000
#define CACHE_LINE_SIZE 64

// Commands to integer conversions for serializing messages
#define NON     5
#define SET     6
#define GET     7
#define DEL     8 
#define END     9

typedef struct node {
    uint64_t key;
    char* value;
    struct node* next;
} Node;

// For counting the number of processed requests
// (with padding to prevent false sharing)
typedef struct counter {
    uint64_t count;
    char padding[CACHE_LINE_SIZE - sizeof(uint64_t)];
} Counter;

typedef struct spinlock {
    pthread_spinlock_t lock;
    char padding[CACHE_LINE_SIZE - sizeof(pthread_spinlock_t)];
} Spinlock;

typedef struct threadArgs {
    Node** hashtable;
    Counter* countArr;
    Spinlock* locks;
    int core_id;
} ThreadArgs;

// Convenient wrapper to pin a thread to a core
int pin_thread_to_core(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    return pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

// Simple hash function for unsigned integers
uint64_t hash_key(uint64_t key) {
    return key % TABLE_SIZE;
}

void initialize_hashtable(Node** hashtable) {
    for (int i = 0; i < TABLE_SIZE; ++i) {
        hashtable[i] = NULL;
    }
}

void hashtable_cleanup(Node** hashtable) {
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

void table_set(Node** hashtable, uint64_t key, char* value, Spinlock* locks) {
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
    new_node->next = head;
    new_node->key = key;
    new_node->value = value;
    hashtable[hash] = new_node;
    pthread_spin_unlock(&locks[hash].lock);
}

char* table_get(Node** hashtable, uint64_t key, Spinlock* locks) {
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

void table_delete(Node** hashtable, uint64_t key, Spinlock* locks) {   
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

void* handle_request(void* arg) {
    int sockfd;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(struct sockaddr);   // because addr is cast to sockaddr later

    ThreadArgs* threadArgs = (ThreadArgs*)arg;
    Node** hashtable = threadArgs->hashtable;
    Counter* countArr = threadArgs->countArr;
    Spinlock* locks = threadArgs->locks;
    int core_id = threadArgs->core_id;
    
    // Pin the thread to a core
    if (pin_thread_to_core(core_id) != 0) {
        perror("Could not pin thread to core\n");
        exit(EXIT_FAILURE);
    }

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Enable SO_REUSEPORT option
    int reuse = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY); // Change this to htonl(INADDR_ANY) to listen to other machines
    server_addr.sin_port = htons(SERVER_PORT);

    // Bind socket to the specified address and port
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    printf("Thread listening\n");
    
    char buffer[MAX_BUFFER_SIZE];
    bool received_end = false;
    while (1) {
        // Receive message from the client
        int bytes_received = recvfrom(sockfd, buffer, MAX_BUFFER_SIZE - 1, MSG_WAITALL, (struct sockaddr*)&client_addr, &addr_len);
        if (bytes_received < 0) {
            perror("Recvfrom failed");
            close(sockfd);
            pthread_exit(NULL);
        }

        char* special_message = NULL;
        const char* default_message = "Message received";
        buffer[bytes_received] = '\0';  // Make buffer a null-terminated string
        //printf("Received message from client: %s\n", buffer);

        uint64_t comm = ((int)(buffer[0] - '0'));
        uint64_t key;
        char* value = (char*)malloc(MAX_BUFFER_SIZE - sizeof(comm) - sizeof(key));

        // Get key from serialized message
        int pos = 2;    // Starting position of key in serialized string
        int numbytes = 0;
        while (buffer[pos] != '|') {
            ++numbytes;
            ++pos;
        }
        char keybuf[10];
        memcpy(keybuf, &buffer[2], numbytes);
        keybuf[numbytes] = '\0';
        char* endptr;
        key = strtol(keybuf, &endptr, 10);

        // Get the value
        ++pos;
        strcpy(value, &buffer[pos]);

        // Process message from the client
        switch (comm) {
            case NON:
                break;
            case SET:
                table_set(hashtable, key, value, locks);
                break;

            case GET:
                countArr[core_id].count += 1;
                char* val = table_get(hashtable, key, locks);
                if (val && val[0] == '*') {    // Prevent compiler optimization
                    printf("star\n");
                }
                /*if (val) {
                    //printf("Value at Key %lu is %s\n", key, val);
                } else {
                    //printf("Key not found\n");
                }*/
                break;

            case DEL:
                table_delete(hashtable, key, locks);
                break;

            case END:
                received_end = true;
                uint64_t total_count = 0;
                for (int i = 0; i < NUM_CORES; ++i) {
                    total_count += countArr[i].count;
                    printf("thread %d: %ld\n", i, countArr[i].count); 
                }
                // Get the total number of processed requests and send back to user
                char end_message[15];
                sprintf(end_message, "%ld", total_count);
                special_message = end_message;
                break;

            default:
                special_message = "Command Not Found";
        }
        
        countArr[core_id].count += 1;

        ssize_t bytes_sent;
        if (special_message) {
            bytes_sent = sendto(sockfd, special_message, strlen(special_message), 0, (struct sockaddr*)&client_addr, addr_len);
        } else {
            bytes_sent = sendto(sockfd, default_message, strlen(default_message), 0, (struct sockaddr*)&client_addr, addr_len);
        }
        if (bytes_sent < 0) {
            perror("Sendto failed\n");
            exit(EXIT_FAILURE);
        }

        //if (received_end) {
        //    break;
        //}
    }

    close(sockfd);
    pthread_exit(NULL);
}

int main() {
    // Initialize a count for each thread, to prevent false sharing from a global counter
    void* rawPtr_Count;
    if (posix_memalign(&rawPtr_Count, CACHE_LINE_SIZE, NUM_CORES * sizeof(Counter)) != 0) {
        perror("posix_memalign error\n");
        exit(EXIT_FAILURE);
    }
    Counter* countArr = (Counter*)rawPtr_Count;
    for (int i = 0; i < NUM_CORES; ++i) {
        countArr[i].count = 0;
    }
    
    // Initialize a spinlock for each bucket, for minimal lock contention
    void* rawPtr_Spinlock;
    if (posix_memalign(&rawPtr_Spinlock, CACHE_LINE_SIZE, TABLE_SIZE * sizeof(Spinlock)) != 0) {
        perror("posix_memalign error\n");
        exit(EXIT_FAILURE);
    }
    Spinlock* locks = (Spinlock*)rawPtr_Spinlock;
    for (int i = 0; i < TABLE_SIZE; ++i) {
        pthread_spin_init(&locks[i].lock, PTHREAD_PROCESS_PRIVATE);
    }

    // Initialize the hashtable, which will serve as the in-memory key-value store
    Node** hashtable = (Node**)malloc(TABLE_SIZE * sizeof(Node*));
    initialize_hashtable(hashtable);
    
    // Create worker threads
    ThreadArgs threadArgs[NUM_CORES];
    pthread_t workers[NUM_CORES];
    for (int i = 0; i < NUM_CORES; ++i) {
        threadArgs[i].hashtable = hashtable;
        threadArgs[i].countArr = countArr;
        threadArgs[i].locks = locks;
        threadArgs[i].core_id = i;
        
        if (pthread_create(&workers[i], NULL, handle_request, (void*)&threadArgs[i]) != 0) {
            perror("Thread creation failed");
            exit(EXIT_FAILURE);
        }
    }

    // Wait for worker threads to finish
    for (int i = 0; i < NUM_CORES; ++i) {
        if (pthread_join(workers[i], NULL) != 0) {
            perror("Thread join failed");
            exit(EXIT_FAILURE);
        }
    }

    // Cleanup
    hashtable_cleanup(hashtable);
    for (int i = 0; i < TABLE_SIZE; ++i) {
        pthread_spin_destroy(&locks[i].lock);
    }
    free(countArr);
    free(locks);

    return 0;
}