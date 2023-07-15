/*
UDP client, meant to stress the server, designed to measure throughput
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <sched.h>

#define SERVER_IP "192.168.6.1"   // Change this to the ip address of the server
#define SERVER_PORT 8889
#define NUM_CORES 100
#define TABLE_SIZE  10000

// Commands to serialize
#define NON     5
#define SET     6
#define GET     7
#define DEL     8
#define END     9

#define BUFFER_SZ  1000 

// Serialize message into format recognized by the server
void serialize(uint64_t comm, uint64_t key, char* value, char* buffer) {
    int pos = 0;
    int nbytes = sprintf(buffer, "%lu", comm);
    pos += nbytes;
    buffer[pos] = '|';
    ++pos;
    
    nbytes = sprintf(&buffer[pos], "%lu", key);
    pos += nbytes;
    buffer[pos] = '|';
    ++pos;

    strcpy(&buffer[pos], value);
}

void *send_message(void* arg) {
    int sockfd;
    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(server_addr);

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
        
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(EXIT_FAILURE);
    }

    // Loop to send many NON messages and receive responses
    char buffer[BUFFER_SZ];
    for (int i = 0; i < 4000000; ++i) {
        uint64_t key = rand();  // random key.  This is probably ideal for minimizing hash collisions
        memset(buffer, '\0', BUFFER_SZ);
        serialize(NON, key, "hello", buffer);
        ssize_t bytes_sent; 
        bytes_sent = sendto(sockfd, buffer, strlen(buffer), MSG_WAITALL, (struct sockaddr*)&server_addr, (socklen_t)sizeof(server_addr));
        if (bytes_sent < 0) {
            perror("Sendto failed");
            exit(EXIT_FAILURE);
        }

    }

    close(sockfd);
    pthread_exit(NULL);
}

int main() {
    pthread_t workers[NUM_CORES];

    // Start worker threads
    for (int i = 0; i < NUM_CORES; ++i) {
        if (pthread_create(&workers[i], NULL, send_message, NULL) != 0) {
            perror("Thread creation failed");
            exit(EXIT_FAILURE);
        }    
    }

    // Wait for all threads to finish
    for (int i = 0; i < NUM_CORES; ++i) {
        pthread_join(workers[i], NULL);
    }

    return 0;
}