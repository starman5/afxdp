/*
Leader client to measure latency.
Leader first makes SET requests to add entries to the key-value store.  Sends messages to followers
telling them begin sending GET requests, and then itself begins sending GET requests
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
#include <stdatomic.h>

// Change these to reflect the actual topology
#define SERVER_IP "192.168.6.1"
#define LEADER_IP   "192.168.6.2"

#define SERVER_PORT 8889
#define COMM_PORT   8890
#define TABLE_SIZE  10000
#define MSG_PER_CORE    100000

// Commands to serialize
#define NON     5
#define SET     6
#define GET     7
#define DEL     8
#define END     9
#define START   10

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

void start_follower(void* ip) {
    const char* ip_addr = (const char*)ip;
    // Set up socket for communication with follower
    int sockfd_follower;
    struct sockaddr_in follower_addr, source_addr;
    socklen_t addr_len = sizeof(follower_addr);

    // Create socket
    if ((sockfd_follower = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Configure follower address
    memset(&follower_addr, 0, sizeof(follower_addr));
    follower_addr.sin_family = AF_INET;
    follower_addr.sin_port = htons(COMM_PORT);     
    if (inet_pton(AF_INET, ip_addr, &follower_addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(EXIT_FAILURE);
    }

    // Configure source address
    memset(&source_addr, 0, sizeof(source_addr));
    source_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, LEADER_IP, &source_addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(EXIT_FAILURE);
    }
    // Bind socket to source_addr
    if (bind(sockfd_follower, (struct sockaddr*)&source_addr, sizeof(source_addr)) < 0) {
        perror("Binding socket failed\n");
        exit(EXIT_FAILURE);
    }

    char buffer[BUFFER_SZ];
    // Send START requests to follower
    uint64_t key = rand();  // Key doesn't matter
    memset(buffer, '\0', BUFFER_SZ);
    serialize(START, key, "hello", buffer);
    printf("Starting Follower\n");
    int bytes_sent = sendto(sockfd_follower, buffer, strlen(buffer), MSG_WAITALL, (struct sockaddr*)&follower_addr, (socklen_t)sizeof(follower_addr));
    if (bytes_sent < 0) {
        perror("Sendto failed");
        exit(EXIT_FAILURE);
    }
    memset(buffer, '\0', BUFFER_SZ);
    printf("Waiting for response from Follower\n");
    int bytes_received = recvfrom(sockfd_follower, buffer, BUFFER_SZ, MSG_WAITALL, (struct sockaddr*)&follower_addr, &addr_len);
    printf("Received response from Follower\n");

    close(sockfd_follower);
}

void *send_message(void* arg) {
    int core_id = *((int*)arg);
    int sockfd;
    struct sockaddr_in server_addr, source_addr;
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

     // Configure source address
    memset(&source_addr, 0, sizeof(source_addr));
    source_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, LEADER_IP, &source_addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(EXIT_FAILURE);
    }

    // Bind socket to source_addr
    if (bind(sockfd, (struct sockaddr*)&source_addr, sizeof(source_addr)) < 0) {
        perror("Binding socket failed\n");
        exit(EXIT_FAILURE);
    }

    // Loop to send many GET messages and receive responses
    double total_latency = 0;
    char buffer[BUFFER_SZ];
    for (int i = 0; i < MSG_PER_CORE; ++i) {
        uint64_t key = rand();  // random key.  This is probably ideal for minimizing hash collisions
        memset(buffer, '\0', BUFFER_SZ);
        serialize(GET, key, "hello", buffer);
        ssize_t bytes_sent; 
        
        // start timer and send message
        struct timespec start_time;
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        bytes_sent = sendto(sockfd, buffer, strlen(buffer), MSG_WAITALL, (struct sockaddr*)&server_addr, (socklen_t)sizeof(server_addr));
        if (bytes_sent < 0) {
            perror("Sendto failed");
            exit(EXIT_FAILURE);
        }

        // receive message back and end timer
        memset(buffer, '\0', BUFFER_SZ);
        int bytes_received = recvfrom(sockfd, buffer, BUFFER_SZ, MSG_WAITALL, (struct sockaddr*)&server_addr, &addr_len);
        struct timespec end_time;
        clock_gettime(CLOCK_MONOTONIC, &end_time);

        // Perform latency calculation
        // Get total time
        /*struct timespec total_time;
        if (end_time.tv_nsec - start_time.tv_nsec < 0) {
            total_time.tv_sec = end_time.tv_sec - start_time.tv_sec - 1;
            total_time.tv_nsec = 1000000000 + end_time.tv_nsec - start_time.tv_nsec;
        } else {
            total_time.tv_sec = end_time.tv_sec - start_time.tv_sec;
            total_time.tv_nsec = end_time.tv_nsec - start_time.tv_nsec;
        }
        double latency = total_time.tv_sec + ((double)total_time.tv_nsec / 1000000000);
        total_latency += latency;*/
    }

    /*double average_latency = total_latency / MSG_PER_CORE;
    printf("%f\n", average_latency);*/
    close(sockfd);
    pthread_exit(NULL);
}

int main(int argc, char* argv[]) {
    // Process command line arguments
    //  NUM_FOLLOWERS
    //  NUM_CORES per FOLLOWER
    //  FOLLOWER_1 IP
    //  ...
    //  FOLLOWER_N IP

    size_t num_followers = atoi(argv[1]);
    size_t num_cores = atoi(argv[2]);
    const char* followers[num_followers];
    for (size_t i = 0; i < num_followers; ++i) {
        followers[i] = argv[3 + i];
    }

    // Set up socket for the main thread
    int sockfd;
    struct sockaddr_in server_addr, source_addr;
    socklen_t addr_len = sizeof(struct sockaddr);

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

    // Configure source address
    memset(&source_addr, 0, sizeof(source_addr));
    source_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, LEADER_IP, &source_addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(EXIT_FAILURE);
    }
    // Bind socket to source_addr
    if (bind(sockfd, (struct sockaddr*)&source_addr, sizeof(source_addr)) < 0) {
        perror("Binding socket failed\n");
        exit(EXIT_FAILURE);
    }

    printf("Filling up Key-Value Store\n");
    // Send SET requests to fill up key-value store
    char buffer[BUFFER_SZ];
    for (int i = 0; i < 10000; ++i) {
        uint64_t key = rand();  // random key.  This is probably ideal for minimizing hash collisions
        memset(buffer, '\0', BUFFER_SZ);
        serialize(SET, key, "hello", buffer);
        ssize_t bytes_sent; 
        bytes_sent = sendto(sockfd, buffer, strlen(buffer), MSG_WAITALL, (struct sockaddr*)&server_addr, (socklen_t)sizeof(server_addr));
        if (bytes_sent < 0) {
            perror("Sendto failed");
            exit(EXIT_FAILURE);
        }
        memset(buffer, '\0', BUFFER_SZ);
        int bytes_received = recvfrom(sockfd, buffer, BUFFER_SZ, MSG_WAITALL, (struct sockaddr*)&server_addr, &addr_len);
    }

    pthread_t follower_threads[num_followers];
    for (size_t i = 0; i < num_followers; ++i) {
        if (pthread_create(&follower_threads[i], NULL, start_follower, (void*)(followers[i])) != 0) {
            perror("Thread creation failed\n");
            exit(EXIT_FAILURE);
        }
    }
    // Wait for all follower_threads to be started
    for (size_t i = 0; i < num_followers; ++i) {
        pthread_join(follower_threads[i], NULL);
    }

    // Now that all followers have been notified to send requests to server, so does the leader
    // start timer
    struct timespec start_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    double start_seconds = start_time.tv_sec + ((double)start_time.tv_nsec / 1000000000);

    pthread_t workers[num_cores];
    // Start worker threads
    for (int i = 0; i < num_cores; ++i) {
        int core = i;
        if (pthread_create(&workers[i], NULL, send_message, (void*)&core) != 0) {
            perror("Thread creation failed");
            exit(EXIT_FAILURE);
        }    
    }

    // Wait for all threads to finish
    for (int i = 0; i < num_cores; ++i) {
        pthread_join(workers[i], NULL);
    }

    // send END message
    uint64_t key = rand();
    //char buffer[BUFFER_SZ];
    memset(buffer, '\0', BUFFER_SZ);
    serialize(END, key, "hello", buffer);
    int bytes_sent = sendto(sockfd, buffer, strlen(buffer), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (bytes_sent < 0) {
        perror("Sendto failed");
        exit(EXIT_FAILURE);
    }

    // receive final response
    char* endptr;
    memset(buffer, '\0', BUFFER_SZ);
    int bytes_received = recvfrom(sockfd, buffer, BUFFER_SZ, MSG_WAITALL, (struct sockaddr*)&server_addr, &addr_len);
    double total_requests = strtol(buffer, &endptr, 10);
    printf("Processed Requests: %f\n", total_requests);

    // Close socket
    close(sockfd);

    // end timer
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double end_seconds = end_time.tv_sec + ((double)end_time.tv_nsec / 1000000000);

    double total_seconds = end_seconds - start_seconds;
    //double total_requests = (NUM_CORES + follower_cores) * MSG_PER_CORE;
    double throughput = total_requests / total_seconds;
    printf("Throughput: %f\n", throughput);
    printf("Seconds: %f\n", total_seconds);
    return 0;
}