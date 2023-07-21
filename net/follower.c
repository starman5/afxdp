/*
UDP client, meant to stress the server, designed to measure latency
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
#define LEADER_IP  "192.168.6.2"

#define SERVER_PORT 8889
#define COMM_PORT   8890
#define MSG_PER_CORE    100000
#define TABLE_SIZE  10000

// Commands to serialize
#define NON     5
#define SET     6
#define GET     7
#define DEL     8
#define END     9

#define BUFFER_SZ  1000 

int NUM_CORES = 0;

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
    if (inet_pton(AF_INET, CLIENT_IP, &source_addr.sin_addr) <= 0) {
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
        struct timespec total_time;
        if (end_time.tv_nsec - start_time.tv_nsec < 0) {
            total_time.tv_sec = end_time.tv_sec - start_time.tv_sec - 1;
            total_time.tv_nsec = 1000000000 + end_time.tv_nsec - start_time.tv_nsec;
        } else {
            total_time.tv_sec = end_time.tv_sec - start_time.tv_sec;
            total_time.tv_nsec = end_time.tv_nsec - start_time.tv_nsec;
        }
        double latency = total_time.tv_sec + ((double)total_time.tv_nsec / 1000000000);
        total_latency += latency;
    }

    double average_latency = total_latency / MSG_PER_CORE;
    printf("%f\n", average_latency);
    close(sockfd);
    pthread_exit(NULL);
}

int main(int argc, char* argv[]) {
    // Process command-line arguments
    if (argc < 2) {
        printf("no command line arguments provided\n");
        return 0;
    }

    NUM_CORES = atoi(argv[1]);

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
    if (inet_pton(AF_INET, CLIENT_IP, &source_addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(EXIT_FAILURE);
    }

    // Bind socket to source_addr
    if (bind(sockfd, (struct sockaddr*)&source_addr, sizeof(source_addr)) < 0) {
        perror("Binding socket failed\n");
        exit(EXIT_FAILURE);
    }

    // Create socket to listen for leader
    int sockfd_leader;
    struct sockaddr_in my_addr;
    struct sockaddr_in l_addr;

    // Create socket
    if ((sockfd_leader = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Configure my address
    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    my_addr.sin_port = htons(COMM_PORT);

    // Bind socket to the specified address and port
    if (bind(sockfd_leader, (struct sockaddr*)&my_addr, sizeof(my_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for START message from leader and respond
    char buffer[BUFFER_SZ];
    printf("Listening for message from Leader\n");
    int bytes_received = recvfrom(sockfd_leader, buffer, BUFFER_SZ - 1, MSG_WAITALL, (struct sockaddr*)&l_addr, &addr_len);
    printf("Received from Leader\n");
    if (bytes_received < 0) {
        perror("Recvfrom failed");
        close(sockfd);
        pthread_exit(NULL);
    }
    printf("Sending back to Leader\n");

    // start timer and send start time of follower to leader
    struct timespec start_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    double start_seconds = start_time.tv_sec + ((double)start_time.tv_nsec / 1000000000);
    char time_buffer[100];
    sprintf(time_buffer, "%f", start_seconds);
    int bytes_sent = sendto(sockfd_leader, time_buffer, strlen(time_buffer), 0, (struct sockaddr*)&l_addr, addr_len);

    pthread_t workers[NUM_CORES];

    // Start worker threads
    for (int i = 0; i < NUM_CORES; ++i) {
        int core = i;
        if (pthread_create(&workers[i], NULL, send_message, (void*)&core) != 0) {
            perror("Thread creation failed");
            exit(EXIT_FAILURE);
        }    
    }

    // Wait for all threads to finish
    for (int i = 0; i < NUM_CORES; ++i) {
        pthread_join(workers[i], NULL);
    }

    // send END message
    uint64_t key = rand();
    memset(buffer, '\0', BUFFER_SZ);
    serialize(END, key, "hello", buffer);
    bytes_sent = sendto(sockfd, buffer, strlen(buffer), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (bytes_sent < 0) {
        perror("Sendto failed");
        exit(EXIT_FAILURE);
    }

    // receive final response
    memset(buffer, '\0', BUFFER_SZ);
    bytes_received = recvfrom(sockfd, buffer, BUFFER_SZ, MSG_WAITALL, (struct sockaddr*)&server_addr, &addr_len);
    char* endptr;
    double total_requests = strtol(buffer, &endptr, 10);
    printf("Processed Requests: %f\n", total_requests);

    // Close socket
    close(sockfd);

    // Only count those out files where the follower finishes before the leader
    printf("Follower Done\n");

    return 0;

    /*
    // end timer
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);

    // Get total time
    struct timespec total_time;
    if (end_time.tv_nsec - start_time.tv_nsec < 0) {
        total_time.tv_sec = end_time.tv_sec - start_time.tv_sec - 1;
        total_time.tv_nsec = 1000000000 + end_time.tv_nsec - start_time.tv_nsec;
    } else {
        total_time.tv_sec = end_time.tv_sec - start_time.tv_sec;
        total_time.tv_nsec = end_time.tv_nsec - start_time.tv_nsec;
    }

    double total_seconds = total_time.tv_sec + ((double)total_time.tv_nsec / 1000000000);
    double throughput = total_requests / total_seconds;
    printf("Throughput: %f\n", throughput);
    printf("Seconds: %f\n", total_seconds);
    */

}
