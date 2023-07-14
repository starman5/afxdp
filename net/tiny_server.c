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

#define MAX_BUFFER_SIZE 1024
#define SERVER_PORT 8889
#define NUM_CORES   1
#define TABLE_SIZE  10000
#define CACHE_LINE_SIZE 64
#define INTERFACE_IP    "192.168.6.1"

int main() {
    
}