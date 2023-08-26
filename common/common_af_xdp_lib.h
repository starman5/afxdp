#ifndef AF_XDP_LIB_H
#define AF_XDP_LIB_H

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <getopt.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <locale.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <unistd.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#include "../common/common_libbpf.h"
#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE 64
#define TX_BATCH_SIZE 5
#define INVALID_UMEM_FRAME UINT64_MAX

#define MAX_PACKET_LEN XSK_UMEM__DEFAULT_FRAME_SIZE

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


typedef bool (*ProcessFunction)(uint8_t*);

typedef struct counter {
  uint64_t count;
  char padding[CACHE_LINE_SIZE - sizeof(uint64_t)];
} Counter;

struct threadArgs {
  struct xsk_socket_info* xski;
  int idx;
  HASHTABLE_T hashtable;
  Spinlock* locks;
  ProcessFunction custom_processing;
};

static struct xdp_program* prog;
static int xsk_map_fd;
static bool custom_xsk = false;
static struct config cfg = {
    .ifindex = -1,
};

struct xsk_umem_info {
  struct xsk_ring_prod fq;
  struct xsk_ring_cons cq;
  struct xsk_umem* umem;
  void* buffer;
};
struct stats_record {
  uint64_t timestamp;
  uint64_t rx_packets;
  uint64_t rx_bytes;
  uint64_t tx_packets;
  uint64_t tx_bytes;
};
struct xsk_socket_info {
  struct xsk_ring_cons rx;
  struct xsk_ring_prod tx;
  struct xsk_umem_info* umem;
  struct xsk_socket* xsk;

  uint64_t umem_frame_addr[NUM_FRAMES];
  uint32_t umem_frame_free;

  uint32_t outstanding_tx;

  struct stats_record stats;
  struct stats_record prev_stats;
};

/*
Spinlock and Hashtable
*/

Spinlock* init_spinlocks();

HASHTABLE_T init_hashtable();

uint64_t hash_key(uint64_t key);

void initialize_hashtable(HASHTABLE_T hashtable);

void table_set(HASHTABLE_T hashtable, uint64_t key, char* value, Spinlock* locks);

char* table_get(HASHTABLE_T hashtable, uint64_t key, Spinlock* locks);

void table_delete(HASHTABLE_T hashtable, uint64_t key, Spinlock* locks);

void cleanup_hashtable(HASHTABLE_T hashtable);

/*
AF_XDP logic
*/

int pin_thread_to_core(int core_id);

__u32 xsk_ring_prod__free(struct xsk_ring_prod* r);

struct xsk_umem_info* configure_xsk_umem(void* buffer, uint64_t size);

uint64_t xsk_alloc_umem_frame(struct xsk_socket_info* xsk);

void xsk_free_umem_frame(struct xsk_socket_info* xsk, uint64_t frame);

uint64_t xsk_umem_free_frames(struct xsk_socket_info* xsk);

struct xsk_socket_info* xsk_configure_socket(struct config* cfg,
                                                    struct xsk_umem_info* umem,
                                                    int queue);

void complete_tx(struct xsk_socket_info* xsk);

__sum16 csum16_add(__sum16 csum, __be16 addend);

__sum16 csum16_sub(__sum16 csum, __be16 addend);

void csum_replace2(__sum16* sum, __be16 old, __be16 new);

uint16_t compute_ip_checksum(struct iphdr* ip);

bool process_packet(struct xsk_socket_info* xsk, uint64_t addr,
                           uint32_t len, struct threadArgs* th_args);

void handle_receive_packets(struct threadArgs* th_args);

void rx_and_process(void* args);

void start_afxdp(int num_sockets, ProcessFunction custom_processing, Spinlock* locks, HASHTABLE_T hashtable);

#endif