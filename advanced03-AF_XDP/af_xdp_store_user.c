#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sched.h>
#include <sys/resource.h>
#include <asm-generic/posix_types.h>
#include <linux/if_link.h>
#include <linux/limits.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../common/common_af_xdp_lib.h"

#define BPF_SYSFS_ROOT "/sys/fs/bpf"

static int nr_cpus = 0;

static uint32_t n_wthreads = 0;
static pthread_t tids[MAX_LCORE_NUM];

// the main table
static struct kvs *table;

bool custom_processing(uint8_t* pkt, TABLE_T table, Counter* counter, int th_idx) {
  struct ext_message msg;

  // Parse headers
  uint8_t tmp_mac[ETH_ALEN];
  uint32_t tmp_ip;
  struct ethhdr* eth = (struct ethhdr*)pkt;
  struct iphdr* iph = (struct iphdr*)(eth + 1);
  struct udphdr* udph = NULL;
  if (ntohs(eth->h_proto) != ETH_P_IP) return false;

  // Retrieve payload
  unsigned char* ip_data = (unsigned char*)iph + (iph->ihl << 2);
  udph = (struct udphdr*)ip_data;
  unsigned char* payload_data = ip_data + sizeof(struct udphdr);

  // Fill in ext_message struct

  if (msg.type == READ) {
    if (ret != sizeof(struct ext_message)) panic("recvfrom read failed");
    
    if (msg.ver1 == 1) kvs_set_evict(table, msg.key2, msg.val2, msg.ver2);

    int res = kvs_get(table, msg.key1, msg.val1, &msg.ver1);
    if (res == 0) msg.type = GRANT_READ;
    else msg.type = NOT_EXIST;
  }
    
  else if (msg.type == SET) {
    if (ret != sizeof(struct ext_message)) panic("recvfrom commit failed");
    if (msg.ver1 == 1) kvs_set_evict(table, msg.key2, msg.val2, msg.ver2);

    kvs_set(table, msg.key1, msg.val1, &msg.ver1);
    if (msg.ver1 != 0) msg.type = SET_ACK;
    else msg.type = NOT_EXIST;
  } 
    
  else if (msg.type == INSERT) {
    if (ret != sizeof(struct ext_message)) panic("recvfrom insert failed");
    kvs_insert(table, msg.key1, msg.val1);
    kvs_set_evict(table, msg.key2, msg.val2, msg.ver2);
    msg.type = INSERT_ACK;
  }

  else return false;

  // On function exit, pkt should contain the data you would like to send out

  return true;
}

int main(int argc, char *argv[]) {
  // Process cmd line args, load XDP, load xsks_map
  int init_success = init_afxdp(argc, argv);
  if (init_success != 0) {
    perror("FAIL");
  }

  table = calloc(1, sizeof(struct kvs));
  kvs_init(table);

  nr_cpus = libbpf_num_possible_cpus();
  start_afxdp(nr_cpus, custom_processing, table);

  fprintf(stderr, "all workers started\n");
}