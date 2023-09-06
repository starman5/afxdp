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
#define NUM_THREADS   1
#define HASH_SIZE     1000000

static int nr_cpus = 0;

static uint32_t n_wthreads = 0;
static pthread_t tids[MAX_LCORE_NUM];

// the main table
static struct kvs *table;

bool custom_processing(uint8_t* pkt, TABLE_T table, Counter* counter, int th_idx) {
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

  // Treat payload as message
  struct message* msg = (struct message*)payload_data;
  int ret;

  switch (msg->type) {
    case kRead:
      ret = kvs_get(table, msg->key, msg->val, &msg->ver);
      if (ret == 0) msg->type = kGrantRead;
      else msg->type = kNotExist;
      break;

      case kSet:
        ret = kvs_set(table, msg->key, msg->val, &msg->ver);
        if (ret == 0) msg->type = kSetAck;
        else msg->type = kNotExist;
        break;

      default:
        return false;
  }

  // Swap source and destination MAC
  memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
  memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
  memcpy(eth->h_source, tmp_mac, ETH_ALEN);

  // Swap source and destination IP
  tmp_ip = iph->saddr;
  iph->saddr = iph->daddr;
  iph->daddr = tmp_ip;

  // Swap source and destination port
  uint16_t tmp = udph->source;
  udph->source = udph->dest;
  udph->dest = tmp;

  // Causing transmission erros, but why?
  // iph->check = compute_ip_checksum(iph);
  udph->check = 0;

  return true;
}

int main(int argc, char *argv[]) {
  // Process cmd line args, load XDP, load xsks_map
  int init_success = init_afxdp(argc, argv);
  if (init_success != 0) {
    perror("FAIL");
  }

  // Allocate and initialize key value store
  table = calloc(1, sizeof(struct kvs));
  kvs_init(table, HASH_SIZE);


  start_afxdp(NUM_THREADS, custom_processing, table);

  fprintf(stderr, "all workers started\n");
}