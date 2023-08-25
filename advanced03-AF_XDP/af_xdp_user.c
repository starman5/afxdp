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
#include "../common/common_af_xdp_lib.h"

#define NUM_SOCKETS 1

#define MAX_PACKET_LEN XSK_UMEM__DEFAULT_FRAME_SIZE

#define NON 5
#define SET 6
#define GET 7
#define DEL 8
#define END 9

#define DONT_OPTIMIZE(var) __asm__ __volatile__("" ::"m"(var));

// These are for counting the number of packets processed
atomic_size_t num_packets = ATOMIC_VAR_INIT(0);
Counter countAr[NUM_THREADS];

// These are for defunct polling logic
atomic_size_t num_ready = ATOMIC_VAR_INIT(0);
size_t num_tx_packets = 0;
struct timespec timeout_start = {0, 0};

// Executed when signal received to stop
static void exit_application(int signal) {
  uint64_t npackets = 0;
  for (int i = 0; i < NUM_THREADS; ++i) {
    printf("thread %d: %d\n", i, countAr[i].count);
    npackets += countAr[i].count;
  }
  printf("total packets: %d\n", npackets);
  int err;

  cfg.unload_all = true;
  err = do_unload(&cfg);
  if (err) {
    fprintf(stderr, "Couldn't detach XDP program on iface '%s' : (%d)\n",
            cfg.ifname, err);
  }

  signal = signal;
  global_exit = true;
}

// Change this function to suit your needs
// This is the custom packet processing logic
bool custom_processing(uint8_t* pkt) {
  int ret;
  uint32_t tx_idx = 0;
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

  // Process request
  char* special_message = NULL;
  const char* default_message = "Message received";

  uint8_t comm = *(uint8_t*)payload_data;
  uint32_t key = *(uint32_t*)&payload_data[1];
  char* value_get = NULL;

  // Process message from the client
  switch (comm) {
    case NON:
      break;

    case SET: {
      char* value = (char*)malloc(VALUE_SIZE);
      // Get the value
      memcpy(value, &payload_data[sizeof(uint8_t) + sizeof(uint32_t)],
             VALUE_SIZE);
      table_set(hashtable, key, value, locks);
      countAr[idx].count += 1;
      break;
    }

    case GET: {
      value_get = table_get(hashtable, key, locks);
#if VALUE_SIZE == 0
      DONT_OPTIMIZE(value_get);
#else
      memcpy(payload_data, value_get, VALUE_SIZE);
#endif
      countAr[idx].count += 1;
      break;
    }

    case DEL: {
      table_delete(hashtable, key, locks);
      break;
    }

    case END: {
      uint64_t total_count = 0;
      for (int i = 0; i < NUM_THREADS; ++i) {
        // @yangzhou, thread-safety issues
        total_count += countAr[i].count;
        printf("thread %d: %ld\n", i, countAr[i].count);
      }
      // Get the total number of processed requests and send back to user
      memcpy(payload_data, (void*)&total_count, sizeof(uint64_t));
      break;
    }

    default: {
      special_message = "Not found";
      memcpy(payload_data, special_message, strlen(special_message));
    }
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

int main(int argc, char** argv) {
  /* Global shutdown handler */
  signal(SIGINT, exit_application);

  /* Cmdline options can change progname */
  parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

  /* Required option */
  if (cfg.ifindex == -1) {
    fprintf(stderr, "ERROR: Required option --dev missing\n\n");
    usage(argv[0], __doc__, long_options, (argc == 1));
    return EXIT_FAIL_OPTION;
  }

  /* Load custom program if configured */
  if (cfg.filename[0] != 0) {
    struct bpf_map* map;

    custom_xsk = true;
    xdp_opts.open_filename = cfg.filename;
    xdp_opts.prog_name = cfg.progname;
    xdp_opts.opts = &opts;

    if (cfg.progname[0] != 0) {
      xdp_opts.open_filename = cfg.filename;
      xdp_opts.prog_name = cfg.progname;
      xdp_opts.opts = &opts;

      prog = xdp_program__create(&xdp_opts);
    } else {
      prog = xdp_program__open_file(cfg.filename, NULL, &opts);
    }
    err = libxdp_get_error(prog);
    if (err) {
      libxdp_strerror(err, errmsg, sizeof(errmsg));
      fprintf(stderr, "ERR: loading program: %s\n", errmsg);
      return err;
    }

    err = xdp_program__attach(prog, cfg.ifindex, cfg.attach_mode, 0);
    if (err) {
      libxdp_strerror(err, errmsg, sizeof(errmsg));
      fprintf(stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
              cfg.ifname, errmsg, err);
      return err;
    }

    /* We also need to load the xsks_map */
    map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "xsks_map");
    xsk_map_fd = bpf_map__fd(map);
    printf("correct xsk_map_fd: %d\n", xsk_map_fd);
    if (xsk_map_fd < 0) {
      fprintf(stderr, "ERROR: no xsks map found: %s\n", strerror(xsk_map_fd));
      exit(EXIT_FAILURE);
    }
  }
  
  // Initialize the spinlocks for the hashtable
  Spinlock* spinlocks = init_spinlocks();

  // Initialize the hashtable, which will serve as the in-memory key-value store
  HASHTABLE_T hashtable = init_hashtable();

  // Initialize global counter array for our own statistics
  for (int i = 0; i < NUM_THREADS; ++i) {
    countAr[i].count = 0;
  }

  // Start NUM_SOCKETS AF_XDP sockets
  start_afxdp(NUM_SOCKETS, custom_processing)

  return EXIT_OK;
}