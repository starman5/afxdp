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

#include "af_xdp_lib.h"

#define VALUE_SIZE 64

#define NUM_SOCKETS 1
#define NUM_THREADS NUM_SOCKETS
#define TIMEOUT_NSEC 500000000
#define CACHE_LINE_SIZE 64

#define MAX_PACKET_LEN XSK_UMEM__DEFAULT_FRAME_SIZE
#define MAX_BUFFER_SIZE 1500
#define TABLE_SIZE 7000000

#define NON 5
#define SET 6
#define GET 7
#define DEL 8
#define END 9

#define DONT_OPTIMIZE(var) __asm__ __volatile__("" ::"m"(var));

atomic_size_t num_packets = ATOMIC_VAR_INIT(0);
atomic_size_t num_ready = ATOMIC_VAR_INIT(0);
size_t num_tx_packets = 0;
struct timespec timeout_start = {0, 0};

static struct xdp_program* prog;
int xsk_map_fd;
bool custom_xsk = false;
struct config cfg = {
    .ifindex = -1,
};

typedef struct node {
  uint64_t key;
  char* value;
  struct node* next;
} Node;

typedef struct counter {
  uint64_t count;
  char padding[CACHE_LINE_SIZE - sizeof(uint64_t)];
} Counter;

typedef struct spinlock {
  pthread_spinlock_t lock;
  char padding[CACHE_LINE_SIZE - sizeof(pthread_spinlock_t)];
} Spinlock;

struct threadArgs {
  struct xsk_socket_info* xski;
  int idx;
  Node** hashtable;
  Spinlock* locks;
};

Counter countAr[NUM_THREADS];

// Convenient wrapper to pin a thread to a core
int pin_thread_to_core(int core_id) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);

  return pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

// Simple hash function for unsigned integers
uint64_t hash_key(uint64_t key) { return key % TABLE_SIZE; }

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
  new_node->next = hashtable[hash];
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

static bool process_packet(struct xsk_socket_info* xsk, uint64_t addr,
                           uint32_t len, struct threadArgs* th_args) {
  Node** hashtable = th_args->hashtable;
  int idx = th_args->idx;
  Spinlock* locks = th_args->locks;

  uint8_t* pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

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

  /* Here we sent the packet out of the receive port. Note that
   * we allocate one entry and schedule it. Your design would be
   * faster if you do batch processing/transmission */

  ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
  if (ret != 1) {
    printf("no more transmit slots\n");
    /* No more transmit slots, drop the packet */
    return false;
  }

  xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
  xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;

  //++num_tx_packets;
  // if (num_tx_packets >= TX_BATCH_SIZE) {
  xsk_ring_prod__submit(&xsk->tx, 1);
  xsk->outstanding_tx += 1;
  // num_tx_packets = 0;
  //}

  xsk->stats.tx_bytes += len;
  xsk->stats.tx_packets++;
  return true;
}


#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static uint64_t gettime(void) {
  struct timespec t;
  int res;

  res = clock_gettime(CLOCK_MONOTONIC, &t);
  if (res < 0) {
    fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
    exit(EXIT_FAIL);
  }
  return (uint64_t)t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct stats_record* r, struct stats_record* p) {
  double period_ = 0;
  __u64 period = 0;

  period = r->timestamp - p->timestamp;
  if (period > 0) period_ = ((double)period / NANOSEC_PER_SEC);

  return period_;
}

static void stats_print(struct stats_record* stats_rec,
                        struct stats_record* stats_prev) {
  uint64_t packets, bytes;
  double period;
  double pps; /* packets per sec */
  double bps; /* bits per sec */

  char* fmt =
      "%-12s %'11lld pkts (%'10.0f pps)"
      " %'11lld Kbytes (%'6.0f Mbits/s)"
      " period:%f\n";

  period = calc_period(stats_rec, stats_prev);
  if (period == 0) period = 1;

  packets = stats_rec->rx_packets - stats_prev->rx_packets;
  pps = packets / period;

  bytes = stats_rec->rx_bytes - stats_prev->rx_bytes;
  bps = (bytes * 8) / period / 1000000;

  printf(fmt, "AF_XDP RX:", stats_rec->rx_packets, pps,
         stats_rec->rx_bytes / 1000, bps, period);

  packets = stats_rec->tx_packets - stats_prev->tx_packets;
  pps = packets / period;

  bytes = stats_rec->tx_bytes - stats_prev->tx_bytes;
  bps = (bytes * 8) / period / 1000000;

  printf(fmt, "       TX:", stats_rec->tx_packets, pps,
         stats_rec->tx_bytes / 1000, bps, period);

  printf("\n");
}

static void* stats_poll(void* arg) {
  unsigned int interval = 2;
  struct xsk_socket_info* xsk = arg;
  static struct stats_record previous_stats = {0};

  previous_stats.timestamp = gettime();

  /* Trick to pretty printf with thousands separators use %' */
  setlocale(LC_NUMERIC, "en_US");

  while (!global_exit) {
    sleep(interval);
    xsk->stats.timestamp = gettime();
    stats_print(&xsk->stats, &previous_stats);
    previous_stats = xsk->stats;
  }
  return NULL;
}

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

int main(int argc, char** argv) {
  int ret;
  void* packet_buffers[NUM_SOCKETS];
  uint64_t packet_buffer_size;
  DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
  DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
  struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
  struct xsk_umem_info* umems[NUM_SOCKETS];
  struct xsk_socket_info* xsk_sockets[NUM_SOCKETS];
  pthread_t stats_poll_thread;
  int err;
  char errmsg[1024];

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

  /* Allow unlimited locking of memory, so all memory needed for packet
   * buffers can be locked.
   */
  if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
    fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* Allocate memory for NUM_FRAMES of the default XDP frame size */
  packet_buffer_size = NUM_FRAMES * FRAME_SIZE;

  for (int sockidx = 0; sockidx < NUM_SOCKETS; ++sockidx) {
    // Allocate packet buffer
    if (posix_memalign(&(packet_buffers[sockidx]),
                       getpagesize(), /* PAGE_SIZE aligned */
                       packet_buffer_size)) {
      fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    }

    /* Configure UMEM */
    umems[sockidx] =
        configure_xsk_umem(packet_buffers[sockidx], packet_buffer_size);
    if (umems[sockidx] == NULL) {
      fprintf(stderr, "ERROR: Can't create umem \"%s\"\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

    /* Open and configure the AF_XDP (xsk) sockets */
    xsk_sockets[sockidx] = xsk_configure_socket(&cfg, umems[sockidx], sockidx);
    if (xsk_sockets[sockidx] == NULL) {
      fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  /* Receive and count packets than drop them */
  pthread_t threads[NUM_THREADS];

  // Initialize a spinlock for each bucket, for minimal lock contention
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

  // Initialize global counter array
  for (int i = 0; i < NUM_THREADS; ++i) {
    countAr[i].count = 0;
  }

  // Initialize the hashtable, which will serve as the in-memory key-value store
  Node** hashtable = (Node**)malloc(TABLE_SIZE * sizeof(Node*));
  initialize_hashtable(hashtable);

  struct threadArgs* threadArgs_ar[NUM_THREADS];
  for (int th_idx = 0; th_idx < NUM_THREADS; ++th_idx) {
    threadArgs_ar[th_idx] = malloc(sizeof(struct threadArgs));
    threadArgs_ar[th_idx]->xski = xsk_sockets[th_idx];
    threadArgs_ar[th_idx]->idx = th_idx;
    threadArgs_ar[th_idx]->hashtable = hashtable;
    threadArgs_ar[th_idx]->locks = locks;
    ret = pthread_create(&threads[th_idx], NULL, rx_and_process,
                         threadArgs_ar[th_idx]);
  }

  // Wait for all threads to finish
  for (int th_idx = 0; th_idx < NUM_THREADS; ++th_idx) {
    pthread_join(threads[th_idx], NULL);
  }

  printf("Threads finished\n");

  /* Cleanup */
  for (int sockidx = 0; sockidx < NUM_SOCKETS; ++sockidx) {
    xsk_socket__delete(xsk_sockets[sockidx]->xsk);
    xsk_umem__delete(umems[sockidx]->umem);
  }
  for (int th_idx = 0; th_idx < NUM_THREADS; ++th_idx) {
    free(threadArgs_ar[th_idx]);
  }
  hashtable_cleanup(hashtable);
  for (int i = 0; i < TABLE_SIZE; ++i) {
    pthread_spin_destroy(&locks[i].lock);
  }
  free(locks);

  return EXIT_OK;
}