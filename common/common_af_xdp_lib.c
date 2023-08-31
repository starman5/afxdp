#include "common_af_xdp_lib.h"

static bool global_exit;
static int global_num_sockets = 0;

static const char* __doc__ = "AF_XDP kernel bypass example\n";

static const struct option_wrapper long_options[] = {

    {{"help", no_argument, NULL, 'h'}, "Show help", false},

    {{"dev", required_argument, NULL, 'd'},
     "Operate on device <ifname>",
     "<ifname>",
     true},

    {{"skb-mode", no_argument, NULL, 'S'},
     "Install XDP program in SKB (AKA generic) mode"},

    {{"native-mode", no_argument, NULL, 'N'},
     "Install XDP program in native mode"},

    {{"auto-mode", no_argument, NULL, 'A'}, "Auto-detect SKB or native mode"},

    {{"force", no_argument, NULL, 'F'},
     "Force install, replacing existing program on interface"},

    {{"copy", no_argument, NULL, 'c'}, "Force copy mode"},

    {{"zero-copy", no_argument, NULL, 'z'}, "Force zero-copy mode"},

    {{"queue", required_argument, NULL, 'Q'},
     "Configure interface receive queue for AF_XDP, default=0"},

    {{"poll-mode", no_argument, NULL, 'p'},
     "Use the poll() API waiting for packets to arrive"},

    {{"quiet", no_argument, NULL, 'q'}, "Quiet mode (no output)"},

    {{"filename", required_argument, NULL, 1},
     "Load program from <file>",
     "<file>"},

    {{"progname", required_argument, NULL, 2},
     "Load program from function <name> in the ELF file",
     "<name>"},

    {{0, 0, NULL, 0}, NULL, false}};

static struct xdp_program* prog;
static int xsk_map_fd;
static bool custom_xsk = false;
static struct config cfg = {
    .ifindex = -1,
};

// These are for counting the number of packets processed, returned when signal received
atomic_size_t num_packets = ATOMIC_VAR_INIT(0);

// Executed when signal received to stop
static void exit_application(int signal) {
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


//**********************************************************************
//************************ AF_XDP Logic ********************************
//**********************************************************************

// Convenient wrapper to pin a thread to a core
int pin_thread_to_core(int core_id) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);

  return pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

inline __u32 xsk_ring_prod__free(struct xsk_ring_prod* r) {
  r->cached_cons = *r->consumer + r->size;
  return r->cached_cons - r->cached_prod;
}

struct xsk_umem_info* configure_xsk_umem(void* buffer, uint64_t size) {
  printf("ifindex: %d\n", cfg.ifindex);
  struct xsk_umem_info* umem;
  int ret;

  umem = calloc(1, sizeof(*umem));
  if (!umem) return NULL;

  ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, NULL);
  if (ret) {
    errno = -ret;
    return NULL;
  }

  umem->buffer = buffer;
  return umem;
}

uint64_t xsk_alloc_umem_frame(struct xsk_socket_info* xsk) {
  uint64_t frame;
  if (xsk->umem_frame_free == 0) return INVALID_UMEM_FRAME;

  frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
  xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
  return frame;
}

void xsk_free_umem_frame(struct xsk_socket_info* xsk, uint64_t frame) {
  assert(xsk->umem_frame_free < NUM_FRAMES);

  xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

uint64_t xsk_umem_free_frames(struct xsk_socket_info* xsk) {
  return xsk->umem_frame_free;
}

struct xsk_socket_info* xsk_configure_socket(struct config* cfg,
                                                    struct xsk_umem_info* umem,
                                                    int queue) {
  printf("ifindex: %d\n", cfg->ifindex);
  struct xsk_socket_config xsk_cfg;
  struct xsk_socket_info* xsk_info;
  uint32_t idx;
  int i;
  int ret;
  uint32_t prog_id;

  xsk_info = calloc(1, sizeof(*xsk_info));
  if (!xsk_info) return NULL;

  xsk_info->umem = umem;
  xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
  xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
  xsk_cfg.xdp_flags = cfg->xdp_flags;
  xsk_cfg.bind_flags = cfg->xsk_bind_flags;
  xsk_cfg.libbpf_flags = (custom_xsk) ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD : 0;
  ret = xsk_socket__create_shared(&xsk_info->xsk, cfg->ifname, queue,
                                  umem->umem, &xsk_info->rx, &xsk_info->tx,
                                  &umem->fq, &umem->cq, &xsk_cfg);
  if (ret) goto error_exit;

  if (custom_xsk) {
    ret = xsk_socket__update_xskmap(xsk_info->xsk, xsk_map_fd);
    if (ret) goto error_exit;
  } else {
    /* Getting the program ID must be after the xdp_socket__create() call */
    if (bpf_xdp_query_id(cfg->ifindex, cfg->xdp_flags, &prog_id))
      goto error_exit;
  }

  /* Initialize umem frame allocation */
  for (i = 0; i < NUM_FRAMES; i++)
    xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

  xsk_info->umem_frame_free = NUM_FRAMES;

  /* Stuff the receive path with buffers, we assume we have enough */
  ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
                               XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);

  if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) goto error_exit;

  for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
    *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
        xsk_alloc_umem_frame(xsk_info);

  xsk_ring_prod__submit(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

  return xsk_info;

error_exit:
  errno = -ret;
  return NULL;
}

void complete_tx(struct xsk_socket_info* xsk) {
  unsigned int completed;
  uint32_t idx_cq;

  if (!xsk->outstanding_tx) {
    printf("No outstanding\n");
    return;
  }

  sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

  /* Collect/free completed TX buffers */
  completed = xsk_ring_cons__peek(&xsk->umem->cq,
                                  XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_cq);

  if (completed > 0) {
    for (int i = 0; i < completed; i++)
      xsk_free_umem_frame(xsk,
                          *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_cq++));

    xsk_ring_cons__release(&xsk->umem->cq, completed);
    xsk->outstanding_tx -=
        completed < xsk->outstanding_tx ? completed : xsk->outstanding_tx;
  } else {
    // printf("No completed\n");
  }
}

inline __sum16 csum16_add(__sum16 csum, __be16 addend) {
  uint16_t res = (uint16_t)csum;

  res += (__u16)addend;
  return (__sum16)(res + (res < (__u16)addend));
}

inline __sum16 csum16_sub(__sum16 csum, __be16 addend) {
  return csum16_add(csum, ~addend);
}

inline void csum_replace2(__sum16* sum, __be16 old, __be16 new) {
  *sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}

/*inline uint16_t compute_ip_checksum(struct iphdr* ip) {
  uint32_t csum = 0;
  uint16_t* next_ip_u16 = (uint16_t*)ip;

  ip->check = 0;

  for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
    csum += *next_ip_u16++;
  }

  return ~((csum & 0xffff) + (csum >> 16));
}*/

bool process_packet(struct xsk_socket_info* xsk, uint64_t addr,
                           uint32_t len, struct threadArgs* th_args) {
  
  printf("processing packet\n");
  TABLE_T table = th_args->table;
  int idx = th_args->idx;
  ProcessFunction custom_processing = th_args->custom_processing;
  Counter* countAr = th_args->countAr;
  
  int ret;
  uint32_t tx_idx = 0;
  uint8_t* pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

  if (!custom_processing(pkt, table, countAr, idx)) {
    return false;
  }

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

void handle_receive_packets(struct threadArgs* th_args) {
  printf("start handle_receive_packets\n");
  struct xsk_socket_info* xsk = th_args->xski;
  int idx = th_args->idx;

  unsigned int rcvd, stock_frames, i;
  uint32_t idx_rx = 0, idx_fq = 0;
  int ret;

  // Check if there is something to consume at all

  rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
  if (!rcvd) return;

  // atomic_fetch_add(&num_ready, 1);
  /* Stuff the ring with as much frames as possible */
  stock_frames = xsk_prod_nb_free(&xsk->umem->fq, xsk_umem_free_frames(xsk));

  if (stock_frames > 0) {
    ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames, &idx_fq);
    /* This should not happen, but just in case */
    while (ret != stock_frames)
      ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);

    for (i = 0; i < stock_frames; i++)
      *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
          xsk_alloc_umem_frame(xsk);

    xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
  }

  /* Process received packets */
  for (i = 0; i < rcvd; i++) {
    uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
    uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

    if (!process_packet(xsk, addr, len, th_args)) {
      printf("Couldn't send!\n");
      xsk_free_umem_frame(xsk, addr);
    }
    xsk->stats.rx_bytes += len;
  }

  xsk_ring_cons__release(&xsk->rx, rcvd);
  xsk->stats.rx_packets += rcvd;

  /* Do we need to wake up the kernel for transmission */
  complete_tx(xsk);
}

void rx_and_process(void* args) {
  printf("start rx_and_process\n");
  printf("ifindex: %d\n", cfg.ifindex);
  struct threadArgs* th_args = (struct threadArgs*)args;
  struct xsk_socket_info* xski = th_args->xski;
  int idx = th_args->idx;

  struct timespec timeout_end;
  struct timespec timeout_elapsed;

  if (pin_thread_to_core(idx) != 0) {
    perror("Could not pin thread to core\n");
    exit(EXIT_FAILURE);
  }

  struct pollfd fds[1];
  int ret = 1;
  int nfds = 1;

  memset(fds, 0, sizeof(fds));
  fds[0].fd = xsk_socket__fd(xski->xsk);
  fds[0].events = POLLIN;

  //printf("before while\n");
  while (!global_exit) {
    if (cfg.xsk_poll_mode) {
      // ret = poll(fds, nfds, -1);
      ret = poll(fds, nfds, 1);
      handle_receive_packets(th_args);
    } else {
      handle_receive_packets(th_args);
    }
  }
}

void start_afxdp(int num_sockets, ProcessFunction custom_processing, TABLE_T table) {
    /* Global shutdown handler */
  printf("start afxdp\n");
  global_num_sockets = num_sockets;
  signal(SIGINT, exit_application);

  int ret;
  void* packet_buffers[num_sockets];
  uint64_t packet_buffer_size;
  struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
  struct xsk_umem_info* umems[num_sockets];
  struct xsk_socket_info* xsk_sockets[num_sockets];

  Counter countAr[num_sockets];
  for (int i = 0; i < num_sockets; ++i) {
    countAr[i].count = 0;
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

  for (int sockidx = 0; sockidx < num_sockets; ++sockidx) {
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
    // TODO: addition of 20 only for -z flag
    xsk_sockets[sockidx] = xsk_configure_socket(&cfg, umems[sockidx], 20 + sockidx);
    if (xsk_sockets[sockidx] == NULL) {
      fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  /* Receive and count packets than drop them */
  pthread_t threads[num_sockets];

  struct threadArgs* threadArgs_ar[num_sockets];
  for (int th_idx = 0; th_idx < num_sockets; ++th_idx) {
    threadArgs_ar[th_idx] = malloc(sizeof(struct threadArgs));
    threadArgs_ar[th_idx]->xski = xsk_sockets[th_idx];
    threadArgs_ar[th_idx]->idx = th_idx;
    threadArgs_ar[th_idx]->table = table;
    threadArgs_ar[th_idx]->custom_processing = custom_processing;
    threadArgs_ar[th_idx]->countAr = countAr;

    ret = pthread_create(&threads[th_idx], NULL, rx_and_process,
                         threadArgs_ar[th_idx]);
  }

  // Wait for all threads to finish
  for (int th_idx = 0; th_idx < num_sockets; ++th_idx) {
    pthread_join(threads[th_idx], NULL);
  }

  printf("Threads finished\n");

  return EXIT_OK;
}


int init_afxdp(int argc, char** argv) {
  printf("init af_xdp\n");
  DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
  DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
  int err;
  char errmsg[1024];

  /* Cmdline options */
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
  return 0;
}