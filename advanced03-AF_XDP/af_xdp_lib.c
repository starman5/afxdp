#include "af_xdp_lib.h"

static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod* r) {
  r->cached_cons = *r->consumer + r->size;
  return r->cached_cons - r->cached_prod;
}

static struct xsk_umem_info* configure_xsk_umem(void* buffer, uint64_t size) {
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

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info* xsk) {
  uint64_t frame;
  if (xsk->umem_frame_free == 0) return INVALID_UMEM_FRAME;

  frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
  xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
  return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info* xsk, uint64_t frame) {
  assert(xsk->umem_frame_free < NUM_FRAMES);

  xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info* xsk) {
  return xsk->umem_frame_free;
}

static struct xsk_socket_info* xsk_configure_socket(struct config* cfg,
                                                    struct xsk_umem_info* umem,
                                                    int queue) {
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

static void complete_tx(struct xsk_socket_info* xsk) {
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

static inline __sum16 csum16_add(__sum16 csum, __be16 addend) {
  uint16_t res = (uint16_t)csum;

  res += (__u16)addend;
  return (__sum16)(res + (res < (__u16)addend));
}

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend) {
  return csum16_add(csum, ~addend);
}

static inline void csum_replace2(__sum16* sum, __be16 old, __be16 new) {
  *sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}

static inline uint16_t compute_ip_checksum(struct iphdr* ip) {
  uint32_t csum = 0;
  uint16_t* next_ip_u16 = (uint16_t*)ip;

  ip->check = 0;

  for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
    csum += *next_ip_u16++;
  }

  return ~((csum & 0xffff) + (csum >> 16));
}

static void handle_receive_packets(struct threadArgs* th_args) {
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

  // Reset timeout start
  clock_gettime(CLOCK_MONOTONIC, &timeout_start);
}

static void rx_and_process(void* args) {
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

  while (!global_exit) {
    if (cfg.xsk_poll_mode) {
      // ret = poll(fds, nfds, -1);
      ret = poll(fds, nfds, 1);
      handle_receive_packets(th_args);
    } else {
      handle_receive_packets(th_args);
    }
    // Check timeout
    /*if (num_tx_packets > 0) {
            clock_gettime(CLOCK_MONOTONIC, &timeout_end);
            timeout_elapsed.tv_sec = timeout_end.tv_sec - timeout_start.tv_sec;
            if (timeout_end.tv_nsec >= timeout_start.tv_nsec) {
                    timeout_elapsed.tv_nsec = timeout_end.tv_nsec -
    timeout_start.tv_nsec; } else { timeout_elapsed_time.tv_sec--;
                    timeout_elapsed.tv_nsec = 1000000000 + end_time.tv_nsec -
    start_time.tv_nsec;
            }

            if (timeout_elapsed.tv_nsec >= TIMEOUT_NSEC) {
                    printf("timeout\n");
                    xsk_ring_prod__submit(&xsk->tx, num_tx_packets);
                    xsk->outstanding_tx += num_tx_packets;
                    num_tx_packets = 0;
                    complete_tx(xsk);
            }
    }*/
  }
}