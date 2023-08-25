#include "common_af_xdp_lib.h"

inline __u32 xsk_ring_prod__free(struct xsk_ring_prod* r) {
  r->cached_cons = *r->consumer + r->size;
  return r->cached_cons - r->cached_prod;
}

struct xsk_umem_info* configure_xsk_umem(void* buffer, uint64_t size) {
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

inline uint16_t compute_ip_checksum(struct iphdr* ip) {
  uint32_t csum = 0;
  uint16_t* next_ip_u16 = (uint16_t*)ip;

  ip->check = 0;

  for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
    csum += *next_ip_u16++;
  }

  return ~((csum & 0xffff) + (csum >> 16));
}
