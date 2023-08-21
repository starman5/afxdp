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

static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod* r);

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

static bool global_exit;

static struct xsk_umem_info* configure_xsk_umem(void* buffer, uint64_t size);

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info* xsk);

static void xsk_free_umem_frame(struct xsk_socket_info* xsk, uint64_t frame);

static uint64_t xsk_umem_free_frames(struct xsk_socket_info* xsk);

static struct xsk_socket_info* xsk_configure_socket(struct config* cfg,
                                                    struct xsk_umem_info* umem,
                                                    int queue);

static void complete_tx(struct xsk_socket_info* xsk);

static inline __sum16 csum16_add(__sum16 csum, __be16 addend);

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend);

static inline void csum_replace2(__sum16* sum, __be16 old, __be16 new);

static inline uint16_t compute_ip_checksum(struct iphdr* ip);

static void handle_receive_packets(struct threadArgs* th_args);

static void rx_and_process(void* args);