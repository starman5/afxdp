/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>

#define SERVER_PORT 8889
#define htons(x) ((__be16)___constant_swab16((x)))

struct {
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 64);
} xsks_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 64);
} xdp_stats_map SEC(".maps");

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx) {
  int index = ctx->rx_queue_index;
  /* A set entry here means that the correspnding queue_id
   * has an active AF_XDP socket bound to it. */
  if (bpf_map_lookup_elem(&xsks_map, &index))
    return bpf_redirect_map(&xsks_map, index, 0);

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;
  if (eth + 1 > data_end) return XDP_PASS;

  struct iphdr *ip = data + sizeof(*eth);
  if (ip + 1 > data_end) return XDP_PASS;

  struct udphdr *udp = (struct udphdr *)(data + sizeof(*eth) + sizeof(*ip));
  if (udp + 1 > data_end) return XDP_PASS;

  if (udp->dest != htons(SERVER_PORT)) return XDP_PASS;

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";