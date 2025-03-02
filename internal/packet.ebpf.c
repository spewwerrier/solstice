//go:build ignore

#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/types.h>

struct ipv6_addr {
  __u64 high;
  __u64 low;
};

struct ipv4_pkt {
    __be32 saddr;
    __u32 pkt_size;
};

struct ipv6_pkt {
    struct in6_addr saddr;
    __u32 pkt_size;
}__attribute__((packed));

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1024);
  __type(key, __be32);
  __type(value, _Bool);

} blacklist_ipv4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1024);
  __type(key, struct ipv6_addr);
  __type(value, _Bool);
} blacklist_ipv6 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
} ip_blocked SEC(".maps");


struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
}ip_log SEC(".maps");


SEC("xdp")
int PacketFilter(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  __u32 data_len = data_end - data;

  struct ethhdr *eth = data;
  if ((void*) (eth+1) > data_end){
    return XDP_PASS;
  }

  // ipv4
  if(bpf_ntohs(eth->h_proto) == ETH_P_IP){
    struct iphdr *ip = (void *)(data + sizeof(struct ethhdr));
    if ((void*)(eth + 1) + sizeof(struct iphdr) > data_end) {
        return XDP_PASS;
    }
    __be32 saddr = ip->saddr;
    int *elem = bpf_map_lookup_elem(&blacklist_ipv4, &saddr);

    struct ipv4_pkt pkt;
    pkt.saddr = saddr;
    pkt.pkt_size = data_len;

    if (elem != NULL){
      // rb type blocked
      bpf_ringbuf_output(&ip_blocked, &pkt, sizeof(pkt), 0);
      return XDP_DROP;
    }
    // rb type logs
    bpf_ringbuf_output(&ip_log, &pkt, sizeof(pkt), 0);
    return XDP_PASS;
  }

  // ipv6
  if(bpf_ntohs(eth->h_proto) == ETH_P_IPV6){
    struct ipv6hdr *ip = (void *)(data + sizeof(struct ethhdr));
    if((void*)(eth + 1) + sizeof(struct ipv6hdr) > data_end){
      return XDP_PASS;
    }
    struct in6_addr saddr = ip->saddr;
    struct ipv6_addr map_key;

    map_key.high = ((__u64)saddr.s6_addr[0] << 56) |
              ((__u64)saddr.s6_addr[1] << 48) |
              ((__u64)saddr.s6_addr[2] << 40) |
              ((__u64)saddr.s6_addr[3] << 32) |
              ((__u64)saddr.s6_addr[4] << 24) |
              ((__u64)saddr.s6_addr[5] << 16) |
              ((__u64)saddr.s6_addr[6] << 8) |
              ((__u64)saddr.s6_addr[7]);

    map_key.low = ((__u64)saddr.s6_addr[8] << 56) |
             ((__u64)saddr.s6_addr[9] << 48) |
             ((__u64)saddr.s6_addr[10] << 40) |
             ((__u64)saddr.s6_addr[11] << 32) |
             ((__u64)saddr.s6_addr[12] << 24) |
             ((__u64)saddr.s6_addr[13] << 16) |
             ((__u64)saddr.s6_addr[14] << 8) |
             ((__u64)saddr.s6_addr[15]);

    struct ipv6_pkt pkt;
    pkt.saddr = saddr;
    pkt.pkt_size = data_len;

    _Bool *elem = bpf_map_lookup_elem(&blacklist_ipv6, &map_key);
    if(elem != NULL && *elem){
      // rb type blocked
      bpf_ringbuf_output(&ip_blocked, &pkt, sizeof(pkt), 0);
      return XDP_DROP;
    }
    // rb type logs
    bpf_ringbuf_output(&ip_log, &pkt, sizeof(pkt), 0);
    return XDP_PASS;
  }

  return XDP_PASS;
}
