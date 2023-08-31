#include "../common/common_af_xdp_lib.h"

// Keep in mind that NUM_SOCKETS = num threads.  One thread per socket
#define NUM_SOCKETS 1

// For extracting requested hashtable operations from packet payload
#define NON 5
#define SET 6
#define GET 7
#define DEL 8
#define END 9

#define DONT_OPTIMIZE(var) __asm__ __volatile__("" ::"m"(var));

/*
You must define a function with this function signature.
It takes in a pointer to a raw packet, a hashtable, an arry of locks, an array of counters, and a thread index
This function defines how you would like to process the raw packet.
It should perform any necessary modififaction of external data structures
And upon function exit, pkt should be overwritten with the data you wish to send back out
It should return true upon successful completion and false on error.
In this case, it performs hashtable operations.
*/
bool custom_processing(uint8_t* pkt, TABLE_T hashtable, Counter* countAr, int idx) {
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

  // Process message from the client
  switch (comm) {
    case NON:
      break;

    case SET: {
      // Get the value
      char* value = (char*)malloc(VAL_SIZE);
      memcpy(value, &payload_data[sizeof(uint8_t) + sizeof(uint32_t)],
             Val_Size);
      kvs_set(table, key, value, 1);
      countAr[idx].count += 1;
      break;
    }

    case GET: {
      char* value = (char*)malloc(VAL_SIZE);
      kvs_get(table, key, value, 1);
/*#if VAL_SIZE == 0
      DONT_OPTIMIZE(value);
#else
      memcpy(payload_data, value_get, VAL_SIZE);
#endif*/
      countAr[idx].count += 1;
      break;
    }

    case DEL: {
      kvs_delete(table, key);
      break;
    }

    case END: {
      uint64_t total_count = 0;
      for (int i = 0; i < NUM_SOCKETS; ++i) {
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
  // Process cmd line args, load XDP, load xsks_map
  int init_success = init_afxdp(argc, argv);
  if (init_success != 0) {
    perror("FAIL");
  }

  // Allocate table
  TABLE_T table =  calloc(1, sizeof(struct kvs));
  kvs_init(table);

  // Start NUM_SOCKETS AF_XDP sockets
  start_afxdp(NUM_SOCKETS, custom_processing, table);

  return EXIT_OK;
}