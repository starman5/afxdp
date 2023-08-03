#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdatomic.h>
#include <sched.h>
#include <stdalign.h>

#include <sys/resource.h>
#include <sys/sysinfo.h>

#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define TX_BATCH_SIZE	   5
#define INVALID_UMEM_FRAME UINT64_MAX
#define NUM_SOCKETS		   1
#define NUM_THREADS		   NUM_SOCKETS
#define TIMEOUT_NSEC	   500000000
#define CACHE_LINE_SIZE	   64

#define MAX_PACKET_LEN	XSK_UMEM__DEFAULT_FRAME_SIZE
#define SRC_MAC	"9c:dc:71:5d:41:f1"
#define DST_MAC	"9c:dc:71:5d:01:81"
#define SRC_IP	"192.168.6.1"
#define DST_IP	"192.168.6.2"
#define SRC_PORT	8889
#define DST_PORT	8889
#define MAX_BUFFER_SIZE 60
#define TABLE_SIZE  1000000

#define NON     5
#define SET     6
#define GET     7
#define DEL     8 
#define END     9

atomic_size_t num_packets = ATOMIC_VAR_INIT(0);
atomic_size_t num_ready = ATOMIC_VAR_INIT(0);
size_t num_tx_packets = 0;
struct timespec timeout_start = {0, 0};

static struct xdp_program *prog;
int xsk_map_fd;
bool custom_xsk = false;
struct config cfg = {
	.ifindex   = -1,
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

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
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
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

	uint32_t outstanding_tx;

	struct stats_record stats;
	struct stats_record prev_stats;
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
uint64_t hash_key(uint64_t key) {
    return key % TABLE_SIZE;
}

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
    new_node->next = head;
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


static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r)
{
	r->cached_cons = *r->consumer + r->size;
	return r->cached_cons - r->cached_prod;
}

static const char *__doc__ = "AF_XDP kernel bypass example\n";

static const struct option_wrapper long_options[] = {

	{{"help",	 no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",	 required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",	 no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",	 no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",	 no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"copy",        no_argument,		NULL, 'c' },
	 "Force copy mode"},

	{{"zero-copy",	 no_argument,		NULL, 'z' },
	 "Force zero-copy mode"},

	{{"queue",	 required_argument,	NULL, 'Q' },
	 "Configure interface receive queue for AF_XDP, default=0"},

	{{"poll-mode",	 no_argument,		NULL, 'p' },
	 "Use the poll() API waiting for packets to arrive"},

	{{"quiet",	 no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progname",	 required_argument,	NULL,  2  },
	 "Load program from function <name> in the ELF file", "<name>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static bool global_exit;

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
	struct xsk_umem_info *umem;
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       NULL);
	if (ret) {
		errno = -ret;
		return NULL;
	}

	umem->buffer = buffer;
	return umem;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
	uint64_t frame;
	if (xsk->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
	xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
	assert(xsk->umem_frame_free < NUM_FRAMES);

	xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
	return xsk->umem_frame_free;
}

static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
						    struct xsk_umem_info *umem, int queue)
{
	struct xsk_socket_config xsk_cfg;
	struct xsk_socket_info *xsk_info;
	uint32_t idx;
	int i;
	int ret;
	uint32_t prog_id;
	int queue_id = 20;

	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	xsk_info->umem = umem;
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.xdp_flags = cfg->xdp_flags;
	xsk_cfg.bind_flags = cfg->xsk_bind_flags;
	xsk_cfg.libbpf_flags = (custom_xsk) ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD: 0;
	ret = xsk_socket__create_shared(&xsk_info->xsk, cfg->ifname,
				 queue_id, umem->umem, &xsk_info->rx,
				 &xsk_info->tx, &umem->fq, &umem->cq, &xsk_cfg);
	if (ret)
		goto error_exit;

	if (custom_xsk) {
		ret = xsk_socket__update_xskmap(xsk_info->xsk, xsk_map_fd);
		if (ret)
			goto error_exit;
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
					XSK_RING_PROD__DEFAULT_NUM_DESCS,
					&idx);

	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		goto error_exit;

	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++)
		*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
			xsk_alloc_umem_frame(xsk_info);

	xsk_ring_prod__submit(&xsk_info->umem->fq,
			    XSK_RING_PROD__DEFAULT_NUM_DESCS);

	return xsk_info;

error_exit:
	errno = -ret;
	return NULL;
}

static void complete_tx(struct xsk_socket_info *xsk)
{
	unsigned int completed;
	uint32_t idx_cq;

	if (!xsk->outstanding_tx) {
		printf("No outstanding\n");
		return;
	}

	sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

	/* Collect/free completed TX buffers */
	completed = xsk_ring_cons__peek(&xsk->umem->cq,
					XSK_RING_CONS__DEFAULT_NUM_DESCS,
					&idx_cq);

	if (completed > 0) {
		for (int i = 0; i < completed; i++)
			xsk_free_umem_frame(xsk,
					    *xsk_ring_cons__comp_addr(&xsk->umem->cq,
								      idx_cq++));

		xsk_ring_cons__release(&xsk->umem->cq, completed);
		xsk->outstanding_tx -= completed < xsk->outstanding_tx ?
			completed : xsk->outstanding_tx;
	}
	else {
		//printf("No completed\n");
	}
}

static inline __sum16 csum16_add(__sum16 csum, __be16 addend)
{
	uint16_t res = (uint16_t)csum;

	res += (__u16)addend;
	return (__sum16)(res + (res < (__u16)addend));
}

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend)
{
	return csum16_add(csum, ~addend);
}

static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new)
{
	*sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}

static bool process_packet(struct xsk_socket_info *xsk,
			   uint64_t addr, uint32_t len, struct threadArgs* th_args)
{
	Node** hashtable = th_args->hashtable;
	int idx = th_args->idx;
	Spinlock* locks = th_args->locks;

	uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

	int ret;
	uint32_t tx_idx = 0;
	uint8_t tmp_mac[ETH_ALEN];
	struct in_addr tmp_ip;
	struct ethhdr *eth = (struct ethhdr *) pkt;
	struct iphdr *iph = (struct iphdr *) (eth + 1);
	struct udphdr *udph = NULL;

	// Retrieve payload
	unsigned char* ip_payload = (unsigned char*)iph + (iph->ihl * 4);
	unsigned char* buffer = ip_payload + sizeof(struct udphdr);

	// Process request
	char* special_message = NULL;
    const char* default_message = "Message received";
    //buffer[bytes_received] = '\0';  // Make buffer a null-terminated string
    //printf("Received message from client: %s\n", buffer);

    uint64_t comm = ((int)(buffer[0] - '0'));
    uint64_t key;
    char* value = (char*)malloc(MAX_BUFFER_SIZE - sizeof(comm) - sizeof(key));

     // Get key from serialized message
    int pos = 2;    // Starting position of key in serialized string
    int numbytes = 0;
    while (buffer[pos] != '|') {
        ++numbytes;
        ++pos;
    }
    char keybuf[10];
    memcpy(keybuf, &buffer[2], numbytes);
    keybuf[numbytes] = '\0';
    char* endptr;
    key = strtol(keybuf, &endptr, 10);

    // Get the value
    ++pos;
    strcpy(value, &buffer[pos]);

    // Process message from the client
    switch (comm) {
        case NON:
            break;
        case SET:
            table_set(hashtable, key, value, locks);
            break;

        case GET:
			;
            char* val = table_get(hashtable, key, locks);
            if (val && val[0] == '*') {    // Prevent compiler optimization
                printf("star\n");
            }
            break;

        case DEL:
            table_delete(hashtable, key, locks);
            break;

        case END:
			;
            uint64_t total_count = 0;
            for (int i = 0; i < NUM_SOCKETS; ++i) {
                total_count += countAr[i].count;
                printf("thread %d: %ld\n", i, countAr[i].count); 
            }
            // Get the total number of processed requests and send back to user
            char end_message[15];
            sprintf(end_message, "%ld", total_count);
            special_message = end_message;
            break;

        default:
            special_message = "Command Not Found";
    }

	countAr[idx].count += 1;

		
	if (ntohs(eth->h_proto) != ETH_P_IP)
			return false;

	// Swap source and destination MAC
	memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, tmp_mac, ETH_ALEN);

	// Swap source and destination IP
	memcpy(&tmp_ip, &iph->saddr, sizeof(tmp_ip));
	memcpy(&iph->saddr, &iph->daddr, sizeof(tmp_ip));
	memcpy(&iph->daddr, &tmp_ip, sizeof(tmp_ip));

	// Swap source and destination port
	unsigned char* ip_data = (unsigned char*)iph + (iph->ihl * 4);
	udph = (struct udphdr*)ip_data;
	//printf("src: %d\n", udph->source);
	//printf("dst: %d\n", udph->dest);
	uint16_t tmp = udph->source;
	udph->source = udph->dest;
	udph->dest = tmp;
	
	char new_payload[5] = "aaaa";
	unsigned char* payload_data = (unsigned char*)(udph) + sizeof(struct udphdr);
	printf("payload: %s\n", payload_data);
	memcpy((payload_data + 1), new_payload, 4);
	printf("new payload: %s\n", payload_data);
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
	//if (num_tx_packets >= TX_BATCH_SIZE) {
		xsk_ring_prod__submit(&xsk->tx, 1);
		xsk->outstanding_tx += 1;
		//num_tx_packets = 0;
	//}

	xsk->stats.tx_bytes += len;
	xsk->stats.tx_packets++;
	return true;
}

static void handle_receive_packets(struct threadArgs* th_args)
{
	struct xsk_socket_info *xsk = th_args->xski;
	int idx = th_args->idx;

	unsigned int rcvd, stock_frames, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

	// Check if there is something to consume at all
	
	rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
	if (!rcvd)
		return;

	//atomic_fetch_add(&num_ready, 1);
	/* Stuff the ring with as much frames as possible */
	stock_frames = xsk_prod_nb_free(&xsk->umem->fq,
					xsk_umem_free_frames(xsk));

	if (stock_frames > 0) {

		ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames,
					     &idx_fq);
		/* This should not happen, but just in case */
		while (ret != stock_frames)
			ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd,
						     &idx_fq);

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

//static void rx_and_process(struct config* cfg,
//						   struct xsk_socket_info **xsk_sockets)

static void rx_and_process(void* args)
{
	struct threadArgs* th_args = (struct threadArgs*)args;
	struct xsk_socket_info *xski = th_args->xski;
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
			ret = poll(fds, nfds, -1);
			handle_receive_packets(th_args);
		}
		else {
			handle_receive_packets(th_args);
		}
		// Check timeout
		/*if (num_tx_packets > 0) {
			clock_gettime(CLOCK_MONOTONIC, &timeout_end);
			timeout_elapsed.tv_sec = timeout_end.tv_sec - timeout_start.tv_sec;
			if (timeout_end.tv_nsec >= timeout_start.tv_nsec) {
				timeout_elapsed.tv_nsec = timeout_end.tv_nsec - timeout_start.tv_nsec;
			} else {
				timeout_elapsed_time.tv_sec--;
				timeout_elapsed.tv_nsec = 1000000000 + end_time.tv_nsec - start_time.tv_nsec;
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

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static uint64_t gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct stats_record *r, struct stats_record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

static void stats_print(struct stats_record *stats_rec,
			struct stats_record *stats_prev)
{
	uint64_t packets, bytes;
	double period;
	double pps; /* packets per sec */
	double bps; /* bits per sec */

	char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
		" %'11lld Kbytes (%'6.0f Mbits/s)"
		" period:%f\n";

	period = calc_period(stats_rec, stats_prev);
	if (period == 0)
		period = 1;

	packets = stats_rec->rx_packets - stats_prev->rx_packets;
	pps     = packets / period;

	bytes   = stats_rec->rx_bytes   - stats_prev->rx_bytes;
	bps     = (bytes * 8) / period / 1000000;

	printf(fmt, "AF_XDP RX:", stats_rec->rx_packets, pps,
	       stats_rec->rx_bytes / 1000 , bps,
	       period);

	packets = stats_rec->tx_packets - stats_prev->tx_packets;
	pps     = packets / period;

	bytes   = stats_rec->tx_bytes   - stats_prev->tx_bytes;
	bps     = (bytes * 8) / period / 1000000;

	printf(fmt, "       TX:", stats_rec->tx_packets, pps,
	       stats_rec->tx_bytes / 1000 , bps,
	       period);

	printf("\n");
}

static void *stats_poll(void *arg)
{
	unsigned int interval = 2;
	struct xsk_socket_info *xsk = arg;
	static struct stats_record previous_stats = { 0 };

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

static void exit_application(int signal)
{
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

int main(int argc, char **argv)
{
	int ret;
	void *packet_buffers[NUM_SOCKETS];
	uint64_t packet_buffer_size;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	struct xsk_umem_info *umems[NUM_SOCKETS];
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
		struct bpf_map *map;

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
			prog = xdp_program__open_file(cfg.filename,
						  NULL, &opts);
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
			fprintf(stderr, "ERROR: no xsks map found: %s\n",
				strerror(xsk_map_fd));
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
		umems[sockidx] = configure_xsk_umem(packet_buffers[sockidx], packet_buffer_size);
		if (umems[sockidx] == NULL) {
			fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
				strerror(errno));
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
    if (posix_memalign(&rawPtr_Spinlock, CACHE_LINE_SIZE, TABLE_SIZE * sizeof(Spinlock)) != 0) {
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
		ret = pthread_create(&threads[th_idx], NULL, rx_and_process, threadArgs_ar[th_idx]);
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