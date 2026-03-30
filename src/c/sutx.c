
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <poll.h>
#include "sutx.h"

static unsigned int rx_mtu = 1500;
static unsigned int rx_buffer_size_mb = 640; //default to 640MB ring buffer size

static inline void handle_frame (struct sockaddr_ll *addr,
		   char *l2content, char *l3content, struct UtxReceiver *ur, void *token);

static inline unsigned int guess_block_size() 
{
    long sz = sysconf(_SC_PAGESIZE);
    if (sz == 4096) {
        return 8192;
    } else {
        return (unsigned int)sz;
    }
}

char *
setup_rx_ring (int s, struct tpacket_req *req)	//return rx_ing
{
    int snaplen = rx_mtu;		//ethernet mtu
    //req->tp_block_size = 8192*2;
    req->tp_block_size = guess_block_size();
    req->tp_frame_size = TPACKET_ALIGN (TPACKET_HDRLEN + ETH_HLEN) + TPACKET_ALIGN (snaplen);	//1584 if mtu=1500
    req->tp_block_nr = rx_buffer_size_mb * (1024 * 1024 / req->tp_block_size);
    size_t frames_per_block = req->tp_block_size / req->tp_frame_size;
    req->tp_frame_nr = req->tp_block_nr * frames_per_block;

    printf("rx_mtu=%d\n", rx_mtu);
    printf("rx_buffer_size_mb=%u\n", rx_buffer_size_mb);
    printf("tp_block_size=%d\n", req->tp_block_size);
    printf("tp_frame_size=%d\n", req->tp_frame_size);
    printf("frames_per_block=%u\n", (int)frames_per_block);
    printf("tp_block_nr=%d\n", req->tp_block_nr);
    printf("tp_frame_nr=%u\n", req->tp_frame_nr);

    if (setsockopt
        (s, SOL_PACKET, PACKET_RX_RING, req, sizeof (struct tpacket_req)) == -1)
    {
        perror ("setsockopt");
        return MAP_FAILED;
    }

    size_t rx_ring_size = req->tp_block_nr * req->tp_block_size;
    char *rx_ring = (char *)mmap (0, rx_ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, s, 0);

    return rx_ring;
}

int
loop(struct UtxReceiver *ur, int ctrl_fd, void * token)
{
    int s = ur->socket_fd;
    struct tpacket_req *req = &ur->req;
    char *rx_ring = ur->rx_ring;

    int ctrl_fd_closed = 0;  // 标记控制通道是否已关闭

    //struct pollfd fds[1] = { 0 };
    //struct pollfd fds[1];
    struct pollfd fds[2];
    fds[0].fd = s;
    fds[0].events = POLLIN;
    fds[1].fd = ctrl_fd;
    fds[1].events = POLLIN;

    size_t frame_idx = 0;
    char *frame_ptr = rx_ring;
    //size_t rx_ring_size = req->tp_block_nr * req->tp_block_size;
    size_t frames_per_buffer = req->tp_block_size / req->tp_frame_size;

    while (1)
    {
        struct tpacket_hdr *tphdr = (struct tpacket_hdr *) frame_ptr;
        while (!(tphdr->tp_status & TP_STATUS_USER))
        {
            //poll的结果有两种:
            // fds[0]有数据,则ring_buffer来数据了
            // fds[1]有数据,则控制通道来数据了
            int poll_result;
            if (!ctrl_fd_closed) {
                poll_result = poll (fds, 2, -1);
            }
            else {
                poll_result = poll (fds, 1, -1); // 只监控 socket
            }
            if (poll_result == -1)
            {
                perror ("poll");
                return -1;
            }

            // 检查 socket 错误
            if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                return -1;
            }

            // 控制通道有数据（且未关闭）
            if (!ctrl_fd_closed && (fds[1].revents & POLLIN)) {
                static unsigned char buf[256];
                int nr = read(ctrl_fd, buf, sizeof(buf));
                if (nr < 0) {
                    if (errno == EINTR) continue;
                    perror("read");
                    close(ctrl_fd);
                    ctrl_fd_closed = 1;
                    // return -1;
                }
                else if (nr == 0) {
                    // 对端关闭，标记为已关闭，不再监控
                    printf("control fd closed by peer, continuing...\n");
                    close(ctrl_fd);
                    ctrl_fd_closed = 1;
                     // 不调用 utx_handler，跳过这次处理
                }
                else {
                    ur->utx_handler(
                        //ur->token,
                        token,
                        UTX_TYPE_SYS,   //utx->type, 
                        0,              //utx->channel, 
                        0,              //utx->seq, 
                        0,              //utx->head, 
                        0,              //utx->tail, 
                        0,              //utx->check, 
                        0,              //utx->session_id,
                        0,              //utx->packet_opt,
                        0,              //utx->packet_head,
                        0,              //utx->packet_tail,
                        buf,            //payload, 
                        nr);            //payload_size);
                }
            }
        }


        struct sockaddr_ll *addr =
            (struct sockaddr_ll *) (frame_ptr + TPACKET_HDRLEN -
                    sizeof (struct sockaddr_ll));
        char *l2content = frame_ptr + tphdr->tp_mac;
        char *l3content = frame_ptr + tphdr->tp_net;
        handle_frame (addr, l2content, l3content, ur, token);

        tphdr->tp_status = TP_STATUS_KERNEL;	//return control to kernel
        frame_idx = (frame_idx + 1) % req->tp_frame_nr;
        int buffer_idx = frame_idx / frames_per_buffer;
        char *buffer_ptr = rx_ring + buffer_idx * req->tp_block_size;
        int frame_idx_diff = frame_idx % frames_per_buffer;
        frame_ptr = buffer_ptr + frame_idx_diff * req->tp_frame_size;
    }
}

int
loop_on_available_packets(struct UtxReceiver *ur, void *token)
{
    struct tpacket_req *req = &ur->req;
    char *rx_ring = ur->rx_ring;

    static char *frame_ptr = NULL;
    static size_t frame_idx = 0;
    static size_t frames_per_buffer = 0;

    if (NULL == frame_ptr) {
        frame_ptr = rx_ring;
        frame_idx = 0;
        frames_per_buffer = req->tp_block_size / req->tp_frame_size;
    }

    int counter = 0;
    while (1)
    {
        struct tpacket_hdr *tphdr = (struct tpacket_hdr *) frame_ptr;
        if (!(tphdr->tp_status & TP_STATUS_USER))
            break;

        struct sockaddr_ll *addr =
            (struct sockaddr_ll *) (frame_ptr + TPACKET_HDRLEN -
                    sizeof (struct sockaddr_ll));
        char *l2content = frame_ptr + tphdr->tp_mac;
        char *l3content = frame_ptr + tphdr->tp_net;
        handle_frame (addr, l2content, l3content, ur, token);

        tphdr->tp_status = TP_STATUS_KERNEL;	//return control to kernel
        frame_idx = (frame_idx + 1) % req->tp_frame_nr;
        int buffer_idx = frame_idx / frames_per_buffer;
        char *buffer_ptr = rx_ring + buffer_idx * req->tp_block_size;
        int frame_idx_diff = frame_idx % frames_per_buffer;
        frame_ptr = buffer_ptr + frame_idx_diff * req->tp_frame_size;

        counter++;
    }

    return counter;
}

static inline void
handle_frame (
    struct sockaddr_ll *addr,
    char *l2content, 
    char *l3content,
    struct UtxReceiver *ur,
    void *token
) {
    struct ethhdr *eth = (struct ethhdr *) l2content;
    if (addr->sll_pkttype != PACKET_HOST || eth->h_proto != 9)	//discard no-UTX ethernet packet
    {
        return;
    }

    struct utxhdr *utx = (struct utxhdr *) l3content;
    unsigned char *payload = (unsigned char*)l3content + UTXHDR_SIZE;
    unsigned short payload_size = utx->len - UTXHDR_SIZE;
    ur->utx_handler(
        token,
        utx->type, 
        utx->channel, 
        utx->seq, 
        utx->head, 
        utx->tail, 
        utx->check, 
        utx->session_id,
        utx->packet_opt,
        utx->packet_head,
        utx->packet_tail,
        payload, 
        payload_size);

}

extern int bindif (int s, const char *if_name);
extern int parse_mac(const char * printable_mac,  unsigned char *macbuf);
extern int find_if_by_mac( int sock, const unsigned char *mac, char if_name[IFNAMSIZ]);

unsigned int
utx_set_rx_mtu(unsigned int mtu)
{
    unsigned int old_rx_mtu = rx_mtu;
    rx_mtu = mtu;
    return old_rx_mtu;
}

unsigned int
utx_set_rx_buffer_size_mb(unsigned int mb)
{
    unsigned int old_value = rx_buffer_size_mb;
    rx_buffer_size_mb = mb;
    return old_value;
}

unsigned long long 
utx_init_receiver(
    const char *rx_mac,
    void (*utx_handler) (
        void * token,
        unsigned char type,
        unsigned char channel,
        unsigned short seq,
        unsigned char head,
        unsigned char tail,
        unsigned short check,
        unsigned short session_id,
        unsigned char packet_opt,
        unsigned char packet_head,
        unsigned char packet_tail,
        unsigned char * payload,
        unsigned short payload_size
    )
) {
    unsigned char rx_mac_bytes[6];
    if (parse_mac(rx_mac, rx_mac_bytes) < 0)
        return 0;

    struct UtxReceiver *ur = (struct UtxReceiver *)malloc(sizeof(struct UtxReceiver));
    if (NULL == ur)
        return 0;

    ur->utx_handler = utx_handler;
	if ((ur->socket_fd = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_UTX))) < 0) {
		perror ("socket() error");
        free((void *)ur);
		return 0;
	}

    char if_name[IFNAMSIZ];
    if (find_if_by_mac(ur->socket_fd, rx_mac_bytes, if_name) < 0) {
        free((void *)ur);
        printf("find_if_by_mac('%s') failed\n", rx_mac);
        return 0;
    }

	if (bindif (ur->socket_fd, if_name) < 0) {
        close(ur->socket_fd);
        free((void *)ur);
		return 0;
	}

	ur->rx_ring = setup_rx_ring (ur->socket_fd, &ur->req);
    if (MAP_FAILED == ur->rx_ring) {
        close(ur->socket_fd);
        free((void *)ur);
        return 0;
    }

    printf("utx_receiver=%p\n", ur);
    return (unsigned long long)ur;
}

int utx_receiver_get_socket_fd(unsigned long long _ur_addr)
{
    struct UtxReceiver *ur = (struct UtxReceiver *)_ur_addr;
    return ur->socket_fd;
}

int utx_receiver_loop(unsigned long long _ur_addr, int fd, void *token)
{
    struct UtxReceiver *ur = (struct UtxReceiver *)_ur_addr;
    if (NULL == ur)
        return 0;

    return loop(ur, fd, token);
}

int utx_receiver_loop_on_available_packets(unsigned long long _ur_addr, void *token)
{
    struct UtxReceiver *ur = (struct UtxReceiver *)_ur_addr;
    if (NULL == ur)
        return 0;

    return loop_on_available_packets(ur, token);
}

