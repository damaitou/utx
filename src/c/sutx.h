
#ifndef _SUTX_H
#define _SUTX_H

#include "utx.h"

struct UtxReceiver {
    int socket_fd;
    struct tpacket_req req;
	char *rx_ring;
    //void * token;
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
        unsigned short payload_size );
};

extern unsigned long long utx_init_receiver(
    const char *rx_mac,
    //void * token,
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
        unsigned short payload_size)
    );

extern int utx_receiver_loop(unsigned long long _ur_addr, int fd, void *token);

#endif

