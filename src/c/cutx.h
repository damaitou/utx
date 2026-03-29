#ifndef _CUTX_H
#define _CUTX_H

#include "utx.h"

//runtime for 'BLOC' mode
struct bloc_rt {
    unsigned int bloc_size;
    char bloc_name[UTX_FILENAME_MAXLEN];
    int bloc_seq; //bloc sequence of current stor
    int bloc_fd;  //fd to the current BLOCK FILE
    int bloc_left; //how many bytes to write to finish the current BLOCK FILE
};

struct UtxSender {
	int socket_fd;
	struct sockaddr_ll sadr_ll;
	//unsigned char packet[UTX_MAXLEN];
	unsigned char *packet;
    struct bloc_rt bloc;
    unsigned short int utx_seq[256];
    unsigned long long utx_counter;
};

extern unsigned long long utx_init_sender (
    const char *tx_mac,
    const char *rx_mac,
    unsigned int bloc_size);

extern void utx_drop_sender (unsigned long long handle);

extern int utx_send_a_file (
    unsigned long long handle,
    int channel,
    const char *root_path,
    const char *filename_of_relative_path,
    unsigned long long *filesize,
    int *_errno);

extern int utx_send_datagram (
    unsigned long long handle,
    int channel,
    const char * buf,
    unsigned int len);

extern int utx_send_bloc_buf (
    unsigned long long handle,
    int channel,
    const char * buf,
    unsigned int len,
    int header_bit,
    int packet_opt);

#endif

