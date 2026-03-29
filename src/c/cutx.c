
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ifaddrs.h>
#include <time.h>
#include "cutx.h"

static unsigned int tx_mtu = 1500;
static unsigned long long tx_busy_sleep_nanos = 010000000; //1ms default

static
unsigned short 
checksum(unsigned char* buff, int buff_len)
{
    unsigned long sum = 0;
    int i;
    for(i=0; i<2*(buff_len/2); i+=2)
        sum += ((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
    if (buff_len%2)
        sum += ((buff[buff_len-1]<<8)&0xFF00);

    while (sum>>16)
        sum = (sum & 0xFFFF)+(sum >> 16);
    return (unsigned short)(~sum);
}

/*
 *printable_mac example:  "6c:b3:11:51:4c:d7"
 *caller must assure macbuf is a at-least-6-bytes buffer
 */
int
parse_mac(const char * printable_mac,  unsigned char *macbuf)
{
	unsigned int t[6];
	if (6 != sscanf(printable_mac, "%x:%x:%x:%x:%x:%x", &t[0], &t[1], &t[2], &t[3], &t[4], &t[5]))
		return -1;

	int i;
	for (i=0; i<6; ++i) {
		if (t[i] < 256)
			macbuf[i] = (unsigned char)t[i];
		else
			return -1;
	}

	return 0;
}

int 
bind_socket_to_interface(int s, const char*if_name) {
    struct ifreq ifr;
    size_t if_name_len = strlen (if_name);
    if (if_name_len < sizeof(ifr.ifr_name)) {
        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), if_name);
    } else {
        printf("bind_socket_to_interface(), interface name too long\n");
        return -1;
    }

    if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        perror("setsockopt()");
        return -1;
    }

    return 0;
}

/* 绑定socket描述符s到if_name指定的网卡
 * 绑定后写入到s的utx报文都通过该网卡发送出去
 */
int 
bindif (int s, const char *if_name)     //s=sockfd
{
    struct ifreq ifr;
    size_t if_name_len = strlen (if_name);
    if (if_name_len < sizeof (ifr.ifr_name))
    {
        memcpy (ifr.ifr_name, if_name, if_name_len);
        ifr.ifr_name[if_name_len] = 0;
    }
    else
    {
        printf("bindif(), interface name too long\n");
        return -1;
    }
    if (ioctl (s, SIOCGIFINDEX, &ifr) == -1)
    {
        perror ("ioctl");
        return -1;
    }
    int ifindex = ifr.ifr_ifindex;

    struct sockaddr_ll addr = { 0 };
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_protocol = htons (ETH_P_ALL);

    if (bind (s, (struct sockaddr *) &addr, sizeof (addr)) == -1)
    {
        perror ("bind");
        return -1;
    }

    return ifr.ifr_ifindex;
}

/* 与bindif功能相似
 * 除了绑定网卡外还额外填充sockaddr_ll信息,便于发送端后续的sendto()操作
 */
int bindif2 (
    int s, 
    const char *if_name, 
    struct sockaddr_ll *sadr_ll, 
    const unsigned char *rx_mac)
{
  int i;
  int ifindex;
  if ((ifindex = bindif(s, if_name)) < 0)
	return ifindex;

  sadr_ll->sll_ifindex = ifindex;
  sadr_ll->sll_halen = ETH_ALEN;
  for (i=0;i<6;++i) sadr_ll->sll_addr[i] = rx_mac[i];

  return ifindex;
}

int 
find_if_by_mac(
    int sock, 
    const unsigned char *mac, 
    char if_name[IFNAMSIZ])
{
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs()");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (AF_PACKET == ifa->ifa_addr->sa_family) {
            struct ifreq ifr;
            strcpy(ifr.ifr_name, ifa->ifa_name);
            if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                if (memcmp(mac, ifr.ifr_hwaddr.sa_data, 6) == 0) {
                    strcpy(if_name, ifa->ifa_name);
                    freeifaddrs(ifaddr);
                    return 0;
                }
            } else {
                perror("ioctl(SIOCGIFHWADDR):");
            }
        }
    }

    freeifaddrs(ifaddr);
    return -1;
}

int 
list_if_macs(char *buf, int buf_len)
{
    if (buf_len < 13) 
        return 0;

    int sock;
	if ((sock = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_UTX))) < 0) {
		perror ("socket():");
        return -1;
	}

    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs()");
        return -1;
    }

    int bytes = 0;
    int i;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (AF_PACKET == ifa->ifa_addr->sa_family) {
//printf("if_name=%s\n", ifa->ifa_name);
            if (memcmp(ifa->ifa_name, "lo", 2) == 0) {
                continue;
            }
            struct ifreq ifr;
            strcpy(ifr.ifr_name, ifa->ifa_name);
            if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                for (i=0;i<6;++i) {
                    sprintf(buf+bytes+2*i,"%02x", ifr.ifr_hwaddr.sa_data[i]);
                }
                bytes += 12;
                if (buf_len < bytes+13)
                    break;
            } else {
                perror("ioctl(SIOCGIFHWADDR):");
                freeifaddrs(ifaddr);
                close(sock);
                return -1;
            }
        }
    }

//printf("uid=%s\n", buf);
    freeifaddrs(ifaddr);
    close(sock);
    return bytes;
}

void 
init_ethhdr(struct ethhdr *eth, const unsigned char *tx_mac, const unsigned char *rx_mac)
{
  int i;
  for (i=0;i<6;++i) eth->h_source[i] = tx_mac[i];
  for (i=0;i<6;++i) eth->h_dest[i] = rx_mac[i];
  eth->h_proto = htons(ETH_P_UTX);
}

inline uint64_t
get_file_size(const char *filepath)
{
	struct stat st;
  if (stat (filepath, &st) == -1)
    {
      printf ("can't find file %s\n", filepath);
      return 0;
    }

	return st.st_size;
}

static 
struct UtxSender * 
_malloc_utx_sender() 
{
    struct UtxSender * us = (struct UtxSender *)malloc(sizeof(struct UtxSender));
    if (NULL == us) {
        return NULL;
    }
    if (NULL == (us->packet = malloc(tx_mtu))) {
        return NULL;
    }

    return us;
}

static
void
_free_utx_sender(struct UtxSender * us) 
{
    if (NULL != us) {
        if (NULL != us->packet) {
            free(us->packet);
        }
        free(us);
    }
}

unsigned int
utx_set_tx_mtu(unsigned int mtu)
{
    unsigned int old_tx_mtu = tx_mtu;
    tx_mtu = mtu;
    return old_tx_mtu;
}

unsigned long long
utx_set_tx_busy_sleep_nanos(unsigned long long nanos)
{
    unsigned long long old_nanos = tx_busy_sleep_nanos;
    tx_busy_sleep_nanos = nanos;
    return old_nanos;
}

unsigned long long 
utx_init_sender (const char *tx_mac, const char *rx_mac, unsigned int bloc_size)
{
    unsigned char tx_mac_bytes[6];
    unsigned char rx_mac_bytes[6];

    if (parse_mac(tx_mac, tx_mac_bytes) < 0) {
        printf("invalid tx_mac parameter.");
        return 0;
    }

    if (parse_mac(rx_mac, rx_mac_bytes) < 0) {
        printf("invalid rx_mac parameter.");
        return 0;
    }

    struct UtxSender *us = _malloc_utx_sender();
    if (NULL == us) {
        printf("malloc() failed.");
        return 0;
    }

    us->bloc.bloc_size = bloc_size;

	if ((us->socket_fd = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_UTX))) < 0) {
        _free_utx_sender(us);
		perror ("socket():");
        return 0;
	}

    char if_name[IFNAMSIZ];
    if (find_if_by_mac(us->socket_fd, tx_mac_bytes, if_name) < 0) {
        _free_utx_sender(us);
        printf("find_if_by_mac('%s') failed\n", tx_mac);
        return 0;
    }

    if (bindif2(us->socket_fd, if_name, &us->sadr_ll, rx_mac_bytes) < 0) {
        _free_utx_sender(us);
		perror ("bindif2:");
        return 0;
	}

	init_ethhdr((struct ethhdr *)us->packet, tx_mac_bytes, rx_mac_bytes);
    int i;
    for (i=0; i<256; ++i) us->utx_seq[i] = 0;
    us->utx_counter = 0;

    //set nonblocking
    int flags = fcntl(us->socket_fd, F_GETFL);
    if (flags < 0) {
        perror("fcntl(F_GETFL) failed");
        return 0;
    }
    if (fcntl(us->socket_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl(F_SETFL, O_NONBLOCK) failed");
        return 0;
    }

    //set sndbuf_size
    unsigned int sndbuf_size = 10*1024*1024;
    if (setsockopt(us->socket_fd, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf_size, sizeof(sndbuf_size)) < 0) {
        perror("setsockopt(SO_SNDBUFFORCE) failed");
        return 0;
    }

    printf("utx_init_sender(), handle=%p\n", us);
    return (unsigned long long )us;
}

void utx_drop_sender (unsigned long long handle)
{
    struct UtxSender * us = (struct UtxSender *)handle;
    printf("drop_utx_sender(), handle=%p\n", us);
    _free_utx_sender(us);
}

/*
 * return 0 if success
 * return -1 if fail
 */
int utx_send_buf (
    unsigned long long handle,
    int channel,
    const char * buf,
    unsigned int len,
    unsigned char type,
    int header_bit,
    int packet_opt)
{
    struct UtxSender * us = (struct UtxSender *)handle;
	struct utxhdr *utx = (struct utxhdr *) (us->packet + ETHHDR_SIZE);
	unsigned char *payload = us->packet + ETHHDR_SIZE + UTXHDR_SIZE;
	int payload_capacity = tx_mtu - (ETHHDR_SIZE + UTXHDR_SIZE); 
    
    utx->type = type,
    utx->head = header_bit;
    utx->tail = 0;
    utx->packet_head = 1;
    utx->packet_opt = packet_opt;

    int left = len; //number of bytes left unsent in the buf;
    int sent = 0; //number of bytes already sent out
    while (left > 0) {
        utx->packet_tail = (left <= payload_capacity);
        int n = left <= payload_capacity ? left : payload_capacity;
    
        memcpy(payload , buf+sent, n);
        utx->len = UTXHDR_SIZE + n;
        utx->channel = channel;
        utx->seq = us->utx_seq[channel]++;
        utx->check = 0;
        utx->check = checksum(us->packet, ETHHDR_SIZE+utx->len);

retry:
        if (sendto (us->socket_fd, (char *) us->packet, ETHHDR_SIZE+utx->len, 0,
                        (struct sockaddr *) &us->sadr_ll,
                        (socklen_t) sizeof (struct sockaddr_ll)) < 0)
        {
            if (errno == EWOULDBLOCK || errno == ENOBUFS) {
                printf("utx_send_buf: sending buffer's full, wait some time...\n");
                usleep(1000);
                goto retry;
            }
            else {
                perror ("utx_send_buf: sendto() error:");
                return -1;
            }
        }

        left -= n;
        sent += n;
        utx->head = 0;
        utx->packet_head = 0;

        if (us->utx_counter++ % 1000 == 0) {
            usleep(10000);
        }
    }

    return 0;
}

/*
 * return 0 if success
 * return -1 if fail
 */
int utx_send_a_file (
    unsigned long long handle,
    int channel,
    const char *root_path,
    const char *filename_of_relative_path,
    unsigned long long *_fsize,
    int *_errno)
{
    if (channel < 0 || channel > 255)
        return -1;

	char pathname[1024];
	strncpy (pathname, root_path, sizeof (pathname));
    strncat (pathname, "/", 1);
	strncat (pathname + strlen (pathname), filename_of_relative_path,
			UTX_FILENAME_MAXLEN);

    uint64_t fsize = get_file_size(pathname);
    *_fsize = fsize;

    struct UtxSender * us = (struct UtxSender *)handle;
	struct utxhdr *utx = (struct utxhdr *) (us->packet + ETHHDR_SIZE);
	unsigned char *payload = us->packet + ETHHDR_SIZE + UTXHDR_SIZE;
	int payload_capacity = tx_mtu - (ETHHDR_SIZE + UTXHDR_SIZE); 

	//initialize file header(filehdr_t) for the first packet
	struct filehdr_t *fh = (struct filehdr_t *)payload;
	strncpy (fh->filename, filename_of_relative_path, UTX_FILENAME_MAXLEN);
	strncpy (fh->username, "anonymous", 65); //dodo
	fh->filesize = fsize;
	fh->size_valid = 1;
	fh->md5_valid = 0;

	int fd = open (pathname, O_RDONLY);
	if (fd < 0) {
        *_errno = errno;
		perror ("open file error");
		return -1;
	}

	utx->type = UTX_TYPE_FILE;
	utx->channel = channel;
	utx->head = 1;
	utx->tail = 0;

	int offset = sizeof(struct filehdr_t);

	int nread, nread_total = 0;
	int nsend, nsend_total = 0;
	unsigned int count = 0;
	int retval = 0;		//sucess assumed 
	while ((nread = read (fd, payload + offset, payload_capacity - offset)) >= 0)
	{
		nread_total += nread;
		utx->len = UTXHDR_SIZE + offset + nread;
		utx->tail = (nread < (payload_capacity - offset));
        utx->seq = us->utx_seq[channel]++;
        utx->check = 0;
        utx->check = checksum(us->packet, ETHHDR_SIZE+utx->len);
/*
char _tmp[10240];
memcpy(_tmp, payload+offset, nread);
_tmp[nread] = '\0';
printf("seq=%d,content=%s\n", utx->seq, _tmp);
*/
retry:
        nsend = sendto (us->socket_fd, (char *) us->packet, ETHHDR_SIZE+utx->len, 0,
						(struct sockaddr *) &us->sadr_ll,
						(socklen_t) sizeof (struct sockaddr_ll)); 
        if (nsend < 0) {
            if (errno == EWOULDBLOCK || errno == ENOBUFS) {
                printf("utx_send_a_file: sending buffer's full, wait some time...\n");
                usleep(1000);
                goto retry;
            }
            else {
                *_errno = errno;
			    perror ("utx_send_a_file: sento() error:");
			    retval = -1;
			    break;
            }
        }

		nsend_total += nsend;

		if (utx->tail) {
			close (fd);
            fd = -1;
			break;
		}

		offset = 0;
		utx->head = 0;
		count++;

        //traffic control
		if (count % 1000 == 0) {
            static struct timespec time_to_sleep;
            time_to_sleep.tv_sec = 0;
            time_to_sleep.tv_nsec = tx_busy_sleep_nanos;
            nanosleep(&time_to_sleep, NULL);
		}
	}
    if (fd != -1) close(fd);
	return retval;
}

static 
void reset_bloc(
    struct UtxSender * us, 
    const char * root_path, 
    const char * filename)
{
    if (us->bloc.bloc_fd != -1) {
        close(us->bloc.bloc_fd);
        us->bloc.bloc_fd = -1;
    }
    us->bloc.bloc_seq = 0;
    strncpy(us->bloc.bloc_name, root_path, UTX_FILENAME_MAXLEN);
    strcat(us->bloc.bloc_name, "/.sent/");
    strncat(us->bloc.bloc_name, filename, UTX_FILENAME_MAXLEN);
}

int utx_send_bloc_header (
    unsigned long long handle,
    int channel,
    const char * root_path,
    const char * filename)
{
    struct UtxSender * us = (struct UtxSender *)handle;
    reset_bloc(us, root_path, filename);

    char buf[512];
    struct filehdr_t *fh = (struct filehdr_t *)buf;
    strncpy(fh->filename, filename, UTX_FILENAME_MAXLEN);
    strncpy(fh->username, "anonymous", 65);
    fh->filesize = 0;
    fh->size_valid = 0;
    fh->md5_valid = 0;
    return utx_send_buf(handle, channel, buf, sizeof(struct filehdr_t), UTX_TYPE_BLOCK, 1, UTX_OPT_STREAM);
}

/*
 * return 0 if success
 * return -1 if fail
 */
int utx_send_datagram (
    unsigned long long handle,
    int channel,
    const char * buf,
    unsigned int len)
{
    if (channel < 0 || channel > 255)
        return -1;

    struct UtxSender * us = (struct UtxSender *)handle;
	struct utxhdr *utx = (struct utxhdr *) (us->packet + ETHHDR_SIZE);
	unsigned char *payload = us->packet + ETHHDR_SIZE + UTXHDR_SIZE;
	int payload_capacity = tx_mtu - (ETHHDR_SIZE + UTXHDR_SIZE); 
    
    utx->type = UTX_TYPE_DATAGRAM;
    utx->channel = channel;

    int head = 1; //head bit for the utx
    int tail = 0; //tail bit for the utx
    int left = len;
    int sent = 0;
    while (left > 0) {
        tail = (left <= payload_capacity);
        int ns = tail ? left : payload_capacity;

        memcpy(payload , buf+sent, ns);
        utx->len = UTXHDR_SIZE + ns;
        utx->seq = us->utx_seq[channel]++;
        utx->head = head;
        utx->tail = tail;
        utx->check = 0;
        utx->check = checksum(us->packet, ETHHDR_SIZE+utx->len);
retry:
        if (sendto (us->socket_fd, (char *) us->packet, ETHHDR_SIZE+utx->len, 0,
                (struct sockaddr *) &us->sadr_ll,
                (socklen_t) sizeof (struct sockaddr_ll)) < 0)
        {
            if (errno == EWOULDBLOCK || errno == ENOBUFS) {
                printf("utx_send_datagram: sending buffer's full, wait some time...\n");
                usleep(1000); //todo
                goto retry;
            }
            else {
                //perror ("utx_send_datagram: sendto() error:");
                return -1;
            }
        }

        left -= ns;
        sent += ns;
        head = 0;
    }

    return 0;
}

/*
 * return 0 if success
 * return -1 if fail
 */
int utx_send_agent (
    unsigned long long handle,
    int channel,
    const char * buf,
    unsigned int len)
{
    if (channel < 0 || channel > 255)
        return -1;

    struct UtxSender * us = (struct UtxSender *)handle;
	struct utxhdr *utx = (struct utxhdr *) (us->packet + ETHHDR_SIZE);
	unsigned char *payload = us->packet + ETHHDR_SIZE + UTXHDR_SIZE;
	int payload_capacity = tx_mtu - (ETHHDR_SIZE + UTXHDR_SIZE); 
    
    utx->type = UTX_TYPE_AGENT;
    utx->channel = channel;

    int head = 1; //head bit for the utx
    int tail = 0; //tail bit for the utx
    int left = len;
    int sent = 0;
    while (left > 0) {
        tail = (left <= payload_capacity);
        int ns = tail ? left : payload_capacity;

        memcpy(payload , buf+sent, ns);
        utx->len = UTXHDR_SIZE + ns;
        utx->seq = us->utx_seq[channel]++;
        utx->head = head;
        utx->tail = tail;
        utx->check = 0;
        utx->check = checksum(us->packet, ETHHDR_SIZE+utx->len);
retry:
        if (sendto (us->socket_fd, (char *) us->packet, ETHHDR_SIZE+utx->len, 0,
                (struct sockaddr *) &us->sadr_ll,
                (socklen_t) sizeof (struct sockaddr_ll)) < 0)
        {
            if (errno == EWOULDBLOCK || errno == ENOBUFS) {
                printf("utx_send_agent: sending buffer's full, wait some time...\n");
                usleep(1000); //todo
                goto retry;
            }
            else {
                return -1;
            }
        }

        left -= ns;
        sent += ns;
        head = 0;
    }

    return 0;
}

static int write_block(
    struct UtxSender *us,
    const char *buf, 
    int size)
{
	if (size<=0) return -1;

	if (us->bloc.bloc_fd < 0) {
		//switch to a new block file;
		char fname[1024]; 
		snprintf(fname, sizeof(fname), "%s-%04d", us->bloc.bloc_name, us->bloc.bloc_seq);
		us->bloc.bloc_fd = open (fname, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (us->bloc.bloc_fd <0) {
            printf("open('%s') failed\n", fname);
			perror("open()");
			return -1;
		}
		//us->bloc.bloc_left = 81920;
		us->bloc.bloc_left = us->bloc.bloc_size;
	}

	if (size < us->bloc.bloc_left) {
		write(us->bloc.bloc_fd, buf, size);
		us->bloc.bloc_left -= size;
	}
	else {
		int nwrite = us->bloc.bloc_left;
		write(us->bloc.bloc_fd, buf, us->bloc.bloc_left);
        close(us->bloc.bloc_fd); //current block is full
		us->bloc.bloc_fd = -1;
		us->bloc.bloc_seq = (us->bloc.bloc_seq+1) % 1000;

		if (size > nwrite) {
		     write_block(us, buf+nwrite, size-nwrite);
		}
	}

    return 0;
}

int utx_send_bloc_buf (
    unsigned long long handle,
    int channel,
    const char * buf,
    unsigned int len,
    int header_bit,
    int packet_opt)
{
    struct UtxSender * us = (struct UtxSender *)handle;
    write_block(us, buf, len);
    return utx_send_buf(handle, channel, buf, len, UTX_TYPE_BLOCK, header_bit, packet_opt);
}

int btx_send_tcp_buf(
    unsigned long long handle,
    int channel,
    unsigned short session_id,
    unsigned char btx_type,
    int head_bit,
    int tail_bit,
    unsigned short *this_seq,
    const char * buf,
    unsigned int len)
{
    struct UtxSender * us = (struct UtxSender *)handle;
	struct utxhdr *utx = (struct utxhdr *) (us->packet + ETHHDR_SIZE);
	unsigned char *payload = us->packet + ETHHDR_SIZE + UTXHDR_SIZE;
	int payload_capacity = tx_mtu - (ETHHDR_SIZE + UTXHDR_SIZE); 

    utx->channel = channel;
    utx->session_id = session_id,
    utx->type = btx_type,
    utx->head = head_bit;
    utx->tail = tail_bit;

    int left = len; //number of bytes left unsent in the buf;
    int sent = 0;   //number of bytes already sent out
    do {
        int n = left <= payload_capacity ? left : payload_capacity;
        if (n > 0)
            memcpy(payload , buf+sent, n);

        utx->len = UTXHDR_SIZE + n;
        utx->seq = (*this_seq)++;
        utx->check = 0;
        utx->check = checksum(us->packet, ETHHDR_SIZE+utx->len);

retry:
        if (sendto (us->socket_fd, (char *) us->packet, ETHHDR_SIZE+utx->len, 0,
                        (struct sockaddr *) &us->sadr_ll,
                        (socklen_t) sizeof (struct sockaddr_ll)) < 0)
        {
            if (errno == ENOBUFS) {
                printf("btx_send_tcp_buf: sending buffer's full, wait some time...\n");
                usleep(100000);
                goto retry;
            }
            else {
                perror ("utx_send_buf: sendto() error:");
                return -1;
            }
        }

        left -= n;
        sent += n;
        utx->head = 0;

        if (us->utx_counter++ % 1000 == 0) {
            usleep(10000);
        }
    } while (left > 0);

    return 0;
}

