#ifndef _UTX_H
#define _UTX_H

#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>     //ETH_P_ALL
#include <linux/if_packet.h>

//network layer, replacement of ip
//UTX:      abbreviation of Unidirectional Transmission
//len:      长度,包括utxhdr以及其后的包体(payload)的总长度
//abort:    紧急停止,传输过程中出现需要紧急停止的情况,tx端发送abort=1的包,rx端收到后终止当前文件传输
//tail:     指示这是当前文件的最后一个包
//head:     指示这是当前文件的第一个包
//seq:      序列号,在一个文件或者一个报文过程中，从0到2^16-1范围内循环
//check:    utxhdr的校验码
//type:     包类型,参考UTX_TYPE_XXX定义
//channel:  通道编码,从0到255.也就是说每一种type下,最多可以支持256个通道
struct utxhdr
{
  unsigned short int len:13, abort:1, tail:1, head:1;
  unsigned short int seq;
  unsigned short check;
  unsigned char type;
  unsigned char channel;
  unsigned int session_id:16, reserved: 12, packet_opt:2, packet_tail:1, packet_head:1; 
  int cliaddr;  //for rx to know which client to deal with (client->txhost->rxhost->server)
};

#define ETH_P_UTX 0x0900  //PRIVATE ETHERNET UTX PROTOCOL NUMBER

#define ETHHDR_SIZE sizeof(struct ethhdr)
#define IPHDR_SIZE sizeof(struct iphdr)
#define UTXHDR_SIZE sizeof(struct utxhdr)

#define UTX_TYPE_SYS 0      //for internal management use
#define UTX_TYPE_DATAGRAM 1
#define UTX_TYPE_BLOCK 2    //divide a ftp-file into many blocks to transfer
#define UTX_TYPE_FILE 3
#define UTX_TYPE_AGENT 4

#define BTX_TYPE_TCP_T2R 10         //from tx to rx
#define BTX_TYPE_TCP_R2T 11         //from tx to rx

//#define UTX_MAXLEN 8000		    //mtu
//#define UTX_MAXLEN 1500		    //mtu
#define UTX_FILENAME_MAXLEN 256 //filename length limit, same to linux limit

#define UTX_OPT_STREAM 0    //单向流模式,不分组
#define UTX_OPT_DATAGRAM 1  //单向报文模式,分组

struct filehdr_t
{
  	unsigned short int reserved:14, size_valid:1, md5_valid:1;
	unsigned long long filesize; //size of file
	char md5sum[33]; //32 bytes md5sum of the file, null-terminated;
	char filename[UTX_FILENAME_MAXLEN]; //name of file
	char username[65]; //64 bytes username, null-terminted
};
#define FILEHDR_SIZE sizeof(struct filehdr_t)

#endif

