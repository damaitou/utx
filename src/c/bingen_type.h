#ifndef _UTX_H
#define _UTX_H

#define UTX_FILENAME_MAXLEN 256 //filename length limit, same to linux limit

//network layer, replacement of ip
//UTX = unidirectional transmission
//len 长度,包括utxhdr以及其后的包体(payload)的总长度
//abort 紧急停止,传输过程中出现需要紧急停止的情况,tx端发送abort=1的包,rx端收到后终止当前文件传输
//tail 指示这是当前文件的最后一个包
//head 指示这是当前文件的第一个包
//seq 序列号,在一个文件或者一个报文过程中，从0到2^16-1范围内循环
//check utxhdr的校验码
//type 包类型,参考UTX_TYPE_XXX定义
//channel 通道编码,从0到255.也就是说每一种type下,最多可以支持256个通道
struct utxhdr
{
  //unsigned short int len:14, tail:1, head:1;
  unsigned short int len:13, abort:1, tail:1, head:1;
  unsigned short int seq;
  unsigned short check;
  unsigned char type;
  unsigned char channel;
  int instance; //in case of multiple concurrent for one channel
  int cliaddr;  //for rx to know which client to deal with (client->txhost->rxhost->server)
};

struct filehdr_t
{
  	unsigned short int reserved:14, size_valid:1, md5_valid:1;
	unsigned long long filesize; //size of file
	char md5sum[33]; //32 bytes md5sum of the file, null-terminated;
	char filename[UTX_FILENAME_MAXLEN]; //name of file
	char username[65]; //64 bytes username, null-terminted
};

void handle_utx (struct utxhdr *utx, char *payload, unsigned int payload_size);

#endif

