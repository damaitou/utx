#include "ethers.h"
#include "utx.h"
#include "file.h"
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include "rxparam.h"
#include "log.h"
#include "audit.h"

using namespace std;

unsigned long lost = 0;
unsigned long count = 0;
unsigned long long nrecv = 0;

int
ensure_path (const char *filename)
{
  char fullpath[1024];
  const char *p1 = filename, *p2 = filename;

  fullpath[0] = '\0';		//importan
  while (1)
    {
      while (*p2 != '\0' && *p2 != '/')
	p2++;

      if (*p2 == '/')
	{
	  strncat (fullpath, p1, p2 - p1 + 1);
	  //printf ("fullpath=%s\n", fullpath);
	  DIR *dir = opendir (fullpath);
	  if (dir)
	    {
	      closedir (dir);	//directory already exists
	    }
	  else if (ENOENT == errno)	//directory not exists, create it
	    {
	      if (mkdir (fullpath, 0755) < 0)
		{
		  perror ("mkdir()");
		  return -1;
		}
	    }

	  p2++;
	  p1 = p2;
	}
      else if (*p2 == '\0')
	break;
    }

  return 0;
}

void do_rx_file_audit(
        struct rxfc_t *fc,
	//struct filehdr_t *fh,
        audit_result _r,
        const char *_msg)
{
	static file_audit_t fa;
        char buf[1024];

        fa.channel = fa.channel;
        fa.side = AS_RX;
        fa.event = AE_RX_FERRY;
        fa.peer_ip = "";
        fa.user = fc->fhdr.username;
        fa.filename = fc->fhdr.filename;
        fa.filesize = fc->fhdr.filesize;
        fa.result = _r;
        fa.result_msg = _msg ? _msg :"";

        fa.to_json(buf, sizeof(buf));
        printf("%s\n", buf);
}

void do_cleanup_file_not_ferried_right(rxfc_t *fc, struct filehdr_t *fh)
{
	close(fc->fd);
	fc->fd = 0;
	
	//todo:: warning to the system
	if (fh != NULL)
		do_rx_file_audit(fc,  AR_FAIL, "file no properly received");
}

void
handle_file (struct tpacket_hdr *tphdr, struct utxhdr *utx)
{
	static int fd;
	static char filepath[512];
	static struct filehdr_t *fh = NULL;

	struct rxfc_t *fc = rxp.fchannels[utx->channel];
	if (NULL == fc) {
		if (utx->head)
			log_warn ("file channel %d not configured.", utx->channel);
		return;
	}

	char *payload = (char *)utx + UTXHDR_SIZE;

	if (utx->head) //a new file comes
	{
		//last filed not ferried right, tail-packet lost
		if (fc->fd != -1) {
			do_cleanup_file_not_ferried_right(fc, fh);
			fh = NULL;
		}

		fh = (struct filehdr_t *)payload;
		if (fh->size_valid) {
			log_trace("new coming file=%s, size=%llu, user=%s", fh->filename, fh->filesize, fh->username);
		}

        memcpy(&fc->fhdr, fh, sizeof(struct filehdr_t));

		memset (filepath, 0, sizeof (filepath));
		strncpy (filepath, fc->path.c_str (), sizeof (filepath));
		strncat (filepath, fh->filename, UTX_FILENAME_MAXLEN);

		if ((fd = open (filepath, O_RDWR | O_CREAT | O_TRUNC, 0644)) <= 0)	//is O_TRUNC ok?
		{
			perror ("open file for write error");
			log_error ("fc %d: open() %s for write failed, try again...",
					utx->channel, filepath);
			if (errno == ENOENT)	//directorys not exists, creates them
			{
				ensure_path (filepath);
			}
			if ((fd = open (filepath, O_RDWR | O_CREAT | O_TRUNC)) <= 0)
			{
				perror ("(2nd) open file for write error");
				log_error
					("fc %d: open() %s for write failed again, abort this file.",
					 utx->channel, filepath);
				return;
			}
		}
		log_info ("file channel %d: new incoming file '%s'", utx->channel, filepath);

		lost = 0;
		count = 0;

		fc->fd = fd;
		fc->seq = utx->seq; //should be 0
	}
	else
	{
		if (fc->fd < 0) {
			return;		//no file_session found, no way to write to file, drop the packet;
		}

		int diff = utx->seq - fc->seq;
		if (diff < 0)
		{
			diff += ((1 << 16));
		}
		if (diff != 1)
		{
			lost += (diff - 1);
			log_warn("handle_file(): seq jump from %u to %u, lost %d packets.", 
                fc->seq, utx->seq, utx->seq - fc->seq);
		}

		fc->seq = utx->seq;
	}

	count++;
	if (count % 100000 == 0) {
		printf ("count=%u,lost=%u\n", count, lost);
	}

	int offset = utx->head ? sizeof (struct filehdr_t) : 0;
	nrecv += utx->len - UTXHDR_SIZE - offset;

	if (write (fc->fd, payload + offset, utx->len - UTXHDR_SIZE - offset) < 0) {
		perror ("write file error");
		log_error ("file_channel_%d: write file error.", utx->channel);
	}

	if (utx->tail) {
		log_info ("file_channel_%d: '%s'(%llu) recv ok.", utx->channel, filepath, nrecv);
		close (fc->fd);
		fc->fd = -1;
		nrecv = 0;
		do_rx_file_audit(fc, AR_SUCCESS, NULL);
	}
}

