#ifndef _ACD_H
#define _ACD_H

#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <fcntl.h>
#include <stdio.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#ifdef MW200H
#include "libubus.h"
#include "libubox/ustream.h"
#include "libubox/uloop.h"
#include "libubox/usock.h"
#include "libubox/blobmsg_json.h"
#else
#include <uci.h>
#include <libubus.h>
#include <libubox/ustream.h>
#include <libubox/uloop.h>
#include <libubox/usock.h>
#include <libubox/blobmsg_json.h>
#endif
#include "sproto.h"
#include "rw.h"

#define SIZEOF_LENGTH 4
#define ENCODE_BUFFERSIZE 2050
#define ENCODE_MAXSIZE 0x1000000
#define ENCODE_DEEPLEVEL 64
#define BUFLEN 1024 * 2
#define INET_ADDRSTRLEN 16
#define AP_STATUS				1
#define AP_INFO				  2
#define AP_CMD					3
#define RESPONSE_ERROR	0
#define RESPONSE_PACK	  0
#define RESPONSE_OK		  1
#define ON						  1
#define OFF						  0
#define REBOOT  				1
#define UPGRADE				  2


#ifndef container_of
#define container_of(ptr, type, member)                                 \
        ({                                                              \
                const typeof(((type *) NULL)->member) *__mptr = (ptr);  \
                (type *) ((char *) __mptr - offsetof(type, member));    \
        })
#endif

enum ACd_msg_status {
	ACd_STATUS_OK,
	ACd_STATUS_REBOOT_OK,
	__ACd_STATUS_LAST
};


static struct ubus_context *ctx;
static struct blob_buf b;

enum {
	MAC,
	SN,
	TMPLATID,
	SSID,
	ENCRYPT,
	CHANNEL,
	KEY,
	TXPOWER,
	CMD,
	ADDR,
	NAME,
	ONLINE,
	HVER,
	SVER,
	AIP,
	RIP,
	LMAC,
	IPADDR,
	EDIT_FLAG,
	MODEL,
	__CFG_MAX
};

enum {
	STAMAC,
	__STA_MAX
};

struct field {
	int tag;
	int type;
	const char * name;
	struct sproto_type * st;
};

struct sproto_type {
	const char * name;
	int n;
	int base;
	int maxn;
	struct field *f;
};

struct protocol {
	const char *name;
	int tag;
	struct sproto_type * p[2];
};

struct chunk {
	struct chunk * next;
};

struct pool {
	struct chunk * header;
	struct chunk * current;
	int current_used;
};

struct sproto {
	struct pool memory;
	int type_n;
	int protocol_n;
	struct sproto_type * type;
	struct protocol * proto;
};

struct client {
	struct sockaddr_in sin;

	struct ustream_fd s;
	int ctr;
};

typedef struct ap_cfg_info
{
	char id[20],
	 		 ssid[200],
			 channel[5],
			 encrypt[50],
			 hver[30],
			 sver[30],
			 key[300],
			 rip[20],
			 aip[20],
			 txpower[5],
			 apmac[20],
			 sn[20],
			model[30];
}ApCfgInfo;

typedef struct
{
	char addr[50],
			 md5[36];
	int  cmd,
			 status;
}apcmd;

typedef struct encode_ud {
	int type,
	    session,
	    ok;
}EncdUd;

typedef struct ap_info
{
	int fd;
	bool online;
	struct timeval last_tv;
	int apid,
			len;
	char *stamac,
		 		apname[50];
	EncdUd ud;

	apcmd cmd;
	ApCfgInfo apinfo;
	struct client *cltaddr;
	struct ap_info *rlink;
	struct ap_info *llink;

}ap_list;

typedef struct tmplat_list
{
	char tpname[50],
			 ssid[50],
			 id[5],
			 encrypt[50],
			 key[30];
	struct tmplat_list *rlink;
	struct tmplat_list *llink;
}tmplat_list;


struct apinfo_request {
	struct ubus_request_data req;
	struct uloop_timeout timeout;
	int fd;
	int idx;
	char data[];
};

static const char *ap_cfg_opt[] = {
	"mac",
	"sn",
	"hver",
	"sver",
	"rip",
	"aip",
	"channel",
	"id",
	"key",
	"encrypt",
	"txpower",
	"name",
	"model",
	0};

#endif


