#ifndef _INFO_H
#define _INFO_H

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
#include <uci.h>
#include <libubus.h>
#include <libubox/ustream.h>
#include <libubox/uloop.h>
#include <libubox/usock.h>
#include <libubox/blobmsg_json.h>
#include "list.h"

#ifndef TRUE
	#define TRUE                1
#endif

#ifndef FALSE
	#define FALSE               0
#endif

#define SIZEOF_LENGTH 		4
#define ENCODE_BUFFERSIZE 	2050
#define ENCODE_MAXSIZE		0x1000000
#define ENCODE_DEEPLEVEL 	64
#define BUFLEN 			    1024 * 2
#define TEMP_SSID_BUF_SIZE  512
#define INET_ADDRSTRLEN 	16
#define AP_STATUS		    1
#define AP_INFO			    2
#define AP_CMD			    3
#define STA_INFO			4
#define AC_INFO				5
#define RESPONSE_ERROR		0
#define RESPONSE_PACK	  	0
#define RESPONSE_OK		    1
#define ON			        1
#define OFF			        0
#define REBOOT  		    1
#define UPGRADE			    2
#define AP_HASH_SIZE 		(1<<8)
#define MAC_LEN			    100
#define ETH_ALEN            6
#define AP_MAX_BINDID       8
#define ILLEGAL_TMPLATE_ID  -1
#define DEFAULT_TMPLATE_ID  0
#define DEFAULT_TMPLATE_ID_MAP 0x07

#define MAX_SSID_LEN        32
#define MAX_TMP_ID          7
#define AC_INIT_OFFLINE     0
#define AC_NEW_HASH_NODE    1
#define AC_AP_HASH_NODE_ON  2
#define AP_CMD_SENDED_FLAG  1
#define IS_DIGIT_STRING     0
#define IS_DIGIT_STRING_ERR 1     

#define WIFI_SIGNAL_TYPE_2_4 	0
#define WIFI_SIGNAL_TYPE_5G		1
#define WIFI_SIGNAL_ENABLE_AUTH		1
#define WIFI_SIGNAL_ENABLE_UNAUTH	0

#define STATION_NEW				1
#define STATION_EXIST			2
#define STATION_AUTH_INIT		0
#define STATION_AUTH_GUEST		1
#define STATION_AUTH_AUTH		2

#define DEFAULT_FD				-1

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
	HIDDEN,
	DISABLED,
	TYPE,
	AUTH,
    MODEL,
	DEBUG,
    __CFG_MAX
};

enum {
    APINFO_MAC,
    __APINFO_MAX
};

enum {
    STAMAC,
    __STA_MAX
};


struct sproto_type {
    const char * name;
    int n;
    int base;
    int maxn;
    struct field *f;
};

struct field {
    int tag;
    int type;
    const char * name;
    struct sproto_type * st;
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
    struct sockaddr_in localaddr;

    struct ustream_fd s;
    int ctr;
};

typedef struct {
    char ssid[33];					//AP 对应的ssid
    char key[33];					//AP 对应无线密码
    char encrypt[33];				//AP 对应的无线加密方式
	char hidden;					//hidden wireless signal;0:disable;1:enable
	char disabled;					//disable the wireless signal;0:disable;1:enable
	char type;						//wireless type 0:2.4G;1:5G
	char auth;						//enable auth;0:disable;1:enable
}ap_ssid_info;

typedef struct  {
    char channel[16];					//AP 对应的无线信道
    char txpower[16];					//AP 对应无线的功率
    ap_ssid_info ssid_info[8];			//auth or custom define template
}ap_wifi_info;

typedef struct ap_info {
    unsigned char id;					//表示对应认证、自定义模板id
    char hver[32];					    //AP 对应的硬件版本号
    char sver[32];					    //AP 对应的软件版本号	
    char rip[16];					    //AP ac 服务器的ip地址
    char aip[16];					    //AP 自身的ip 地址	
    unsigned char apmac[6];				//AP 对应AP的mac 地址
    char sn[64];					    //AP 对应设备的sn 序号
    char model[32];					    //AP 对应设备的型号
    ap_wifi_info wifi_info;
}ap_sys_info;

typedef struct {
    char	addr[32];
    char	md5[36];
    int 	cmd;
    int		status;
}ap_cmd;

typedef struct encode_ud {
    int	type;
    int session;
    int ok;
}ecode_ud_spro;

typedef struct {
	int		fd;
    char	sn[32];
	char 	dt;
	char	moid[32];
	char 	product[32];
	ecode_ud_spro 	ud;
}device_info;

typedef struct {
    struct hlist_node	hlist;
    unsigned char 		mac[6];               //station mac address;
    unsigned char 		ap_mac[6];            //ap device mac address;
	unsigned char 		bssid[6];			  //bssid of station wifi connect
	unsigned char 		status;				  //1:on;0:off
	unsigned char 		type;				  //1:5G;0:2.4G
	unsigned char 		auth;				  //0:默认初始值；1:访客用户；2:认证用户
	unsigned char 		ssid[64];
    char 				ip[16];
    char 				name[64];
	unsigned char 		exist_flag;			  //0:默认初始值；1：新建hash node；2：已建立的hashnode;
	ecode_ud_spro 		ud;
    struct timeval 		time_stamp;
}sta_entry;

typedef struct {
    struct hlist_node	hlist;
    
    char 	status;					    //用来处理是否走上线流程,0：ac 初始化时，未上线；1：新建hash node；2：上线
    char 	online;					    //标识ap 设备是否在线
    
    int		fd;
    int 	apid;					    //用于标示 在aplist 文件中ap_cfg_x 的number
	unsigned int 	sta_num;			//用于标示ap 上总用户数
	unsigned int	sta_2G_num;			//用于标示ap 上2.4G用户数
	unsigned int 	sta_5G_num;			//用于标示ap 上5G用户数
	unsigned int 	sta_guest_num;		//用于标示ap 访客网络的用户数
	unsigned int 	sta_guest_2G_num;	//用于标示ap 访客网络的2.4G用户数
	unsigned int 	sta_guest_5G_num;	//用于标示ap 访客网络的5G用户数
    
    ap_cmd 			    cmd;
    ecode_ud_spro 		ud;
    ap_sys_info 		apinfo;
    struct timeval 		last_tv;
    struct client 		*client_addr;
    char			    apname[128];    //AP 别名
}ap_status_entry;

typedef struct {
    struct hlist_head		hash[AP_HASH_SIZE];
}ap_list;

typedef struct {
    struct hlist_head		hash[AP_HASH_SIZE];
}sta_list;

typedef struct {
    char 	tpname[64];
    unsigned char	id;				    //模板id号
    ap_ssid_info tmplat_ssid_info;
}tmp_info;

typedef struct tmplat_list
{
    tmp_info tmplate_info;
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

#endif
