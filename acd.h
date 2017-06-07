#ifndef _ACD_H
#define _ACD_H

#include <stdio.h>
#include "random.h"
#include "sproto.h"
#include "rw.h"
#include "info.h"
#include "station.h"

#define AP_LIST_FILE        	"/etc/aplist"
#define TP_LIST_FILE			"/etc/tplist"
#define APC_SP_FILE				"/usr/share/apc.sp"
#define AC_DNS_DOMAIN  			"www.morewifi.ac.com"
#define DEFAULT_DEVICE_IP		"192.168.33.111"

#define ONE_SECOND			1000
#define DNS_SET_INTERVAL	30*ONE_SECOND
#define HEAR_BEAT_INTEVAL	30*ONE_SECOND
#define STATION_STATUS_CHECK_INTERVAL 180*ONE_SECOND

#define set_bit(x,y) 		x = x | (0x1<<y)
#define clear_bit(x,y)		x = x & (~(0x1<<y))

extern tmplat_list 	*tplist;
extern ap_list 		aplist;
extern sta_list 	stalist;
extern u32 		ap_listdb_salt;
extern u32 		sta_listdb_salt;

int is_digit_string(char * string);
void print_debug_log (const char *form, ...);
void fill_data(ap_status_entry *apcfg, char *tagname, char *value, int len);
void fill_encode_data(ap_status_entry *apcfg, char *tagname, char *value);
void format_ap_cfg(ap_status_entry *apinfo, char *res);
void format_tmp_cfg (tmplat_list * tpcfg, char *res);
void free_mem(ap_status_entry *ap);
int sproto_read_entity (char *filename);
int sproto_encode_data (struct encode_ud *ud, char *res);
int proc_tmplate_info (tmplat_list * tpcfg, struct ubus_request_data *req);
int send_data_to_ap (ap_status_entry * ap);
int rcv_and_proc_data (char *data, int len, struct client *cl);
int ap_online_proc (ap_status_entry * ap, int sfd, struct sockaddr_in *localaddr);
void aplist_entry_init(ap_status_entry aplist_node);
void stalist_entry_init(sta_entry stalist_node);
int stalist_hash_init(void);
int aplist_hash_init(void);

extern void gettime(struct timeval *tv);

#endif


