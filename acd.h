#ifndef _ACD_H
#define _ACD_H

#include <stdio.h>
#include "random.h"
#include "sproto.h"
#include "rw.h"
#include "info.h"

#define AP_LIST_FILE        	"/etc/aplist"
#define TP_LIST_FILE		"/etc/tplist"
#define APC_SP_FILE		"/usr/share/apc.sp"

extern tmplat_list *tplist;
extern ap_list aplist;
extern u32 ap_listdb_salt;

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

#endif


