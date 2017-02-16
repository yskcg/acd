#ifndef _RW_H
#define _RW_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "acd.h"
#include "jhash.h"


int write_apinfo(char *fname, char *tagname, char *value);
char *read_apinfo(char *fname, char *tagname, char *value);
void del_apinfo(char *fname, char *tagname);
ap_status_entry *aplist_entry_find(struct hlist_head *head, const unsigned char *addr，const char *sn);
ap_status_entry *aplist_entry_creat((struct hlist_head *head,ap_sys_info *p_ap_data));
int aplist_entry_insert(ap_sys_info *p_ap_data);
#endif


