#ifndef _STATION_H
#define _STATION_H

#include <uci.h>
#include "info.h"
#include "rw.h"

#define STATION_ON			1
#define STATION_OFF			0

#define GUEST_LIST_MAC			"WhiteList_wifi_src"
#define FIREWALL_CONFIG_FILE	"/etc/config/firewall"
#define WIRELESS_GUEST_PATH		"/etc/firewall.guest"

extern sta_entry *stalist_entry_update(sta_entry *sta_info);
extern void sta_noauth_init();
extern int ipset_del(u8_t *addr,char *name_entry);
extern int ipset_add(u8_t *addr,char *name_entry);
#endif
