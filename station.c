#include "station.h"

int ipset_add(u8_t *addr,char *name_entry)
{
	char shell_cmd[256] = {0};

	if (addr == NULL || name_entry == NULL){
		return -1;
	}

	sprintf(shell_cmd,"ipset add %s %02x:%02x:%02x:%02x:%02x:%02x\n",name_entry,addr[0]&0xff,addr[1]&0xff,addr[2]&0xff,addr[3]&0xff,addr[4]&0xff,addr[5]&0xff);
	print_debug_log("%s %d %s\n",__FUNCTION__,__LINE__,shell_cmd);
	system(shell_cmd);

	return 0;
}

int ipset_del(u8_t *addr,char *name_entry)
{
	char shell_cmd[256] = {0};
	if (addr == NULL || name_entry == NULL){
		return -1;
	}

	sprintf(shell_cmd,"ipset del %s %02x:%02x:%02x:%02x:%02x:%02x\n",name_entry ,addr[0]&0xff,addr[1]&0xff,addr[2]&0xff,addr[3]&0xff,addr[4]&0xff,addr[5]&0xff);
	system(shell_cmd);

	return 0;
}

void sta_noauth_init()
{
	system("lua /usr/lib/lua/sta_noauth_init.lua");
}

sta_entry *stalist_entry_update(sta_entry *sta_info)
{
	sta_entry *stalist_node = NULL;
	ap_status_entry *ap = NULL;
	struct hlist_head *head = NULL;
	int i;

	if(sta_info == NULL){
		return NULL;
	}
	
	stalist_node = stalist_entry_insert(sta_info->mac);
	
	if(stalist_node == NULL){
		return NULL;
	}

	/*find the ap */
	head = &aplist.hash[aplist_entry_hash(sta_info->ap_mac)];
	ap = aplist_entry_find(head,sta_info->ap_mac);
	if(ap == NULL ){
		return NULL;
	}else{
		memcpy(stalist_node->ap_mac,sta_info->ap_mac,ETH_ALEN);
	}

	memset(stalist_node->ssid,0,sizeof(stalist_node->ssid));
	memcpy(stalist_node->ssid,sta_info->ssid,sizeof(sta_info->ssid));
	memcpy(stalist_node->bssid,sta_info->bssid,ETH_ALEN);
	
	/*station online*/
	if(sta_info->status == STATION_ON ){
		if(sta_info->type){
			ap->sta_5G_num = ap->sta_5G_num +1;
		}else{
			ap->sta_2G_num = ap->sta_2G_num +1;
		}
		ap->sta_num = ap->sta_num +1;

		/*del first*/
		ipset_del(stalist_node->mac,GUEST_LIST_MAC);
		/*find the ssid ->templist id*/
		for (i = 0; i<=MAX_TMP_ID; i++){
			if(ap->apinfo.id & (0x01<<i)){
				if(ap->apinfo.wifi_info.ssid_info[i].auth == WIFI_SIGNAL_ENABLE_UNAUTH && \
				   strcmp((const char *)ap->apinfo.wifi_info.ssid_info[i].ssid,(const char *)stalist_node->ssid) == 0){
					/*add this station to the guest network*/
					ipset_add(stalist_node->mac,GUEST_LIST_MAC);
					print_debug_log("%s %d station %02x:%02x:%02x:%02x:%02x:%02x is online guest wifi!\n",__FUNCTION__,__LINE__,\
									stalist_node->mac[0]&0xff,stalist_node->mac[1]&0xff,stalist_node->mac[2]&0xff,\
									stalist_node->mac[3]&0xff,stalist_node->mac[4]&0xff,stalist_node->mac[5]&0xff);
					if(stalist_node->exist_flag == STATION_NEW || stalist_node->auth !=STATION_AUTH_GUEST ){
						/*sum the num of guest*/
						if(sta_info->type){
							ap->sta_guest_5G_num = ap->sta_guest_5G_num +1;
						}else{
							ap->sta_guest_2G_num = ap->sta_guest_2G_num +1;
						}
						ap->sta_guest_num = ap->sta_guest_num +1;
					}

					stalist_node->auth = STATION_AUTH_GUEST;
					break;
				}else if(ap->apinfo.wifi_info.ssid_info[i].auth == WIFI_SIGNAL_ENABLE_AUTH && \
				   strcmp((const char *)ap->apinfo.wifi_info.ssid_info[i].ssid,(const char *)stalist_node->ssid) == 0){
					stalist_node->auth = STATION_AUTH_AUTH;
					break;
				}
			}
		}
	}else if(sta_info->status == STATION_OFF ){
		ipset_del(stalist_node->mac,GUEST_LIST_MAC);
		print_debug_log("%s %d station %02x:%02x:%02x:%02x:%02x:%02x is leave wifi ,type %d,auth_type:%d !\n",__FUNCTION__,__LINE__,\
									stalist_node->mac[0]&0xff,stalist_node->mac[1]&0xff,stalist_node->mac[2]&0xff,\
									stalist_node->mac[3]&0xff,stalist_node->mac[4]&0xff,stalist_node->mac[5]&0xff,stalist_node->type,stalist_node->auth);
		if(stalist_node->type){
			if(ap->sta_5G_num >0){
				ap->sta_5G_num = ap->sta_5G_num -1;
			}
		}else{
			if(ap->sta_2G_num >0){
				ap->sta_2G_num = ap->sta_2G_num -1;
			}
		}

		if(ap->sta_num >0){
			ap->sta_num = ap->sta_num -1;	
		}

		/*for guest network station sum*/
		if(stalist_node->auth == STATION_AUTH_GUEST){
			/*sum the num of guest*/
			if(stalist_node->type){
				if(ap->sta_guest_5G_num >0){
					ap->sta_guest_5G_num = ap->sta_guest_5G_num - 1;
				}
			}else{
				if(ap->sta_guest_2G_num >0){
					ap->sta_guest_2G_num = ap->sta_guest_2G_num - 1;
				}
			}

			if(ap->sta_guest_num >0){
				ap->sta_guest_num = ap->sta_guest_num -1;
			}
		}
		
		stalist_node->auth = STATION_AUTH_INIT ;
		
	}

	stalist_node->status = sta_info->status;
	stalist_node->type = sta_info->type;
	
	return stalist_node;
}

