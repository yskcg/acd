#include "station.h"

static struct uci_context *ctx = NULL;

static int ipset_add(u8_t *addr,char *name_entry)
{
	char shell_cmd[256] = {0};

	if (addr == NULL || name_entry == NULL){
		return -1;
	}

	sprintf(shell_cmd,"ipset add WhiteList_wifi_src %2x:%2x:%2x:%2x:%2x:%2x\n",addr[0],addr[1],addr[2],addr[3],addr[4],addr[5]);
	print_debug_log("%s %d %s\n",__FUNCTION__,__LINE__,shell_cmd);
	system(shell_cmd);

	return 0;
}

static int ipset_del(u8_t *addr,char *name_entry)
{
	char shell_cmd[256] = {0};
	if (addr == NULL || name_entry == NULL){
		return -1;
	}
	sprintf(shell_cmd,"ipset del WhiteList_wifi_src %2x:%2x:%2x:%2x:%2x:%2x\n",addr[0],addr[1],addr[2],addr[3],addr[4],addr[5]);
	print_debug_log("%s %d \n",__FUNCTION__,__LINE__);
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
	
	//if(stalist_node->ssid != NULL && strcmp((const char *)stalist_node->ssid ,(const char *)sta_info->ssid) != 0 ){
		//ipset_del(stalist_node->mac,GUEST_LIST_MAC);
	//}
	ipset_del(stalist_node->mac,GUEST_LIST_MAC);
	
	memset(stalist_node->ssid,0,sizeof(stalist_node->ssid));
	memcpy(stalist_node->ssid,sta_info->ssid,sizeof(sta_info->ssid));
	memcpy(stalist_node->bssid,sta_info->bssid,ETH_ALEN);
	
	/*station online*/
	if(sta_info->status == STATION_ON ){
		/*find the ssid ->templist id*/
		for (i = 0; i<=MAX_TMP_ID; i++){
			if(ap->apinfo.id & (0x01<<i)){
				if(ap->apinfo.wifi_info.ssid_info[i].auth == WIFI_SIGNAL_DISABLE && \
				   strcmp((const char *)ap->apinfo.wifi_info.ssid_info[i].ssid,(const char *)stalist_node->ssid) == 0){
					/*add this station to the guest network*/
					ipset_add(stalist_node->mac,GUEST_LIST_MAC);
					break;
				}
			}
		}
	}else if(sta_info->status == STATION_OFF ){
		ipset_del(stalist_node->mac,GUEST_LIST_MAC);
	}

	stalist_node->status = sta_info->status;
	stalist_node->type = sta_info->type;
	
	return stalist_node;
}

