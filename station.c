#include "station.h"

static int ipset_add(u8_t *addr,char *name_entry)
{
	if (addr == NULL || name_entry == NULL){
		return -1;
	}
	print_debug_log("%s %d \n",__FUNCTION__,__LINE__);

	return 0;
}

static int ipset_del(u8_t *addr,char *name_entry)
{
	if (addr == NULL || name_entry == NULL){
		return -1;
	}
	print_debug_log("%s %d \n",__FUNCTION__,__LINE__);

	return 0;
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
	
	if(stalist_node->ssid != NULL && strcmp((const char *)stalist_node->ssid ,(const char *)sta_info->ssid) != 0 ){
		ipset_del(stalist_node->mac,GUEST_LIST_MAC);
	}
	
	memset(stalist_node->ssid,0,sizeof(stalist_node->ssid));
	
	memcpy(stalist_node->ssid,sta_info->ssid,sizeof(sta_info->ssid));
	
	memcpy(stalist_node->bssid,sta_info->bssid,ETH_ALEN);
	
	/*station online*/
	if(sta_info->status == STATION_ON && (sta_info->status != stalist_node->status)){
		/*find the ssid ->templist id*/
		for (i = 0; i<=MAX_TMP_ID; i++){
			if(ap->apinfo.id & (0x01<<i)){
				if(ap->apinfo.wifi_info.ssid_info[i].auth == WIFI_SIGNAL_DISABLE && \
				   strcmp((const char *)ap->apinfo.wifi_info.ssid_info[i].ssid,(const char *)stalist_node->ssid) == 0){
					/*add this station to the guest network*/
					ipset_add(stalist_node->mac,GUEST_LIST_MAC);
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

