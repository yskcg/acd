#include "rw.h"

int write_apinfo(char *fname, char *index, char *value)
{
	char shell_cmd[128] = {0};
	char buf[1024] = {0};
	
	if( access(fname,F_OK) !=0){
		return -1;
	}
	
	if (index && value){
		
		
		/*删除指定行*/
		sprintf(shell_cmd,"sed -i '/mac=%s*/d'",index); 
		system(shell_cmd);
		
		/*添加index 的内容*/
		sprintf(buf,"echo \"%s\" >>%s",value,fname);
		system(buf);
	}
	
	return 0;
}

char *read_apinfo(char *fname, char *tagname, char *value)
{
	FILE *fp;
	char buf[1024] = {0}, name[128] = {0}, *str = NULL;
	
	if (!(fname && tagname && value)){
		return NULL;
	}

	sprintf(name, "/etc/%s", fname);
	if (access(name, F_OK) != 0){
		return NULL;
	}
	
	if ((fp = fopen(name, "r")) == NULL){
		return NULL;
	}

	while(!feof(fp)){
		bzero(buf, sizeof(buf));
		
		if (fgets(buf, sizeof(buf), fp) == NULL){
			continue;
		}
		
		if ((str = strstr(buf, tagname)) == NULL){
			continue;
		}
		
		fclose(fp);
		strcpy(value, str + strlen(tagname) + 1);
		value[strlen(value) - 1] = 0;
		return value;
	}
	
	fclose(fp);
	return NULL;
}
void del_apinfo(char *fname, char *tagname)
{
	FILE *fp;
	int len;
	char *str = NULL, buf[1024] = {0}, name[128] = {0}
	,*nstr = NULL, *tmp = NULL, *ntmp = NULL;

	if (!(fname && tagname))
		return;

	sprintf(name, "/etc/%s", fname);
	if (access(name, F_OK) != 0)
		return;

	if ((fp = fopen(name, "r")) == NULL)
		return;
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	if (len == 0)
	{
		fclose(fp);
		return;
	}
	if ((str = alloca(len)) == NULL)
		return;
	memset(str, 0, len);
	fseek(fp, 0, SEEK_SET);
	fread(str, len, sizeof(char), fp);
	str[len] = 0;
	fclose(fp);

	if ((tmp = strstr(str, tagname)) == NULL)
		return;
	if ((nstr = alloca(len)) == NULL)
		return;
	memset(nstr, 0, len);

	strncpy(nstr, str, tmp - str);
	strcat(nstr, buf);
	if ((ntmp = strstr(tmp + strlen(tagname), "\n")) == NULL)
		return;
	strcat(nstr, ntmp + 1);

	if ((fp = fopen(name, "w+")) == NULL)
		return;
	fwrite(nstr, strlen(nstr), sizeof(char), fp);
	fclose(fp);
	return;
}


/*For hash list operation function API*/


int aplist_entry_hash(const unsigned char *addr)
{
	/* use 1 byte of OUI and 3 bytes of NIC */
	u32 key = get_unaligned((u32 *)(addr + 2));
	return jhash_1word(key, ap_listdb_salt) & (AP_HASH_SIZE - 1);
}

ap_status_entry *aplist_entry_creat(struct hlist_head *head,const unsigned char *addr)
{
	
	ap_status_entry *aplist_node = NULL;
	struct timeval node_tv;

	if (!is_valid_ether_addr(addr)){
		return NULL;
	}
	
	if (is_local_ether_addr(addr)){
		return NULL;
	}

	aplist_node = kmem_cache_alloc(ap_list_cache, GFP_ATOMIC);
	if (aplist_node) {
		memcpy(aplist_node->apinfo.apmac, addr, ETH_ALEN);
		aplist_node->status = 1;
		hlist_add_head(&aplist_node->hlist, head);
	}
	return aplist_node;
}

int aplist_entry_remove()
{
	int res = -1;
	int i;
	ap_status_entry *aplist_node = NULL;
	struct hlist_node *tmp;

	for(i = 0;i < AP_HASH_SIZE;i++){
		hlist_for_each_entry_safe(aplist_node,tmp,&(ap_list.hash[i]), hlist) {
			/*del the node*/
			hlist_del(&aplist_node->hlist);
			kmem_cache_free(ap_list_cache, aplist_node);			
		}
	}
	
	return res;
}

ap_status_entry *aplist_entry_find(struct hlist_head *head, const unsigned char *addr，const char *sn)
{
	ap_status_entry *aplist_node = NULL;


	if (!is_valid_ether_addr(addr)){
		return NULL;
	}
	
	if (is_local_ether_addr(addr)){
		return NULL;
	}
	
	hlist_for_each_entry(aplist_node, head, hlist) {
		if (ether_addr_equal(aplist_node->apinfo.apmac, addr)){
			if ((sn != NULL && sn[0] != 0) && strcasecmp(sn, aplist_node->apinfo.sn) == 0){
				return aplist_node;
			}
		}
	}
	return NULL;
}

ap_status_entry *aplist_entry_insert(const unsigned char *addr)
{	
	struct hlist_head *head = &ap_status_info.hash[aplist_entry_hash(addr)];
	ap_status_entry *aplist_node = NULL;
	
	
	if (!is_valid_ether_addr(addr)){
		return NULL;
	}
	
	if (is_local_ether_addr(addr)){
		return NULL;
	}
	
	aplist_node = aplist_entry_find(head,addr);
	
	if(!aplist_node) {
		aplist_node = aplist_entry_creat(head,addr);
		
		if(!aplist_node){
			return NULL;
		}
	}else{
		
		aplist_node->status = 0;
	}
	
	return aplist_node;
}


