#include "rw.h"

/*file operation API :write,read,and del index line*/
int file_write(char *fname, char *index, char *value)
{
	char shell_cmd[128] = {0};
	char buf[1024] = {0};
	
	if( access(fname,F_OK) !=0){
		return -1;
	}
	
	if (index && value){
		/*删除指定行*/
		sprintf(shell_cmd,"sed -i '/%s/d' %s",index,fname); 
		system(shell_cmd);
		
		/*添加index 的内容*/
		sprintf(buf,"echo \"%s\" >>%s",value,fname);
		system(buf);
		
		/*删除空白行*/
		memset(shell_cmd,'\0',sizeof(shell_cmd));
		sprintf(shell_cmd,"sed -i '/^\s*$/d' %s",fname);
		system(shell_cmd);
	}
	
	return 0;
}

int file_spec_content_del(char *fname, char *index)
{
	char shell_cmd[128] = {'\0'};
	
	if( access(fname,F_OK) !=0){
		return -1;
	}
	
	if (index != NULL){
		/*删除指定行*/
		sprintf(shell_cmd,"sed -i '/%s/d' %s",index,fname); 
		system(shell_cmd);
		/*删除空白行*/
		memset(shell_cmd,'\0',sizeof(shell_cmd));
		sprintf(shell_cmd,"sed -i '/^\s*$/d' %s",fname);
		system(shell_cmd);
	}
	
	return 0;
}

int file_sort_by_key(char *fname,int filed,char *key)
{
	char shell_cmd[128] = {'\0'};
	
	if( access(fname,F_OK) !=0){
		return -1;
	}
	
	if (key !=NULL && filed >=0){
		sprintf(shell_cmd,"sort -n -k %d -t \"%s\" \"%s\" -o \"%s\"",filed,key,fname,fname);
		system(shell_cmd);
	}
	
	return 0;
}

/*doubule list operation API:init ,insert,del and find*/
tmplat_list *template_entry_init(void)
{
	tmplat_list *p = (tmplat_list *) calloc (sizeof (tmplat_list), 1);
	
	if (p == NULL){
		return NULL;
	}
	p->rlink = NULL;
	p->llink = NULL;
	
	return p;
}

//list_add(struct list_head *_new, struct list_head *head)
int template_insert_by_id(tmplat_list *t)
{
	tmplat_list *p = tplist;
	tmplat_list *s = NULL;

	s = template_entry_init ();

	if (t == NULL || p == NULL || s == NULL){
		return 0;
	}
	
	strcpy (s->tmplate_info.tpname, t->tmplate_info.tpname);
	s->tmplate_info.id = t->tmplate_info.id;
	memcpy(&(s->tmplate_info.tmplat_ssid_info),&(t->tmplate_info.tmplat_ssid_info),sizeof(t->tmplate_info.tmplat_ssid_info));

	//print_debug_log("%s,%d id:%d ssid:%s\n",__FUNCTION__,__LINE__,s->tmplate_info.id,s->tmplate_info.tmplat_ssid_info.ssid);
	while (1){
		if (p->rlink == NULL){
			p->rlink = s;
			s->llink = p;
			break;
		}

		p = p->rlink;
	}
	return 1;
}


void template_del_by_id(tmplat_list *h, char id)
{
	tmplat_list *p = h;
	
	if (p == NULL ){
		return;
	}

	while (1){
		if (p->rlink == NULL){
			break;
		}
		p = p->rlink;
		if ( p->tmplate_info.id !=id ){
			continue;
		}
		if (p->rlink != NULL){
			p->llink->rlink = p->rlink;
			p->rlink->llink = p->llink;
		}else{
			p->llink->rlink = NULL;
		}
		
		free (p);
		p = NULL;
		break;
	}
	return;
}

tmplat_list *template_find_by_id(char id)
{
	tmplat_list *p = tplist;

	if (p == NULL ){
		return NULL;
	}

	while (p->rlink){
		p = p->rlink;
		if ( p->tmplate_info.id == id ){
			return p;
		}
	}
	return NULL;
}

/*For hash list operation function API*/
#if defined(BB_BIG_ENDIAN) && BB_BIG_ENDIAN == 1
static inline u32  get_unaligned_32(const u8_t *buf)
{
	return (u32)(buf[0] << 24)
			| ((u32)buf[1] << 16)
			| ((u32)buf[2] << 8)
			| (u32)buf[3];
}
#else
static inline u32  get_unaligned_32(const u8_t *buf)
{
	return (u32)buf[0]
		   | ((u32)buf[1] << 8)
		   | ((u32)buf[2] << 16)
		   | ((u32)buf[3] << 24);
}
#endif

int aplist_entry_hash(u8_t *addr)
{
	u32 hash_value;
	
	/* use 1 byte of OUI and 3 bytes of NIC */
	u32 key = get_unaligned_32((const u8_t *)(addr + 2));
	hash_value = jhash_1word(key, ap_listdb_salt) & (AP_HASH_SIZE - 1);
	
	return hash_value;
}

ap_status_entry *aplist_entry_creat(struct hlist_head *head,const u8_t *addr)
{
	
	ap_status_entry *aplist_node = NULL;

	if (!is_valid_ether_addr((const u8 *)addr)){
		return NULL;
	}
	
	if (is_local_ether_addr((const u8 *)addr)){
		return NULL;
	}

	aplist_node = (ap_status_entry *)calloc(1, sizeof(*aplist_node));;
	if (aplist_node) {
		memset(aplist_node,'\0',sizeof(ap_status_entry));
		memcpy(aplist_node->apinfo.apmac, addr, ETH_ALEN);
		aplist_node->status = AC_NEW_HASH_NODE;
		aplist_node->apinfo.id = DEFAULT_TMPLATE_ID_MAP;
		hlist_add_head(&aplist_node->hlist, head);
	}
	return aplist_node;
}

void * aplist_entry_remove(u8_t *addr)
{
	struct hlist_head *head = NULL;
	ap_status_entry *aplist_node = NULL;
	struct hlist_node *tmp;
		
	if (!is_valid_ether_addr((const u8 *)addr)){
		return NULL;
	}
	
	if (is_local_ether_addr((const u8 *)addr)){
		return NULL;
	}
	
	head = &aplist.hash[aplist_entry_hash(addr)];
	
	hlist_for_each_entry_safe(aplist_node,tmp,head, hlist) {
		if (ether_addr_equal((const u8 *)aplist_node->apinfo.apmac,(const u8 *)addr)){
			/*del the node*/
			hlist_del(&aplist_node->hlist);
			free_mem(aplist_node);
			free(aplist_node);
		}
	}

	return NULL;
}

ap_status_entry *aplist_entry_find(struct hlist_head *head, u8_t *addr)
{
	ap_status_entry *aplist_node = NULL;


	if (!is_valid_ether_addr((const u8 *)addr)){
		return NULL;
	}
	
	if (is_local_ether_addr((const u8 *)addr)){
		return NULL;
	}
	
	hlist_for_each_entry(aplist_node, head, hlist) {		
		if (ether_addr_equal((const u8 *)aplist_node->apinfo.apmac,(const u8 *)addr)){
			return aplist_node;
		}
	}
	
	return NULL;
}

ap_status_entry *aplist_entry_insert(u8_t *addr)
{	
	struct hlist_head *head = NULL;
	ap_status_entry *aplist_node = NULL;

	if (!is_valid_ether_addr((const u8 *)addr)){
		return NULL;
	}

	if (is_local_ether_addr((const u8 *)addr)){
		return NULL;
	}

	head = &aplist.hash[aplist_entry_hash(addr)];
	aplist_node = aplist_entry_find(head,addr);

	if(!aplist_node) {

		aplist_node = aplist_entry_creat(head,addr);
		if(!aplist_node){
			return NULL;
		}
	}else{
		if (aplist_node->status != AC_AP_HASH_NODE_ON){
			aplist_node->status = AC_INIT_OFFLINE;

		}
	}

	return aplist_node;
}


/*API: For the station hash list*/

int stalist_entry_hash(u8_t *addr)
{
	u32 hash_value;

	/* use 1 byte of OUI and 3 bytes of NIC */
	u32 key = get_unaligned_32((const u8_t *)(addr + 2));
	hash_value = jhash_1word(key, sta_listdb_salt) & (AP_HASH_SIZE - 1);

	return hash_value;
}

sta_entry *stalist_entry_creat(struct hlist_head *head,const u8_t *addr)
{

	sta_entry *stalist_node = NULL;

	if (!is_valid_ether_addr((const u8 *)addr)){
		return NULL;
	}

	if (is_local_ether_addr((const u8 *)addr)){
		return NULL;
	}

	stalist_node = (sta_entry *)calloc(1, sizeof(*stalist_node));;
	if (stalist_node) {
		memset(stalist_node,0,sizeof(stalist_node));
		/*The node operation*/
		gettime(&stalist_node->time_stamp);
		memcpy(stalist_node->mac, addr, ETH_ALEN);
		hlist_add_head(&stalist_node->hlist, head);
	}
	return stalist_node;
}

void * stalist_entry_remove(u8_t *addr)
{
	struct hlist_head *head = NULL;
	sta_entry *stalist_node = NULL;
	struct hlist_node *tmp;

	if (!is_valid_ether_addr((const u8 *)addr)){
		return NULL;
	}

	if (is_local_ether_addr((const u8 *)addr)){
		return NULL;
	}

	head = &stalist.hash[stalist_entry_hash(addr)];

	hlist_for_each_entry_safe(stalist_node,tmp,head, hlist) {
		if (ether_addr_equal((const u8 *)stalist_node->mac,(const u8 *)addr)){
			/*del the node*/
			hlist_del(&stalist_node->hlist);
			free(stalist_node);
			break;
		}
	}

	return NULL;
}

sta_entry *stalist_entry_find(struct hlist_head *head, u8_t *addr)
{
	sta_entry *stalist_node = NULL;

	if (!is_valid_ether_addr((const u8 *)addr)){
		return NULL;
	}

	if (is_local_ether_addr((const u8 *)addr)){
		return NULL;
	}

	hlist_for_each_entry(stalist_node, head, hlist) {
		if (ether_addr_equal((const u8 *)stalist_node->mac,(const u8 *)addr)){
			return stalist_node;
		}
	}

	return NULL;
}

sta_entry *stalist_entry_insert(u8_t *addr)
{
	struct hlist_head *head = NULL;
	sta_entry *stalist_node = NULL;

	if (!is_valid_ether_addr((const u8 *)addr)){
		return NULL;
	}

	if (is_local_ether_addr((const u8 *)addr)){
		return NULL;
	}

	head = &stalist.hash[stalist_entry_hash(addr)];
	stalist_node = stalist_entry_find(head,addr);

	if(!stalist_node) {
		stalist_node = stalist_entry_creat(head,addr);
		if(!stalist_node){
			return NULL;
		}
		stalist_node->exist_flag = STATION_NEW;
	}else{
		gettime(&stalist_node->time_stamp);
		stalist_node->exist_flag = STATION_EXIST;
	}

	return stalist_node;
}

