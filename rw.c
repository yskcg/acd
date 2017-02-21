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
	}
	
	return 0;
}

char *file_read(char *fname, char *tagname, char *value)
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


int file_spec_content_del(char *fname, char *index)
{
	char shell_cmd[128] = {0};
	
	if( access(fname,F_OK) !=0){
		return -1;
	}
	
	if (index != NULL){
		/*删除指定行*/
		sprintf(shell_cmd,"sed -i '/%s/d' %s",index,fname); 
		system(shell_cmd);
	}
	
	return 0;
}

/*doubule list operation API:create ,insert,del and find*/
tmplat_list *create_tplist(void)
{
	tmplat_list *p = (tmplat_list *) calloc (sizeof (tmplat_list), 1);
	
	if (p == NULL){
		return NULL;
	}
	p->rlink = NULL;
	p->llink = NULL;
	
	return p;
}

int insert_template(tmplat_list *s)
{
	tmplat_list *p = tplist, *t;

	t = create_tplist ();
	if (t == NULL || p == NULL || s == NULL){
		return 0;
	}
	
	strcpy (t->tpname, s->tpname);
	t->id = s->id;
	memcpy(&(t->tmplat_ssid_info),&(s->tmplat_ssid_info),sizeof(s->tmplat_ssid_info));
	
	while (1){
		if (p->rlink == NULL){
			p->rlink = t;
			t->llink = p;
			break;
		}
		p = p->rlink;
	}
	return 1;
}

void del_template(tmplat_list *h, char id)
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
		if ( p->id !=id ){
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

tmplat_list *find_template(char id)
{
	tmplat_list *p = tplist;

	if (p == NULL ){
		return NULL;
	}

	while (p->rlink){
		p = p->rlink;
		if ( p->id == id ){
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

int aplist_entry_hash(u8 *addr)
{
	/* use 1 byte of OUI and 3 bytes of NIC */
	u32 key = get_unaligned_32((const u8_t *)(addr + 2));
	return jhash_1word(key, ap_listdb_salt) & (AP_HASH_SIZE - 1);
}

ap_status_entry *aplist_entry_creat(struct hlist_head *head,const u8 *addr)
{
	
	ap_status_entry *aplist_node = NULL;

	if (!is_valid_ether_addr(addr)){
		return NULL;
	}
	
	if (is_local_ether_addr(addr)){
		return NULL;
	}

	aplist_node = (ap_status_entry *)calloc(1, sizeof(*aplist_node));;
	if (aplist_node) {
		memcpy(aplist_node->apinfo.apmac, addr, ETH_ALEN);
		aplist_node->status = 1;
		hlist_add_head(&aplist_node->hlist, head);
	}
	return aplist_node;
}

void * aplist_entry_remove(u8 *addr)
{
	struct hlist_head *head = NULL;
	ap_status_entry *aplist_node = NULL;
		
	if (!is_valid_ether_addr(addr)){
		return NULL;
	}
	
	if (is_local_ether_addr(addr)){
		return NULL;
	}
	
	head = &aplist.hash[aplist_entry_hash(addr)];
	aplist_node = aplist_entry_find(head,addr);
	
	if(aplist_node){
		free_mem(aplist_node);
		free(aplist_node);	
	}
	
	return NULL;
}

ap_status_entry *aplist_entry_find(struct hlist_head *head, u8 *addr)
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
			return aplist_node;
		}
	}
	return NULL;
}

ap_status_entry *aplist_entry_insert(u8 *addr)
{	
	struct hlist_head *head = NULL;
	ap_status_entry *aplist_node = NULL;
	
	
	if (!is_valid_ether_addr(addr)){
		return NULL;
	}
	
	if (is_local_ether_addr(addr)){
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
		
		aplist_node->status = 0;
	}
	
	return aplist_node;
}


