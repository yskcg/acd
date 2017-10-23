#include "acd.h"

const char 	*port 	= "4444"; //acd 服务器监听端口
FILE 		*debug 	= NULL;
static struct uloop_fd 		server;
static struct client 		*next_client = NULL;
static struct sproto 		*spro_new = NULL;	//the protocol
static struct ubus_context  *ctx;
static struct blob_buf b;
static struct uloop_timeout timeout;
static struct uloop_timeout sta_timeout;

static char temp_ssid[TEMP_SSID_BUF_SIZE] = {'\0'};
static char temp_key[TEMP_SSID_BUF_SIZE]  = {'\0'};
static char temp_encrypt[TEMP_SSID_BUF_SIZE]  = {'\0'};
static char temp_hidden[TEMP_SSID_BUF_SIZE] = {'\0'};
static char temp_disabled[TEMP_SSID_BUF_SIZE] = {'\0'};
static char temp_type[TEMP_SSID_BUF_SIZE] = {'\0'};
static char temp_device_info[TEMP_SSID_BUF_SIZE] = {'\0'};

u32 ap_listdb_salt;
u32 sta_listdb_salt;
ap_list 	aplist;							//ap information list
sta_list 	stalist;						//station information list
tmplat_list *tplist 	= NULL;

static device_info	 ac_info;
static ap_status_entry apcfg_receive;
static sta_entry  sta_status_info_receive;


void gettime(struct timeval *tv)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;

}

static int tv_diff(struct timeval *t1, struct timeval *t2)
{
	return
		(t1->tv_sec - t2->tv_sec) * 1000 +
		(t1->tv_usec - t2->tv_usec) / 1000;

}

char char_to_data(const char ch)
{
    switch(ch){
		case '0': return 0;
		case '1': return 1;
		case '2': return 2;
		case '3': return 3;
		case '4': return 4;
		case '5': return 5;
		case '6': return 6;
		case '7': return 7;
		case '8': return 8;
		case '9': return 9;
		case 'a':
		case 'A': return 10;
		case 'b':
		case 'B': return 11;
		case 'c':
		case 'C': return 12;
		case 'd':
		case 'D': return 13;
		case 'e':
		case 'E': return 14;
		case 'f':
		case 'F': return 15;
    }
    return 0;
}

static void mac_string_to_value(unsigned char *mac,unsigned char *buf)
{
    int i;
    int len;
	unsigned char * p_temp = mac;

	if(mac && buf){
		len = strlen((const char *)mac);
		for (i=0;i<(len-5)/2;i++){
			//mach_len = sscanf((const char *)mac+i*3,"%2x",&buf[i]);

			buf[i] = char_to_data(*p_temp++) * 16;
			buf[i] += char_to_data(*p_temp++);
			p_temp++;
		}
	}
}

int is_ip(const char *str)
{
    struct in_addr addr;
    int ret;

		if (str == NULL)
			return -1;
    ret = inet_pton(AF_INET, str, &addr);
    return ret;
}

void set_ac_dns_address(struct uloop_timeout *t)
{
	system(". /usr/sbin/set_ac_dns_addr.sh");
	uloop_timeout_set(t, DNS_SET_INTERVAL);

	return;
}

int data_range_in(int data,int little,int bigger)
{
	if (data >= little && data <= bigger){
		return 1;
	}else{
		return 0;
	}
}

void check_station_status(struct uloop_timeout *t)
{
	int i;
	long td;
	struct timeval tv;
	sta_entry *station = NULL;
	struct hlist_node *tmp;
	ap_status_entry *ap = NULL;
	struct hlist_head *head = NULL;

	for(i = 0;i < AP_HASH_SIZE;i++){
		if (hlist_empty(&(stalist.hash[i]))){
			continue;
		}
		hlist_for_each_entry_safe(station,tmp,&(stalist.hash[i]), hlist) {
			gettime(&tv);
			td = tv_diff(&tv, &station->time_stamp);

			if (td > STATION_STATUS_CHECK_INTERVAL) {	//3 minute
				/*del the WhiteList_wifi_src*/
				ipset_del(station->mac,GUEST_LIST_MAC);
				/*find the ap */
				head = &aplist.hash[aplist_entry_hash(station->ap_mac)];
				ap = aplist_entry_find(head,station->ap_mac);
				if(ap != NULL ){
					if(station->type){
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
					/*find the ssid ->templist id*/
					for (i = 0; i<=MAX_TMP_ID; i++){
						if(ap->apinfo.id & (0x01<<i)){
							if(ap->apinfo.wifi_info.ssid_info[i].auth == WIFI_SIGNAL_DISABLE && \
							   strcmp((const char *)ap->apinfo.wifi_info.ssid_info[i].ssid,(const char *)station->ssid) == 0){

								/*sum the num of guest*/
								if(station->type){
									if(ap->sta_guest_5G_num >0 ){
										ap->sta_guest_5G_num = ap->sta_guest_5G_num -1;
									}
								}else{
									if(ap->sta_guest_2G_num >0){
										ap->sta_guest_2G_num = ap->sta_guest_2G_num -1;	
									}
								}

								if (ap->sta_guest_num >0){
									ap->sta_guest_num = ap->sta_guest_num -1;
								}

								break;
							}
						}
					}
				}

				/*del the node*/
				hlist_del(&station->hlist);
				free(station);
			}
		}
	}

	uloop_timeout_set(t, STATION_STATUS_CHECK_INTERVAL);

	return;
}

static void client_read_cb(struct ustream *s, int bytes)
{
	struct client *cl = container_of (s, struct client, s.stream);
	char *str;
	int len = 0,ret;
	
	do {
		str = ustream_get_read_buf (s, &len);
		if (!str){
			break;
		}

		ret = rcv_and_proc_data (str, len, cl);
		
		if (ret != ACd_STATUS_REBOOT_OK){
			ustream_consume (s, len);
		}
	} while(1);

	if (s->w.data_bytes > 256 && !ustream_read_blocked(s)) {
		print_debug_log ("[debug] [Block read, bytes: %d]\n", s->w.data_bytes);
		ustream_set_read_blocked (s, TRUE);
	}
}

static void client_close(struct ustream *s)
{
	struct client *cl = container_of (s, struct client, s.stream);
	int i;
	ap_status_entry *ap = NULL;

	print_debug_log ("[debug] [fd:%d connection closed!!]\n", cl->s.fd.fd);
	
	/*show all ap info in this AC*/
	for(i = 0;i < AP_HASH_SIZE;i++){
		if (hlist_empty(&(aplist.hash[i]))){
			continue;
		}
		hlist_for_each_entry(ap, &(aplist.hash[i]), hlist) {
			if ( ap->client_addr && ap->client_addr->s.fd.fd == cl->s.fd.fd){
				free_mem(ap);
			}
		}
	}
}

static void client_notify_state(struct ustream *s)
{
	struct client *cl = container_of (s, struct client, s.stream);
	print_debug_log ("[debug] [fd:%d state changed: %d %d!!]\n", cl->s.fd.fd, s->eof, s->w.data_bytes);
	
	if (!s->eof){
		return;
	}

	if (!s->w.data_bytes){
		return client_close (s);
	}
}

static void server_cb(struct uloop_fd *fd, unsigned int events)
{
	struct client *cl;
	unsigned int sl = sizeof (struct sockaddr_in);
	int sfd;
	int so_reuseaddr = TRUE;
	struct timeval timeout;

	if (!next_client){
		next_client = calloc (1, sizeof (*next_client));
	}

	cl = next_client;
	sfd = accept (server.fd, (struct sockaddr *) &cl->sin, &sl);
	if (sfd < 0) {
		print_debug_log ("Accept failed\n");
		return;
	}

	sl = sizeof (struct sockaddr_in);
	if (getsockname(sfd, (struct sockaddr *)&cl->localaddr, &sl) != 0){
		print_debug_log("[debug] getsockname errno: %s\n", errno);
	}

	/*socket receive timeout set*/
	timeout.tv_sec  = 5;
	timeout.tv_usec = 0;
	setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
	/*socket send timeout set*/
	timeout.tv_sec  = 5;
	timeout.tv_usec = 0;
	setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

	/*set the sock reuse*/
	setsockopt(sfd,SOL_SOCKET,SO_REUSEADDR,&so_reuseaddr,sizeof(so_reuseaddr));

	cl->s.stream.string_data = TRUE;
	cl->s.stream.notify_read = client_read_cb;
	cl->s.stream.notify_state = client_notify_state;

	ustream_fd_init (&cl->s, sfd);
	next_client = NULL;
	print_debug_log("[debug] [New connection] [local ip:%s]\n", inet_ntoa(cl->localaddr.sin_addr));
	print_debug_log("[debug] [New connection] [peer ip:%s fd:%d]\n", inet_ntoa(cl->sin.sin_addr), sfd);
}


int is_digit_string(char * string)
{
	int res = IS_DIGIT_STRING_ERR;
	int len = 0;
	char tem_buf[64] = {'\0'};

	if (string == NULL){
		return res;
	}

	len = strlen (string);
	sprintf(tem_buf,"%d",atoi(string));
	if (len != strlen(tem_buf)){
		res = IS_DIGIT_STRING_ERR;
		return res;
	}

	res = IS_DIGIT_STRING;

	return res;
}

void aplist_insert(char *buf)
{
	int len =0;
	int i;
	int offset = 0;
	char temp_buf[64] = {'\0'};
	char temp_buf2[512] = {'\0'};
	char key[32] = {'\0'};
	char value[128] = {'\0'};
	unsigned char mac[6] = {0};
	char *optstr;
	char *p_key_value = NULL;
	ap_status_entry *ap = NULL;
	tmplat_list *tp = NULL;

	/*get the mac address of ap*/
	if (strlen(buf) <=1 || buf[0] ==10){ //排除文件换行无内容情况
		return;
	}else{
		len = strlen(buf);
		p_key_value = strstr(buf,"|");
		offset = len -strlen(p_key_value);
		strncpy(temp_buf,buf,offset);
		
		while(strlen(temp_buf) >0){			
			memset(key,'\0',sizeof(key));
			memset(value ,'\0',sizeof(value));
			optstr = strstr (temp_buf, "=");
			strncpy (key, temp_buf, optstr - temp_buf);
			strncpy (value, optstr + 1,strlen(optstr)-1);
			
			/*creat or find the hash node*/
			if ((strcasecmp(key,"mac") == 0)&&strlen(value) > 0){
				/*dele the ':' and make string to int*/
				mac_string_to_value((unsigned char *)value,mac);
				/*for_each to find hash node*/
				ap = aplist_entry_insert(mac);
			}
			/*fill data in the hash node*/
			if ( ap ){
				fill_data (ap, key, value, strlen (value));
			}else{
				break;
			}

			memset(temp_buf,0,sizeof(temp_buf));
			memset(temp_buf2,0,sizeof(temp_buf2));
			if(! p_key_value ){
				break;
			}
			p_key_value = p_key_value +1;
			len = strlen(p_key_value);
			strncpy(temp_buf2,p_key_value,len);
			p_key_value = strstr(p_key_value,"|");

			if(p_key_value){
				offset = len -strlen(p_key_value);
				strncpy(temp_buf,temp_buf2,offset);
			}else{
				strncpy(temp_buf,temp_buf2,len);
			}		
		}

		/*find the aplist id <-> tmplate id,if id not exist,use default tmplate,else use tmplate id*/
		if (ap == NULL){
			return;
		}

		ap->status = AC_INIT_OFFLINE;    //init the aplist  set the status to zero
		if (ap->apinfo.id != DEFAULT_TMPLATE_ID_MAP){
			ap->apinfo.id = DEFAULT_TMPLATE_ID_MAP; //default band three template
		}

		for ( i = 0;i<=AP_MAX_BINDID;i++){
			if (ap->apinfo.id & (0x01<<i)){
				if ((tp = template_find_by_id(i)) != NULL){
					memcpy(&(ap->apinfo.wifi_info.ssid_info[i]),&(tp->tmplate_info.tmplat_ssid_info),sizeof(ap_ssid_info));
				}else if(i>2){ //default band three template
					clear_bit(ap->apinfo.id,i);
				}
			}
		}
	}
}

void aplist_init(void)
{
	int file_size;
	char buf[512] = {'\0'};
	FILE *fp =NULL;
	
	/*1:read the content from the aplist*/
	
	if (access(AP_LIST_FILE, F_OK) != 0){
		return;
	}

	if ((fp = fopen(AP_LIST_FILE, "r")) == NULL){
		return;
	}
	
	/*for old aplist file cut the ap_cfg_xx= header line*/
	sprintf(buf,"sed -i 's/^ap_cfg_[0-9]*=//g' %s",AP_LIST_FILE);
	system(buf);
	/*删除空白行*/
	memset(buf,'\0',sizeof(buf));
	sprintf(buf,"sed -i '/^\s*$/d' %s",AP_LIST_FILE);
	system(buf);
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	
	if (file_size == 0){
		fclose(fp);
		return;
	}
	
	fseek(fp,0,SEEK_SET);
	/*get the aplist file content*/
	while((fgets(buf,512,fp))!=NULL){
		aplist_insert(buf);
		memset(buf,0,sizeof(buf));
	}
	
	fclose(fp);
	return ;
	
}

void get_ac_info()
{
	int read_size = 0;
	char shell_cmd [128] = {0};
	char ac_infos[256] = {0};
	FILE *ac_info_fp = NULL;

	/*must dynamic get the ac info*/

try:
	system("ubus wait_for sysd");
	sprintf(shell_cmd,"ubus call sysd sysinfo > %s",DEVICE_INFO);
	system(shell_cmd);

	memset(&ac_info,0,sizeof(ac_info));
	if(access(DEVICE_INFO,F_OK) == 0){
		ac_info_fp = fopen(DEVICE_INFO,"r");
		if(ac_info_fp != NULL){
			read_size = fread(ac_infos,sizeof(ac_infos),1,ac_info_fp);

			if(read_size <= 0  && strlen(ac_infos) <=1){
				fclose(ac_info_fp);
				unlink(DEVICE_INFO);
				sleep(5);
				goto try;
			}else{
				json_parse(ac_infos,"sn",ac_info.sn);
				json_parse(ac_infos,"moid",ac_info.moid);
				json_parse(ac_infos,"dt",&(ac_info.dt));
				json_parse(ac_infos,"product",ac_info.product);
				fclose(ac_info_fp);
				unlink(DEVICE_INFO);
				print_debug_log("%s %d ac_infos:%s sn:%s moid:%s dt:%d product:%s\n",__FUNCTION__,__LINE__,ac_infos,ac_info.sn,ac_info.moid,ac_info.dt,ac_info.product);
			}	
		}
	}
}

void tplist_insert(char *buf)
{
	tmplat_list tp;
	int len =0;
	int offset = 0;
	char temp_buf[64] = {'\0'};
	char temp_buf2[512] = {'\0'};
	char key[32] = {'\0'};
	char value[128] = {'\0'};
	char *optstr;
	char *p_key_value = NULL;

	/*get the mac address of ap*/
	if (strlen(buf) <=1 || buf[0] ==10){ //排除文件换行无内容情况
		return;
	}else{
		len = strlen(buf);
		p_key_value = strstr(buf,"|");
		offset = len -strlen(p_key_value);
		strncpy(temp_buf,buf,offset);
		memset (&tp, '\0', sizeof (tmplat_list));

		while(strlen(temp_buf) >0){
			memset(key,'\0',sizeof(key));
			memset(value ,'\0',sizeof(value));
			optstr = strstr (temp_buf, "=");
			strncpy (key, temp_buf, optstr - temp_buf);
			strncpy (value, optstr + 1,strlen(optstr)-1);
			/*fill data in the double link list node*/
			if (strcasecmp(key, "name") == 0){
				strcpy(tp.tmplate_info.tpname,value);
			}else if (strcasecmp (key, "id") == 0){
				tp.tmplate_info.id = (char )atoi(value);
			}else if (strcasecmp (key, "ssid") == 0){
				strcpy(tp.tmplate_info.tmplat_ssid_info.ssid,value);
			}else if (strcasecmp (key, "encrypt") == 0){
				strcpy(tp.tmplate_info.tmplat_ssid_info.encrypt,value);
			}else if (strcasecmp (key, "key") == 0){
				strcpy(tp.tmplate_info.tmplat_ssid_info.key,value);
			}else if (strcasecmp (key, "auth") == 0){
				tp.tmplate_info.tmplat_ssid_info.auth = (char )atoi(value);
			}else if (strcasecmp (key, "type") == 0){
				tp.tmplate_info.tmplat_ssid_info.type = (char )atoi(value);
			}else if (strcasecmp (key, "disabled") == 0){
				tp.tmplate_info.tmplat_ssid_info.disabled = (char )atoi(value);
			}else if (strcasecmp (key, "hidden") == 0){
				tp.tmplate_info.tmplat_ssid_info.hidden = (char )atoi(value);
			}

			memset(temp_buf,0,sizeof(temp_buf));
			memset(temp_buf2,0,sizeof(temp_buf2));
			if(! p_key_value ){
				break;
			}
			p_key_value = p_key_value +1;
			len = strlen(p_key_value);
			strncpy(temp_buf2,p_key_value,len);
			p_key_value = strstr(p_key_value,"|");

			if(p_key_value){
				offset = len -strlen(p_key_value);
				strncpy(temp_buf,temp_buf2,offset);
			}else{
				strncpy(temp_buf,temp_buf2,len);
			}
		}

		template_insert_by_id (&tp);
		memset (&tp, '\0', sizeof (tmplat_list));
	}
}

void tplist_init(void)
{
	int template_numbers = 0;
	int file_size;
	char buf[512];
	char default_ssid[32] = {'\0'}; 
	FILE *fp =NULL;
	
	/*1:read the content from the tplist*/
	if (access(TP_LIST_FILE, F_OK) != 0){
		return;
	}

	/*sort the tplist file*/
	file_sort_by_key(TP_LIST_FILE,3,"=");

	if ((fp = fopen(TP_LIST_FILE, "r")) == NULL){
		return;
	}
	
	/*for old tplist file cut the template_[0-9]= header line*/
	/*for old tplist file support for auth disable type hidden attr*/
	memset(buf,'\0',sizeof(512));
	sprintf(buf," . /usr/sbin/tplist.sh %s" ,TP_LIST_FILE);
	system(buf);

	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	fseek(fp,0,SEEK_SET);
	memset(buf,'\0',sizeof(512));

	/*get the template numbers*/
	while((fgets(buf,512,fp))!=NULL){
		template_numbers = template_numbers +1;
		memset(buf,'\0',sizeof(512));
	}

	if (file_size == 0 || template_numbers !=3 ){
		memset(buf,0,sizeof(buf));
		/*no contents - write the default value for default template*/
		strcpy(default_ssid,ac_info.product);
		sprintf(buf, "name=default|id=0|ssid=%s|encrypt=none|key=|auth=1|type=2|disabled=1|hidden=0",strlen(default_ssid)>1?default_ssid:"morewifi");
		file_write(TP_LIST_FILE, "id=0", buf);
		tplist_insert(buf);
		memset(buf,0,sizeof(buf));
		sprintf(buf, "name=default|id=1|ssid=%s|encrypt=none|key=|auth=0|type=0|disabled=0|hidden=0",strlen(default_ssid)>1?default_ssid:"morewifi");
		file_write(TP_LIST_FILE, "id=1", buf);
		tplist_insert(buf);
		memset(buf,0,sizeof(buf));
		sprintf(buf, "name=default|id=2|ssid=%s|encrypt=none|key=|auth=0|type=1|disabled=0|hidden=0",strlen(default_ssid)>1?default_ssid:"morewifi");
		file_write(TP_LIST_FILE, "id=2", buf);
		tplist_insert(buf);
	}else{
		/*get the aplist file content*/
		fseek(fp,0,SEEK_SET);
		memset(buf,'\0',sizeof(512));
		/*get the tplist file content*/
		while((fgets(buf,512,fp))!=NULL){
			tplist_insert(buf);
			memset(buf,'\0',sizeof(512));
		}
	}

	fclose(fp);

	return;
}



int memcat(char *res, char *buf, int slen, int len)
{
	int i;
	
	if (buf == NULL || len <= 0){
		return 0;
	}
	
	for (i = 0; i < len; i++){
		res[i + slen] = buf[i];
	}
	
	res[i + slen] = 0;
	
	return slen + len;
}

int sproto_read_entity(char *filename)
{
	FILE *fp;
	int len;
	unsigned char spro_buf[BUFLEN];
	
	if ((fp = fopen(filename, "rb")) == NULL){
		print_debug_log ("[debug] [error] [fopen() failed!]\n");
		return -1;
	}
	
	if ((len = fread(spro_buf, 1, sizeof(spro_buf), fp)) <= 0){
		print_debug_log ("[debug] [error] [fread() failed!]\n");
		fclose (fp);
		return 0;
	}
	
	if ((spro_new = sproto_create(spro_buf, len)) == NULL){
		print_debug_log ("[debug] [error] [sproto_create() failed!]\n");
		fclose (fp);
		return 0;
	}
	
	fclose (fp);
	return len;
}

int sproto_encode_cb(void *ud, const char *tagname, int type, int index, struct sproto_type *st, void *value, int length)
{
	struct encode_ud *self = ud;
	size_t sz;
	ap_status_entry *apcfg = NULL;

	if (self->type <=AP_CMD){
		apcfg = container_of (ud, ap_status_entry, ud);
	}

	if (length < 2 * SIZEOF_LENGTH){
		return 0;
	}

	switch (type) {
		case SPROTO_TINTEGER: {
			
			if (strcasecmp (tagname, "type") == 0){
				*(uint32_t *) value = self->type;
			}else if (strcasecmp (tagname, "session") == 0){
				*(uint32_t *) value = self->session;
			}else if (strcasecmp (tagname, "apcmd") == 0){
				*(uint32_t *) value = apcfg->cmd.cmd;
			}else if (strcasecmp (tagname, "status") == 0){
				*(uint32_t *) value = apcfg->cmd.status;
			}
			
			print_debug_log("[debug] [encode] [%s:] [%d]\n", tagname, *(int *)value);
			return 4;
		}
		
		case SPROTO_TBOOLEAN: {
			if (strcasecmp (tagname, "ok") == 0){
				*(int *) value = self->ok;
			}
			
			print_debug_log("[debug] [encode] [%s:] [%d]\n", tagname, *(int *)value);
			return 4;
		}
		
		case SPROTO_TSTRING: {
			if (strcasecmp(tagname, "ac_info") == 0){
					strcpy(value,temp_device_info);
					sz = strlen(value);
			}else{
				fill_encode_data (apcfg, (char *) tagname, (char *) value);
				print_debug_log("[debug] [encode] [%s:] [%s]\n", tagname, (char *)value);
				sz = strlen ((char *) value);
			}
			return sz;
		}
		
		case SPROTO_TSTRUCT: {
			int r = sproto_encode (st, value, length, sproto_encode_cb, self);
			return r;
		}
		
		default:
		print_debug_log ("[debug] [unknown type]\n");
	}
	return 1;
}

int sproto_encode_data(struct encode_ud *ud, char *res)
{
	int header_len, rpc_len, len, size;
	char header[BUFLEN], buf[BUFLEN], pro_buf[BUFLEN];
	struct sproto_type *pro_type;

	if((pro_type = sproto_type(spro_new, "package")) == NULL){
		print_debug_log ("[debug] [error] [sproto_type() failed!]\n");
		return 0;
	}
	
	bzero (header, sizeof (header));
	
	if((header_len = sproto_encode(pro_type, header, sizeof(header), sproto_encode_cb, ud)) < 0){
		return 0;
	}
	
	memcat (buf, header, 0, header_len);
	len = header_len;
	print_debug_log ("[debug] [encode type:%d]\n", ud->type);

	if((pro_type = sproto_protoquery(spro_new, ud->type, ud->session)) == NULL){
		print_debug_log ("[debug] [error] [sproto_protoquery() failed!]\n");
		return 0;
	}
	
	bzero (pro_buf, sizeof (pro_buf));
	if((rpc_len = sproto_encode(pro_type, pro_buf, sizeof(pro_buf), sproto_encode_cb, ud)) < 0){
		print_debug_log ("[debug] [error] [sproto_encode() failed!]\n");
		return 0;
	}
	
	memcat (buf, pro_buf, header_len, rpc_len);
	len += rpc_len;

	size = sproto_pack (buf, len, res, sizeof (buf));
	print_debug_log ("[debug] [encode len:%d] [pack size:%d]\n", len, size);
	return size;
}

void fill_encode_data(ap_status_entry *apcfg, char *tagname, char *value)
{
	if (apcfg == NULL){
		return;
	}

	if (strcasecmp (tagname, "ssid") == 0){
		strcpy (value, (const char *)temp_ssid);
	}else if (strcasecmp (tagname, "encrypt") == 0){
		strcpy (value, (const char *)temp_encrypt);
	}else if (strcasecmp (tagname, "hidden") == 0){
		strcpy (value, (const char *)temp_hidden);
	}else if (strcasecmp (tagname, "type") == 0){
		strcpy (value, (const char *)temp_type);
	}else if (strcasecmp (tagname, "disabled") == 0){
		strcpy (value, (const char *)temp_disabled);
	}else if (strcasecmp (tagname, "key") == 0){
		strcpy (value, (const char *)temp_key);
	}else if (strcasecmp (tagname, "channel") == 0){
		strcpy (value, apcfg->apinfo.wifi_info.channel);
	}else if (strcasecmp (tagname, "txpower") == 0){
		strcpy (value, apcfg->apinfo.wifi_info.txpower);
	}else if (strcasecmp (tagname, "addr") == 0){
		strcpy (value, apcfg->cmd.addr);
	}else if (strcasecmp (tagname, "md5") == 0){
		strcpy (value, apcfg->cmd.md5);
	}else if (strcasecmp (tagname, "aip") == 0){
		strcpy (value, apcfg->apinfo.aip);
	}
	return;
}

void fill_data(ap_status_entry *apcfg, char *tagname, char *value, int len)
{
	unsigned char mac_value[ETH_ALEN] = {0};
	sta_entry *station = NULL;
	
	if (apcfg == NULL || strlen (value) == 0 || len == 0){
		return;
	}

	print_debug_log("[debug:][%s] [tagname]:%s [value]:%s \n",__FUNCTION__,tagname,value);
	if (strcasecmp (tagname, "hver") == 0){
		memset(apcfg->apinfo.hver,'\0',sizeof(apcfg->apinfo.hver));
		strncpy (apcfg->apinfo.hver, value, len);
	}else if (strcasecmp (tagname, "model") == 0){
		memset(apcfg->apinfo.model ,'\0',sizeof(apcfg->apinfo.model));
		strncpy (apcfg->apinfo.model, value, len);
	}else if (strcasecmp (tagname, "sver") == 0){
		memset(apcfg->apinfo.sver ,'\0',sizeof(apcfg->apinfo.sver));
		strncpy (apcfg->apinfo.sver, value, len);
	}else if (strcasecmp (tagname, "sn") == 0){
		memset(apcfg->apinfo.sn ,'\0',sizeof(apcfg->apinfo.sn));
		strncpy (apcfg->apinfo.sn, value, len);
	}else if (strcasecmp (tagname, "aip") == 0){
		memset(apcfg->apinfo.aip ,'\0',sizeof(apcfg->apinfo.aip));
		strncpy (apcfg->apinfo.aip, value, len);
	}else if (strcasecmp (tagname, "mac") == 0){
		memset(apcfg->apinfo.apmac ,0,sizeof(apcfg->apinfo.apmac));
		mac_string_to_value((unsigned char *)value,mac_value);	
		memcpy(apcfg->apinfo.apmac, mac_value, ETH_ALEN);
	}else if (strcasecmp (tagname, "channel") == 0){
		memset(apcfg->apinfo.wifi_info.channel ,'\0',sizeof(apcfg->apinfo.wifi_info.channel));
		strncpy (apcfg->apinfo.wifi_info.channel, value,len);
		apcfg->apinfo.wifi_info.channel[strlen(apcfg->apinfo.wifi_info.channel) -1] = '\0';
	}else if (strcasecmp (tagname, "id") == 0){
		apcfg->apinfo.id = atoi(value);
	}else if (strcasecmp(tagname, "name") == 0){
		memset(apcfg->apname ,'\0',sizeof(apcfg->apname));
		strncpy(apcfg->apname, value, len);
	}else if (strcasecmp(tagname, "txpower") == 0){
		memset(apcfg->apinfo.wifi_info.txpower ,'\0',sizeof(apcfg->apinfo.wifi_info.txpower));
		strncpy(apcfg->apinfo.wifi_info.txpower, value, len);
	}else if (strcasecmp(tagname, "stamac") == 0){
		/*insert the stalist hash list*/
		mac_string_to_value((unsigned char *)value,mac_value);	
		station = stalist_entry_insert(mac_value);
		if (station){
			if(apcfg->apinfo.apmac){
				memcpy(station->ap_mac,apcfg->apinfo.apmac, ETH_ALEN);
			}
		}
	}
	return;
}

int fill_data_sta_info(sta_entry *sta_info,char *tagname, char *value, int len)
{
	unsigned char mac_value[ETH_ALEN] = {0};
	sta_entry *station = sta_info;

	if (sta_info == NULL || strlen (value) == 0 || len == 0){
		return -1;
	}

	if (strcasecmp (tagname, "sta_mac") == 0){
		mac_string_to_value((unsigned char *)value,mac_value);
		memcpy(station->mac, mac_value, ETH_ALEN);
	}else if (strcasecmp (tagname, "sta_bssid") == 0){
		mac_string_to_value((unsigned char *)value,mac_value);
		memcpy(station->bssid, mac_value, ETH_ALEN);
	}else if (strcasecmp (tagname, "sta_ssid") == 0){
		memset(station->ssid,'\0',sizeof(station->ssid));
		strncpy ((char *)station->ssid, value, len);
	}else if (strcasecmp (tagname, "sta_ap_mac") == 0){
		mac_string_to_value((unsigned char *)value,mac_value);
		memcpy(station->ap_mac, mac_value, ETH_ALEN);
	}

	return 0;
}

int sproto_parser_cb(void *ud, const char *tagname, int type, int index, struct sproto_type *st, void *value, int length)
{
	int r;
	char val[256] = {0};
	struct encode_ud *self = ud;
	ap_status_entry *apcfg =&apcfg_receive;
	sta_entry  *sta_status_info = &sta_status_info_receive;

	if (!(tagname && ud )){
		return 0;
	}

	switch (type) {
		case SPROTO_TINTEGER:
			if (strcasecmp (tagname, "type") == 0){
				self->type = *(int *) value;
			}else if (strcasecmp (tagname, "session") == 0){
				self->session = *(int *) value;
			}else if (strcasecmp (tagname, "apstatus") == 0){
				apcfg->cmd.status = *(int *) value;
			}else if (strcasecmp(tagname, "sta_status") == 0){
				sta_status_info->status = *(int *) value;
			}else if (strcasecmp(tagname, "sta_type") == 0){
				sta_status_info->type = *(int *) value;
			}
			print_debug_log ("[debug] [decode] [%s:] [%d]\n", tagname, *(int *) value);
			break;

		case SPROTO_TBOOLEAN:
			self->ok = *(int *) value;
			print_debug_log ("[debug] [decode] [%s:] [%d]\n", tagname, *(int *) value);
			break;
		
		case SPROTO_TSTRING:
			strncpy(val, value, length);
			print_debug_log("[debug] [decode] [%s: %s,%d]\n", tagname, val, length);
			if (self->type == STA_INFO){
				fill_data_sta_info(sta_status_info,(char *) tagname,val,length);
			}else{
				fill_data (apcfg, (char *) tagname, val, length);
			}

			break;
		
		case SPROTO_TSTRUCT:
			r = sproto_decode (st, value, length, sproto_parser_cb, self);
			print_debug_log("%s %d,length:%d\n",__FUNCTION__,__LINE__,length);
			if (r < 0 || r != length){
				return r;
			}
			break;
		
		default:
			print_debug_log ("[debug] [unknown type]\n");
			break;
	}
	return 0;
}

int sproto_header_parser(char *pack, int size, struct encode_ud *ud, char *unpack)
{
	int unpack_len, header_len;
	struct sproto_type *stype;

	if ((unpack_len = sproto_unpack(pack, size, unpack, BUFLEN)) <= 0){
		print_debug_log ("[debug] [error] [sproto_unpack() failed!]\n");
		return 0;
	}

	if ((stype = sproto_type(spro_new, "package")) == NULL){
		print_debug_log ("[debug] [error] [sproto_type() failed!]\n");
		return 0;
	}

	if ((header_len = sproto_decode(stype, unpack, unpack_len, sproto_parser_cb, ud)) <= 0){
		print_debug_log ("[debug] [error] [sproto_decode() failed!]\n");
		return 0;
	}

	return header_len;
}

int sproto_parser(char *data, int headlen, struct encode_ud *ud)
{
	struct sproto_type *stype;
	int len;

	if ((stype = sproto_protoquery(spro_new, ud->type, ud->session)) == NULL){
		print_debug_log ("[debug] [error] [sproto_protoquery() failed!]\n");
		return 0;
	}

	if ((len = sproto_decode(stype, data + headlen, BUFLEN, sproto_parser_cb, ud)) <= 0){
		print_debug_log ("[debug] [error] [sproto_decode() failed!]\n");
		return 0;
	}

	return len;
}


void free_mem(ap_status_entry *ap)
{
	if (ap == NULL){
		return;
	}

	ap->online = OFF;
	ap->status = AC_INIT_OFFLINE;
	
	if (ap->client_addr != NULL){
		ustream_free (&ap->client_addr->s.stream);
		
		if (ap->client_addr->s.fd.fd > 0){
			close(ap->client_addr->s.fd.fd);
		}
		
		ap->client_addr->s.fd.fd = 0;
		ap->fd = 0;
		free (ap->client_addr);
		ap->client_addr = NULL;
	}

	return;
}


int ap_online_proc(ap_status_entry * ap, int sfd, struct sockaddr_in *localaddr)
{
	int len;
	int i;
	char res[1024 * 2] = {0};
	char index[64] = {0};
	tmplat_list *tp = NULL;
	
	if (ap == NULL || sfd <= 0){
		return 0;
	}
	
	/*when the hash node is new creat,so,use the default tmplate id*/
	if( ap->status ==AC_NEW_HASH_NODE ){
		for ( i = 0;i<=AP_MAX_BINDID;i++){
			if (ap->apinfo.id & (0x01<<i)){
				if ((tp = template_find_by_id(i)) != NULL){
					memcpy(&(ap->apinfo.wifi_info.ssid_info[i]),&(tp->tmplate_info.tmplat_ssid_info),sizeof(ap_ssid_info));
				}
			}
		}
	}
	
	if (strlen(ap->apinfo.wifi_info.channel) <1){
		strcpy (ap->apinfo.wifi_info.channel, "auto\0");
	}
	
	if (strlen(ap->apinfo.wifi_info.txpower) <1){
		strcpy (ap->apinfo.wifi_info.txpower, "18\0");
	}
	
	if (strlen(ap->apname) <1){
		strcpy (ap->apname, "");
	}
	
	strcpy (ap->apinfo.rip, inet_ntoa(localaddr->sin_addr));
	ap->status = AC_AP_HASH_NODE_ON;
	ap->fd = sfd;
	format_ap_cfg (ap, res);

	sprintf(index,"mac=%02x:%02x:%02x:%02x:%02x:%02x",\
		ap->apinfo.apmac[0]&0xff,\
		ap->apinfo.apmac[1]&0xff,\
		ap->apinfo.apmac[2]&0xff,\
		ap->apinfo.apmac[3]&0xff,\
		ap->apinfo.apmac[4]&0xff,\
		ap->apinfo.apmac[5]&0xff);
	file_write(AP_LIST_FILE, index, res);

	ap->ud.type = AP_INFO;
	ap->ud.session = SPROTO_REQUEST;
	len = send_data_to_ap (ap);

	return len;
}

int rcv_and_proc_data(char *data, int len, struct client *cl)
{
	int slen;
	int headlen;
	int status = 0;
	ecode_ud_spro 	ud;
	char unpack[1024 * 6] = { 0 };
	sta_entry *stal= NULL;
	ap_status_entry *apl = NULL ;
	ap_status_entry *ap = NULL;

	print_debug_log ("[debug] [rcv] [data len:%d, fd:%d]\n", len, cl->s.fd.fd);
	
	/*sproto header parse：type and session*/
	memset(&ud,0,sizeof(ecode_ud_spro));
	if ((headlen = sproto_header_parser(data, len, &ud, unpack)) <= 0){
		print_debug_log ("[debug] [error] [sproto header parser failed!!]\n");
		return -1;
	}

	print_debug_log("%s %d type:%d session:%d\n",__FUNCTION__,__LINE__,ud.type,ud.session);
	if(ud.type == STA_INFO){
		//for station
		stalist_entry_init(&sta_status_info_receive);
		stal = &sta_status_info_receive;
		memcpy(&(stal->ud),&ud,sizeof(ud));

		/*sproto encoded data parse*/
		if (sproto_parser (unpack, headlen, &ud) <= 0){
			print_debug_log ("[debug] [error] [sproto_parser() failed!]\n");
		}
	
		stalist_entry_update(stal);
		
		return ACd_STATUS_OK;
	}else if (ud.type == AC_INFO){
		stalist_entry_init(&sta_status_info_receive);
		stal = &sta_status_info_receive;
		memcpy(&(stal->ud),&ud,sizeof(ud));
		/*sproto encoded data parse*/
		if (sproto_parser (unpack, headlen, &ud) <= 0){
			print_debug_log ("[debug] [error] [sproto_parser() failed!]\n");
		}

		/*must dynamic get the ac info*/
		get_ac_info();
		ac_info.fd = cl->s.fd.fd;
		ac_info.ud.type = AC_INFO;
		ac_info.ud.ok = RESPONSE_OK;
		ac_info.ud.session = SPROTO_RESPONSE;

		send_acinfo_to_ap (&ac_info);

		return ACd_STATUS_OK;
	}else if (ud.type == AP_CMD){
		aplist_entry_init(&apcfg_receive);
		apl = &apcfg_receive;
		apl->client_addr = cl;
		memcpy(&(apl->ud),&ud,sizeof(ud));
		//print_debug_log("%s %d model:%s mac:%02x:%02x:%02x:%02x:%02x:%02x sn:%s \n",__FUNCTION__,__LINE__,\
				apl->apinfo.model,apl->apinfo.apmac[0],apl->apinfo.apmac[1],apl->apinfo.apmac[2],apl->apinfo.apmac[3],apl->apinfo.apmac[4],apl->apinfo.apmac[5],\
				apl->apinfo.sn);
		if (sproto_parser (unpack, headlen, &(ud)) <= 0){
			print_debug_log ("[debug] [error] [sproto_parser() failed!]\n");
			goto error;
		}

		/*after decode the sproto data ,find the hash node*/
		if ( apl->apinfo.apmac != NULL ){
			ap = aplist_entry_find(&aplist.hash[aplist_entry_hash(apl->apinfo.apmac)],apl->apinfo.apmac);
			
			if(ap && ud.session == SPROTO_RESPONSE && ud.ok == RESPONSE_OK){
				free_mem(ap);
				return ACd_STATUS_REBOOT_OK;	
			}
		}
	
		//print_debug_log("%s %d model:%s mac:%02x:%02x:%02x:%02x:%02x:%02x sn:%s \n",__FUNCTION__,__LINE__,\
				apl->apinfo.model,apl->apinfo.apmac[0],apl->apinfo.apmac[1],apl->apinfo.apmac[2],apl->apinfo.apmac[3],apl->apinfo.apmac[4],apl->apinfo.apmac[5],\
				apl->apinfo.sn);
		return ACd_STATUS_OK;
	}else if(ud.type == AP_INFO ){
		/*AP_INFO(AC config the AP) don't handle if OK*/
		if (ud.session != SPROTO_RESPONSE){
			return -2;
		}

		aplist_entry_init(&apcfg_receive);
		apl = &apcfg_receive;
		apl->client_addr = cl;
		memcpy(&(apl->ud),&ud,sizeof(ud));

		if (sproto_parser (unpack, headlen, &(ud)) <= 0){
			print_debug_log ("[debug] [error] [sproto_parser() failed!]\n");
			goto error;
		}

		if (ud.ok == RESPONSE_ERROR){
			/*after decode the sproto data ,we creat/update hash list*/
			if ( apl->apinfo.apmac != NULL ){
				ap = aplist_entry_find(&aplist.hash[aplist_entry_hash(apl->apinfo.apmac)],apl->apinfo.apmac);
				
				if(ap){
					ap->ud.session = SPROTO_REQUEST;
					ap->ud.type = AP_INFO;
					slen = send_data_to_ap (ap);
					return ACd_STATUS_OK;	
				}
			}

		}else{
			print_debug_log ("[debug] <receive> [response pack]\n");
			return ACd_STATUS_OK;
		}
	}else if(ud.type == AP_STATUS){/*AP_STATUS->ap send the heart beat to ac*/
		//for ap online and update the time
		aplist_entry_init(&apcfg_receive);
		apl = &apcfg_receive;
		apl->client_addr = cl;
		memcpy(&(apl->ud),&ud,sizeof(ud));
		apl->online = ON;

		if (sproto_parser (unpack, headlen, &(ud)) <= 0){
			print_debug_log ("[debug] [error] [sproto_parser() failed!]\n");
			goto error;
		}

		/*after decode the sproto data ,we creat/update hash list*/
		if ( apl->apinfo.apmac != NULL ){
			/*for_each to find hash node*/
			ap = aplist_entry_insert(apl->apinfo.apmac);

			if ( ap ){
				ap->online = apl->online;
				if (ap->status == AC_NEW_HASH_NODE || ap->status == AC_INIT_OFFLINE ){
					/*fix:when chang the AC control device network dhcp range ,maybe cause ap can't communicate with ac,ac can't send date to ap*/
					if(ap->fd > 0){
						close(ap->fd);
					}
					ap->client_addr = cl;
					status = AC_NEW_HASH_NODE;
				}else{
					/*fix:when chang the AC control device network dhcp range ,maybe cause ap can't communicate with ac,ac can't send date to ap*/
					if(ap->fd == DEFAULT_FD){
						status = AC_NEW_HASH_NODE;
						ap->client_addr = cl;
					}else if( ap->fd != cl->s.fd.fd ){
						if(ap->client_addr->s.fd.fd > 0){
							close(ap->client_addr->s.fd.fd);
							ap->client_addr = cl;
							ap->fd = cl->s.fd.fd;
							strcpy (ap->apinfo.rip, inet_ntoa(cl->localaddr.sin_addr));
						}
					}
				}
				gettime(&ap->last_tv);
				memcpy(&(ap->ud),&(apl->ud),sizeof(ecode_ud_spro));
				/*update the ap info :hver,sver,sn,aip,model,stamac*/
				strcpy(ap->apinfo.hver,apl->apinfo.hver);
				strcpy(ap->apinfo.sver,apl->apinfo.sver);
				strcpy(ap->apinfo.sn,apl->apinfo.sn);
				strcpy(ap->apinfo.aip,apl->apinfo.aip);
				strcpy(ap->apinfo.model,apl->apinfo.model);
			}else{
				return -2;
			}
			
			if (status ==AC_NEW_HASH_NODE  && ap->ud.session == SPROTO_REQUEST){
				return ap_online_proc (ap, cl->s.fd.fd, &cl->localaddr);
			}else{
				ap->ud.session = SPROTO_RESPONSE;
				ap->ud.ok = RESPONSE_OK;
				slen = send_data_to_ap (ap);
				
				return ACd_STATUS_OK;
			}
		}
	}
error:
	ap->ud.session = SPROTO_RESPONSE;
	ap->ud.ok = RESPONSE_ERROR;
	slen = send_data_to_ap (ap);
	print_debug_log ("[debug] <send> [data len:%d]\n", slen);

	return -1;
}

int prepare_tmplist_data(ap_status_entry * ap)
{
	int i;

	if (ap == NULL){
		return -1;
	}

	if (ap->ud.type == AP_INFO && ap->ud.session == SPROTO_REQUEST){
		/*temp method,after will change method*/
		memset(temp_ssid,'\0',sizeof(temp_ssid));
		memset(temp_encrypt,'\0',sizeof(temp_encrypt));
		memset(temp_key,'\0',sizeof(temp_key));
		memset(temp_disabled,'\0',sizeof(temp_disabled));
		memset(temp_hidden,'\0',sizeof(temp_hidden));
		memset(temp_type,'\0',sizeof(temp_type));

		for (i = 0; i<=MAX_TMP_ID; i++){
			if(ap->apinfo.id & (0x01<<i)){
				if (template_find_by_id(i) != NULL){
					sprintf(temp_ssid+strlen((const char *)temp_ssid),"%s,",&(ap->apinfo.wifi_info.ssid_info[i].ssid[0]));
					sprintf(temp_encrypt+strlen((const char *)temp_encrypt),"%s,",&(ap->apinfo.wifi_info.ssid_info[i].encrypt[0]));
					sprintf(temp_key+strlen((const char *)temp_key),"%s,",&(ap->apinfo.wifi_info.ssid_info[i].key[0]));
					sprintf(temp_disabled+strlen((const char *)temp_disabled),"%d,",ap->apinfo.wifi_info.ssid_info[i].disabled);
					sprintf(temp_hidden+strlen((const char *)temp_hidden),"%d,",ap->apinfo.wifi_info.ssid_info[i].hidden);
					sprintf(temp_type+strlen((const char *)temp_type),"%d,",ap->apinfo.wifi_info.ssid_info[i].type);
				}
			}
		}

		temp_ssid[strlen((const char *)temp_ssid)-1] = '\0';
		temp_encrypt[strlen((const char *)temp_encrypt)-1] = '\0';
		temp_key[strlen((const char *)temp_key)-1] = '\0';
		temp_disabled[strlen((const char *)temp_disabled)-1] = '\0';
		temp_hidden[strlen((const char *)temp_hidden)-1] = '\0';
		temp_type[strlen((const char *)temp_type)-1] = '\0';
	}

	return 0;
}

int prepare_device_data(device_info * ac)
{
	if (ac == NULL){
		return -1;
	}
	
	if(ac->ud.type == AC_INFO && ac->ud.session == SPROTO_RESPONSE){
		memset(temp_device_info,0,sizeof(temp_device_info));
	
		sprintf(temp_device_info,"{\"sn\":\"%s\",\"moid\":\"%s\",\"dt\":%d}",ac->sn,ac->moid,ac->dt);
	}

	return 0;
}

int send_data_to_ap (ap_status_entry * ap)
{
	int psize;
	int len;
	char res[BUFLEN] = { 0 };

	if (ap == NULL){
		return -1;
	}

	prepare_tmplist_data(ap);

	psize = sproto_encode_data (&ap->ud, res);
	if (ap->fd <= 0){
		return 0;
	}
	
	len = write (ap->fd, res, psize);

	return len;
}

int send_acinfo_to_ap (device_info * ac)
{
	int psize;
	int len;
	char res[BUFLEN] = { 0 };

	if (ac == NULL){
		return -1;
	}

	prepare_device_data(ac);
	psize = sproto_encode_data (&ac->ud, res);
	if (ac->fd <= 0){
		return 0;
	}

	len = write (ac->fd, res, psize);

	return len;
}

void print_debug_log(const char *form ,...)
{
	if (debug == NULL){
		return;
	}

	va_list arg;
	char pbString[256];

	va_start (arg, form);
	vsprintf (pbString, form, arg);
	fprintf (debug, pbString);
	va_end (arg);
	return;
}

int proc_template_edit(tmplat_list *tpcfg, struct ubus_request_data *req)
{
	char change = FALSE;
	int  i;
	ap_status_entry *ap = NULL;

	blob_buf_init (&b, 0);
	/*show all ap info in this AC*/
	for(i = 0;i < AP_HASH_SIZE;i++){
		if (hlist_empty(&(aplist.hash[i]))){
			continue;
		}
		hlist_for_each_entry(ap, &(aplist.hash[i]), hlist) {	
			if (((0x01 << tpcfg->tmplate_info.id) & ap->apinfo.id)){
				memset(&(ap->apinfo.wifi_info.ssid_info[tpcfg->tmplate_info.id]),'\0',sizeof(ap_ssid_info));
				memcpy(&(ap->apinfo.wifi_info.ssid_info[tpcfg->tmplate_info.id]),&(tpcfg->tmplate_info.tmplat_ssid_info),sizeof(ap_ssid_info));
				change = TRUE;
			}
			if (change == TRUE){
				ap->ud.type = AP_INFO;
				ap->ud.session = SPROTO_REQUEST;
				send_data_to_ap (ap);
				change = FALSE;
			}
		}
	}

	blobmsg_add_u32 (&b, "code", 0);
	
	return ubus_send_reply (ctx, req, b.head);
}

void format_tmp_cfg(tmplat_list *tpcfg, char *res)
{
	char buf[1024] = { 0 };
	
	sprintf (buf + strlen (buf), "name=%s", tpcfg->tmplate_info.tpname);
	sprintf (buf + strlen (buf), "|id=%d", tpcfg->tmplate_info.id);
	sprintf (buf + strlen (buf), "|ssid=%s", tpcfg->tmplate_info.tmplat_ssid_info.ssid);
	sprintf (buf + strlen (buf), "|encrypt=%s", tpcfg->tmplate_info.tmplat_ssid_info.encrypt);
	sprintf (buf + strlen (buf), "|key=%s", tpcfg->tmplate_info.tmplat_ssid_info.key);
	sprintf (buf + strlen (buf), "|auth=%d",tpcfg->tmplate_info.tmplat_ssid_info.auth);
	sprintf (buf + strlen (buf), "|type=%d",tpcfg->tmplate_info.tmplat_ssid_info.type);
	sprintf (buf + strlen (buf), "|disabled=%d",tpcfg->tmplate_info.tmplat_ssid_info.disabled);
	sprintf (buf + strlen (buf), "|hidden=%d",tpcfg->tmplate_info.tmplat_ssid_info.hidden);
	strcpy (res, buf);
	res[strlen (buf)] = 0;
	
	return;
}

void format_ap_cfg(ap_status_entry *ap, char *res)
{
	char tbuf[1024];
	
	bzero (tbuf, sizeof (tbuf));
	
	sprintf (tbuf + strlen (tbuf), "mac=%02x:%02x:%02x:%02x:%02x:%02x", ap->apinfo.apmac[0]&0xff,\
		ap->apinfo.apmac[1]&0xff,\
		ap->apinfo.apmac[2]&0xff,\
		ap->apinfo.apmac[3]&0xff,\
		ap->apinfo.apmac[4]&0xff,\
		ap->apinfo.apmac[5]&0xff);
	sprintf (tbuf + strlen (tbuf), "|name=%s", ap->apname);
	sprintf (tbuf + strlen (tbuf), "|sn=%s", ap->apinfo.sn);
	sprintf (tbuf + strlen (tbuf), "|model=%s", ap->apinfo.model);
	sprintf (tbuf + strlen (tbuf), "|id=%d", ap->apinfo.id);
	sprintf (tbuf + strlen (tbuf), "|txpower=%s", ap->apinfo.wifi_info.txpower);
	sprintf (tbuf + strlen (tbuf), "|hver=%s", ap->apinfo.hver);
	sprintf (tbuf + strlen (tbuf), "|sver=%s", ap->apinfo.sver);
	sprintf (tbuf + strlen (tbuf), "|aip=%s", ap->apinfo.aip);
	sprintf (tbuf + strlen (tbuf), "|channel=%s", ap->apinfo.wifi_info.channel);
	strncpy (res, tbuf, strlen (tbuf));
	res[strlen (res)] = '\0';
	
	return;
}

static void template_to_blob(struct blob_buf *buf, tmplat_list *t)
{
	blobmsg_add_string (buf, "name", t->tmplate_info.tpname);
	blobmsg_add_u32 (buf, "id", t->tmplate_info.id);
	blobmsg_add_string (buf, "ssid", t->tmplate_info.tmplat_ssid_info.ssid);
	blobmsg_add_string (buf, "encrypt",  t->tmplate_info.tmplat_ssid_info.encrypt);
	blobmsg_add_string (buf, "key",  t->tmplate_info.tmplat_ssid_info.key);
	blobmsg_add_u32 (buf, "auth", t->tmplate_info.tmplat_ssid_info.auth);
	blobmsg_add_u32 (buf, "type", t->tmplate_info.tmplat_ssid_info.type);
	blobmsg_add_u32 (buf, "disabled", t->tmplate_info.tmplat_ssid_info.disabled);
	blobmsg_add_u32 (buf, "hidden", t->tmplate_info.tmplat_ssid_info.hidden);
	return;
}

static void apinfo_to_json_string(struct blob_buf *buf, ap_status_entry *ap)
{
	int i;
	unsigned int sta_num = 0;
	unsigned int sta_2G_num = 0;
	unsigned int sta_5G_num = 0;
	unsigned int sta_guest_num = 0;
	unsigned int sta_guest_2G_num = 0;
	unsigned int sta_guest_5G_num = 0;

	char mac_temp[32] = {'\0'};
	char ssid_temp[64] = {'\0'};
	void *arr = NULL;
	char *table = NULL;
	long td;
	struct timeval tv;
	sta_entry *station = NULL;

	
	if (buf == NULL || ap == NULL){
		return;
	}
	
	blobmsg_add_string (buf, "name", ap->apname);

	if (ap->online != OFF) {
		gettime(&tv);
		td = tv_diff(&tv, &ap->last_tv);
		
		if (td > (HEAR_BEAT_INTEVAL)) {// 30s
			print_debug_log ("[debug] set offline for lost heartbeat %lu\n", td);
			ap->online = OFF;
			ap->status = AC_INIT_OFFLINE;
		}
	}
	
	blobmsg_add_u32 (buf, "online", ap->online);
	arr = blobmsg_open_array (buf, "id");
	for ( i = 0;i<=AP_MAX_BINDID;i++){
		if (ap->apinfo.id & (0x01<<i)){
			blobmsg_add_u32 (buf, NULL, i);
		}
	}

	blobmsg_close_array (buf, arr);

	sprintf(mac_temp,"%02x:%02x:%02x:%02x:%02x:%02x",\
		ap->apinfo.apmac[0]&0xff,\
		ap->apinfo.apmac[1]&0xff,\
		ap->apinfo.apmac[2]&0xff,\
		ap->apinfo.apmac[3]&0xff,\
		ap->apinfo.apmac[4]&0xff,\
		ap->apinfo.apmac[5]&0xff);
	blobmsg_add_string (buf, "mac", mac_temp);
	blobmsg_add_string (buf, "sn", ap->apinfo.sn);
	blobmsg_add_string (buf, "model", ap->apinfo.model);
	blobmsg_add_string (buf, "hver", ap->apinfo.hver);
	blobmsg_add_string (buf, "sver", ap->apinfo.sver);
	blobmsg_add_string (buf, "aip", ap->apinfo.aip);
	blobmsg_add_string (buf, "rip", ap->apinfo.rip);
	blobmsg_add_string (buf, "channel", ap->apinfo.wifi_info.channel);
	blobmsg_add_string (buf, "txpower", ap->apinfo.wifi_info.txpower);

	arr = blobmsg_open_array (buf, "sta");
	/*show all station info in this AP*/
	for(i = 0;i < AP_HASH_SIZE;i++){
		if (hlist_empty(&(stalist.hash[i]))){
			continue;
		}
		hlist_for_each_entry(station, &(stalist.hash[i]), hlist) {
			if (ether_addr_equal((const u8 *)station->ap_mac,(const u8 *)ap->apinfo.apmac)){
				table = blobmsg_open_table (&b, NULL);
				memset(mac_temp,'\0',sizeof(mac_temp));
				sprintf(mac_temp,"%02x:%02x:%02x:%02x:%02x:%02x",\
					station->mac[0]&0xff,\
					station->mac[1]&0xff,\
					station->mac[2]&0xff,\
					station->mac[3]&0xff,\
					station->mac[4]&0xff,\
					station->mac[5]&0xff);
				blobmsg_add_string(buf, "mac", mac_temp);
				memset(mac_temp,'\0',sizeof(mac_temp));
				sprintf(mac_temp,"%02x:%02x:%02x:%02x:%02x:%02x",\
					station->bssid[0]&0xff,\
					station->bssid[1]&0xff,\
					station->bssid[2]&0xff,\
					station->bssid[3]&0xff,\
					station->bssid[4]&0xff,\
					station->bssid[5]&0xff);
				blobmsg_add_string(buf, "bssid", mac_temp);
				blobmsg_add_u32 (buf, "online", station->status);
				blobmsg_add_u32 (buf, "type", station->type);
				memset(ssid_temp,'\0',sizeof(ssid_temp));
				sprintf(ssid_temp,"%s",station->ssid);
				blobmsg_add_string(buf, "ssid", ssid_temp);

				/*for statistic*/
				sta_num = sta_num +1;

				if(station->auth == STATION_AUTH_GUEST){
					if(station->type){
						sta_guest_5G_num = sta_guest_5G_num +1;
					}else{
						sta_guest_2G_num = sta_guest_2G_num +1;
					}
					sta_guest_num = sta_guest_num +1;
				}

				if(station->type){
					sta_5G_num = sta_5G_num +1;
				}else{
					sta_2G_num = sta_2G_num +1;
				}

				blobmsg_close_table (&b, table);
			}
		}
	}
	blobmsg_close_array (buf, arr);
	blobmsg_add_u32 (buf, "sta_num", sta_num);
	blobmsg_add_u32 (buf, "sta_2G_num", sta_2G_num);
	blobmsg_add_u32 (buf, "sta_5G_num", sta_5G_num);

	blobmsg_add_u32 (buf, "sta_guest_num", sta_guest_num);
	blobmsg_add_u32 (buf, "sta_guest_2G_num", sta_guest_2G_num);
	blobmsg_add_u32 (buf, "sta_guest_5G_num", sta_guest_5G_num);
	return;
}


static const struct blobmsg_policy apinfo_policy[__APINFO_MAX] = {
	[APINFO_MAC] = {.name = "mac",.type = BLOBMSG_TYPE_STRING},
};

static int ubus_proc_apinfo(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__APINFO_MAX];
	int i;
	unsigned char mac_value[ETH_ALEN] = {0};
	char *mac = NULL;
	void *arr = NULL;
	char *table = NULL;
	ap_status_entry *ap = NULL;
	struct hlist_head *head = NULL;
	
	
	blob_buf_init (&b, 0);
	blobmsg_parse(apinfo_policy, ARRAY_SIZE(apinfo_policy), tb, blob_data(msg), blob_len(msg));
	
	if (tb[MAC]){
		mac = blobmsg_get_string (tb[MAC]);
		/*use the mac to find the ap exist*/
		if ( mac != NULL){
			mac_string_to_value((unsigned char *)mac,mac_value);
			head = &aplist.hash[aplist_entry_hash(mac_value)];
			ap = aplist_entry_find(head,mac_value);
			if(ap != NULL){
				apinfo_to_json_string (&b, ap);
				return ubus_send_reply (ctx, req, b.head);
			}
		}
		
		blobmsg_add_u32 (&b, "code", 1);
		blobmsg_add_string (&b, "msg", "not found this ap, mac not exist in this AC!");
		return ubus_send_reply (ctx, req, b.head);
	}
	
	/*show all ap info in this AC*/
	arr = blobmsg_open_array (&b, "data");
	
	for(i = 0;i < AP_HASH_SIZE;i++){
		if (hlist_empty(&(aplist.hash[i]))){
			continue;
		}
		hlist_for_each_entry(ap, &(aplist.hash[i]), hlist) {
			if (ap != NULL){
				table = blobmsg_open_table (&b, NULL);
				apinfo_to_json_string (&b, ap);
				blobmsg_close_table (&b, table);
			}
		}
	}
	
	if (i == AP_HASH_SIZE){
		blobmsg_close_array (&b, arr);
		return ubus_send_reply (ctx, req, b.head);
	}
	blobmsg_add_u32 (&b, "code", 1);
	ubus_send_reply (ctx, req, b.head);
	
	return 0;
}

int apedit_cb(struct blob_attr **tb, struct ubus_request_data *req)
{
	
	int len;
	int i = 0;
	unsigned char temp_id = 0x00;
	char temp_buf[64] = {'\0'};
	char res[1024] = {'\0'};
	char index[64] = {'\0'};
	char id[32][8] = {{'\0'}};
	int template_id;
	unsigned char mac_value[ETH_ALEN] = {'\0'};
	char is_digit = IS_DIGIT_STRING_ERR;
	char *mac = NULL;
	char *channel = NULL;
	char *txpower = NULL;
	char *apname = NULL;
	char *aip = NULL;
	struct blob_attr *attr;
	struct blob_attr *dt;
	struct hlist_head *head =NULL;
	ap_status_entry *ap = NULL;
	tmplat_list *tpl = NULL;	
	
	
	blob_buf_init (&b, 0);

	if (tb[MAC]){
		mac = blobmsg_get_string (tb[MAC]);
	}
	
	if (tb[CHANNEL]){
		channel = blobmsg_get_string (tb[CHANNEL]);
	}
	
	if (tb[TXPOWER]){
		txpower = blobmsg_get_string (tb[TXPOWER]);
	}
	
	if (tb[NAME]){
		apname = blobmsg_get_string (tb[NAME]);
	}

	if (tb[AIP]){
		aip = blobmsg_get_string (tb[AIP]);
	}
	
	/*use the mac to find the ap exist*/
	if ( mac != NULL){
		mac_string_to_value((unsigned char *)mac,mac_value);
		head = &aplist.hash[aplist_entry_hash(mac_value)];
		ap = aplist_entry_find(head,mac_value);
		
		if(ap == NULL){
			blobmsg_add_string (&b, "msg", "not found this ap or ap offline!");
			goto error;
		}
	}
	
	if (channel != NULL && channel[0] != 0){
		if(strcasecmp("auto", channel) != 0){
			is_digit = is_digit_string(channel);
			if ( is_digit != IS_DIGIT_STRING){
				blobmsg_add_string (&b, "msg", "channel invalid 1~13 or auto available!");
				goto error;
			}else{
				if (atoi(channel) > 13 || atoi(channel) < 1){
					blobmsg_add_string (&b, "msg", "channel invalid 1~13 or auto available!");
					goto error;
				}
			}
		}

		memset (ap->apinfo.wifi_info.channel, '\0', sizeof (ap->apinfo.wifi_info.channel));
		strncpy (ap->apinfo.wifi_info.channel, channel, strlen (channel));

	}

	if (txpower != NULL && txpower[0] != 0){
		if (atoi(txpower) > 23 || atoi(txpower) < 1){
			blobmsg_add_string (&b, "msg", "txpower invalid!");
			goto error;
		}

		is_digit = IS_DIGIT_STRING_ERR;
		is_digit = is_digit_string(txpower);
		if ( is_digit != IS_DIGIT_STRING){
			blobmsg_add_string (&b, "msg", "txpower invalid 1~20  available!");
			goto error;
		}

		memset (ap->apinfo.wifi_info.txpower, '\0', sizeof (ap->apinfo.wifi_info.txpower));
		strncpy (ap->apinfo.wifi_info.txpower, txpower, strlen (txpower));
	}

	if (apname != NULL && apname[0] != 0){
		memset (ap->apname, '\0', sizeof (ap->apname));
		strncpy (ap->apname, apname, strlen (apname));
	}
	/*tempid 使用数组为了关联多个模板，实现multi ssid*/
	if (tb[TMPLATID]){
		dt = blobmsg_data (tb[TMPLATID]);
		len = blobmsg_data_len (tb[TMPLATID]);
		
		
		__blob_for_each_attr(attr, dt, len) {
			sprintf (id[i++], "%d", blobmsg_get_u32 (attr));
		}
		
		if ( i > AP_MAX_BINDID){
			blobmsg_add_string (&b, "msg", "Max bind 8 template at the same time!");
			goto error;
		}
	}
	
	for (i = 0; id[i][0] != 0; i++){
		template_id = atoi(&id[i][0]);
		if ((tpl = template_find_by_id (template_id)) == NULL){
			sprintf(temp_buf,"%d not exist!",template_id);
			blobmsg_add_string (&b, "template_id", temp_buf);
			continue;
		}

		memset (&(ap->apinfo.wifi_info.ssid_info[template_id]),'\0',sizeof (ap_ssid_info));
		set_bit(temp_id,template_id); //bit set,0~7bit <->0~7 templateid
		memcpy(&(ap->apinfo.wifi_info.ssid_info[template_id]),&(tpl->tmplate_info.tmplat_ssid_info),sizeof(ap_ssid_info));
	}

	if (temp_id >0){
		ap->apinfo.id = temp_id;
	}

	format_ap_cfg (ap, res);
	sprintf(index,"mac=%02x:%02x:%02x:%02x:%02x:%02x",\
		ap->apinfo.apmac[0]&0xff,\
		ap->apinfo.apmac[1]&0xff,\
		ap->apinfo.apmac[2]&0xff,\
		ap->apinfo.apmac[3]&0xff,\
		ap->apinfo.apmac[4]&0xff,\
		ap->apinfo.apmac[5]&0xff);
	file_write(AP_LIST_FILE, index, res);

	ap->ud.type = AP_INFO;
	ap->ud.session = SPROTO_REQUEST;
	
	if (send_data_to_ap (ap) <= 0){
		blobmsg_add_string (&b, "msg", "Distributed configuration failed");
		goto error;
	}

    apinfo_to_json_string (&b, ap);
	blobmsg_add_u32 (&b, "code", 0);
	
	return ubus_send_reply (ctx, req, b.head);

error:
	blobmsg_add_u32 (&b, "code", 1);
	
	return ubus_send_reply (ctx, req, b.head);
}

static const struct blobmsg_policy apedit_policy[__CFG_MAX] = {
	[MAC] = {.name = "mac",.type = BLOBMSG_TYPE_STRING},
	[NAME] = {.name = "name",.type = BLOBMSG_TYPE_STRING},
	[AIP] ={.name = "aip",.type = BLOBMSG_TYPE_STRING },
	[TMPLATID] = {.name = "templateid",.type = BLOBMSG_TYPE_ARRAY},
	[CHANNEL] = {.name = "channel",.type = BLOBMSG_TYPE_STRING},
	[TXPOWER] = {.name = "txpower",.type = BLOBMSG_TYPE_STRING},
};

static int ubus_proc_apedit(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__CFG_MAX];

	blobmsg_parse(apedit_policy, __CFG_MAX, tb, blob_data(msg), blob_len(msg));
	
	return apedit_cb (tb, req);
}

int templatedit_cb(struct blob_attr **tb, struct ubus_request_data *req)
{
	int  id = -1;
	int  hidden = 0;				//default 0,wifi show
	int  disabled = 0;				//default 0,wifi on
	int  type = 0;					//default 0,2.4G
	int  auth = 0;					//default 0,no auth
	char hidden_changed = 0;
	char disabled_changed = 0;
	char type_changed = 0;
	char auth_changed = 0;
	char edit_temp0_flag = FALSE;
	char index[64] = {0};
	char res[1024] = {0};
	char *ssid = NULL;
	char *key = NULL;
	char *encrypt = NULL;
	char *tpname = NULL;
	tmplat_list *tp = NULL;
	
	blob_buf_init (&b, 0);

	if (tb[TMPLATID]){
		id = blobmsg_get_u32 (tb[TMPLATID]);
	}

	if (tb[SSID]){
		ssid = blobmsg_get_string (tb[SSID]);
	}

	if (tb[ENCRYPT]){
		encrypt = blobmsg_get_string (tb[ENCRYPT]);
	}

	if (tb[KEY]){
		key = blobmsg_get_string (tb[KEY]);
	}

	if (tb[NAME]){
		tpname = blobmsg_get_string (tb[NAME]);
	}

	if (tb[EDIT_FLAG] ){
		edit_temp0_flag = blobmsg_get_bool(tb[EDIT_FLAG]);
	}

	if (tb[HIDDEN]){
		hidden = blobmsg_get_u32 (tb[HIDDEN]);
		hidden_changed = 1;
	}

	if (tb[DISABLED]){
		disabled = blobmsg_get_u32 (tb[DISABLED]);
		disabled_changed = 1;
	}

	if (tb[TYPE]){
		type = blobmsg_get_u32 (tb[TYPE]);
		type_changed = 1;
	}

	if (tb[AUTH]){
		auth = blobmsg_get_u32 (tb[AUTH]);
		auth_changed = 1;
	}

	if (id < 0){
		blobmsg_add_string (&b, "msg", "Need template id!");
		goto error;
	}
	
	/*the default template can't be modified by user*/
	if ( ( id == 0  && edit_temp0_flag== FALSE) || (tp = template_find_by_id (id)) == NULL){
		blobmsg_add_string (&b, "msg", "template id invalid");
		goto error;
	}
	
	/*get the templatedit id*/
	tp = template_find_by_id (id);
	if(tp == NULL){
		blobmsg_add_string (&b, "msg", "template id invalid");
		goto error;
	}

	if (ssid != NULL && ssid[0] != 0){
		strcpy (tp->tmplate_info.tmplat_ssid_info.ssid, ssid);
	}
	
	if (tpname != NULL && tpname[0] != 0){
		strcpy (tp->tmplate_info.tpname, tpname);
	}
	
	if (data_range_in(hidden,0,1) == 0){

		blobmsg_add_string (&b, "msg", "hidden value(0 or 1) invalid");
		goto error;
	}else{
		if(hidden_changed){
			tp->tmplate_info.tmplat_ssid_info.hidden = hidden;
		}
	}

	if (data_range_in(disabled,0,1) == 0){
		blobmsg_add_string (&b, "msg", "disabled value(0 or 1) invalid");
		goto error;
	}else{
		if(disabled_changed){
			tp->tmplate_info.tmplat_ssid_info.disabled = disabled;
		}
	}

	if (data_range_in(type,0,2) == 0){
		blobmsg_add_string (&b, "msg", "type value(0 or 1,2) invalid");
		goto error;
	}else{
		if(type_changed){
			tp->tmplate_info.tmplat_ssid_info.type = type;
		}
	}

	if (data_range_in(auth,0,1) == 0){
		blobmsg_add_string (&b, "msg", "auth value(0 or 1) invalid");
		goto error;
	}else{
		if(auth_changed){
			tp->tmplate_info.tmplat_ssid_info.auth = auth;
		}
	}

	if (encrypt != NULL && encrypt[0] != 0){
		if (strcasecmp(encrypt, "none") != 0){
			if (strcasecmp(encrypt,"psk") == 0 ){
				strcpy (tp->tmplate_info.tmplat_ssid_info.encrypt, encrypt);
			}else if(strcasecmp(encrypt,"psk-mixed") == 0 ){
				strcpy (tp->tmplate_info.tmplat_ssid_info.encrypt, encrypt);
			}else if(strcasecmp(encrypt,"psk2") == 0){
				strcpy (tp->tmplate_info.tmplat_ssid_info.encrypt, encrypt);
			}else{
				blobmsg_add_string (&b, "msg", "Encrypt support 'psk psk-mixed psk2' method!");
				goto error;
			}

			if (key == NULL || key[0] == 0){
				blobmsg_add_string (&b, "msg", "need key");
				goto error;
			}else if(key != NULL && key[0] != 0){
				if (strlen (key) < 8){
					blobmsg_add_string (&b, "msg", "Invalid key");
					goto error;
				}
				strcpy (tp->tmplate_info.tmplat_ssid_info.key, key);
			}
		}else{
			strcpy (tp->tmplate_info.tmplat_ssid_info.encrypt, encrypt);
			strcpy (tp->tmplate_info.tmplat_ssid_info.key, "");
		}
	}
	
	sprintf (index, "id=%d", id);
	format_tmp_cfg (tp, res);
	file_write(TP_LIST_FILE, index, res);
	/*sort the tplist file*/
	file_sort_by_key(TP_LIST_FILE,3,"=");

	return proc_template_edit (tp, req);

error:
	blobmsg_add_u32 (&b, "code", 1);
	
	return ubus_send_reply (ctx, req, b.head);
}

static const struct blobmsg_policy templatedit_policy[__CFG_MAX] = {
	[TMPLATID] = {.name = "id",.type = BLOBMSG_TYPE_INT32},
	[NAME] = {.name = "name",.type = BLOBMSG_TYPE_STRING},
	[SSID] = {.name = "ssid",.type = BLOBMSG_TYPE_STRING},
	[ENCRYPT] = {.name = "encrypt",.type = BLOBMSG_TYPE_STRING},
	[KEY] = {.name = "key",.type = BLOBMSG_TYPE_STRING},
	[HIDDEN] = {.name = "hidden",.type = BLOBMSG_TYPE_INT32},
	[DISABLED] = {.name = "disabled",.type = BLOBMSG_TYPE_INT32},
	[TYPE] = {.name = "type",.type = BLOBMSG_TYPE_INT32},
	[AUTH] = {.name = "auth",.type = BLOBMSG_TYPE_INT32},
	[EDIT_FLAG] = {.name = "edit_flag",.type = BLOBMSG_TYPE_BOOL },
};

static int ubus_proc_templatedit(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method,
		       struct blob_attr *msg)
{
	struct blob_attr *tb[__CFG_MAX];
	
	blobmsg_parse(templatedit_policy, __CFG_MAX, tb, blob_data(msg), blob_len(msg));

	return templatedit_cb (tb, req);
}

int templatedel_cb(struct blob_attr **tb, struct ubus_request_data *req)
{
	int i;
	char change = FALSE;
	char res[1024] = {0};
	char index[64] = {'\0'};
	int id = ILLEGAL_TMPLATE_ID;
	tmplat_list *tp = NULL;
	ap_status_entry *ap = NULL;

	if (tb[TMPLATID]){
		id = blobmsg_get_u32 (tb[TMPLATID]);
	}
	
	blob_buf_init (&b, 0);
	if (id == ILLEGAL_TMPLATE_ID || id == DEFAULT_TMPLATE_ID){
		blobmsg_add_string (&b, "msg", "Defalut template can'be deleate ,Need template id!");
		goto error;
	}
	
	if ((tp = template_find_by_id (id)) == NULL){
		blobmsg_add_string (&b, "msg", "id error,not found this template");
		goto error;
	}
	
	/*show all ap info in this AC*/
	for(i = 0;i < AP_HASH_SIZE;i++){
		if (hlist_empty(&(aplist.hash[i]))){
			continue;
		}
		hlist_for_each_entry(ap, &(aplist.hash[i]), hlist) {	
			if (((0x01 << tp->tmplate_info.id) & ap->apinfo.id)){
				print_debug_log("%s %d tpid:%d apid:%d\n",__FUNCTION__,__LINE__,tp->tmplate_info.id,ap->apinfo.id);
				memset(&(ap->apinfo.wifi_info.ssid_info[tp->tmplate_info.id]),'\0',sizeof(ap_ssid_info));
				clear_bit(ap->apinfo.id,tp->tmplate_info.id);
				
				if (ap->apinfo.id == DEFAULT_TMPLATE_ID){
					if ((tp = template_find_by_id (DEFAULT_TMPLATE_ID)) != NULL){
						memcpy(&(ap->apinfo.wifi_info.ssid_info[DEFAULT_TMPLATE_ID]),&(tp->tmplate_info.tmplat_ssid_info),sizeof(ap_ssid_info));
						set_bit(ap->apinfo.id,DEFAULT_TMPLATE_ID);
					}
				}
				change =TRUE;
			}
			
			if (change){
				if (ap->online != OFF ){
					ap->ud.type = AP_INFO;
					ap->ud.session = SPROTO_REQUEST;
					send_data_to_ap (ap);
				}

				format_ap_cfg (ap, res);
				sprintf(index,"mac=%02x:%02x:%02x:%02x:%02x:%02x",\
					ap->apinfo.apmac[0]&0xff,\
					ap->apinfo.apmac[1]&0xff,\
					ap->apinfo.apmac[2]&0xff,\
					ap->apinfo.apmac[3]&0xff,\
					ap->apinfo.apmac[4]&0xff,\
					ap->apinfo.apmac[5]&0xff);
				file_write(AP_LIST_FILE, index, res);
				change = FALSE;
			}
		}
	}
	
	memset(index,'\0',sizeof(index));
	sprintf (index, "id=%d", id);
	file_spec_content_del(TP_LIST_FILE, index);
	template_del_by_id (tplist, id);
	/*sort the tplist file*/
	file_sort_by_key(TP_LIST_FILE,3,"=");

	blobmsg_add_u32 (&b, "code", 0);

	return ubus_send_reply (ctx, req, b.head);

error:
	blobmsg_add_u32 (&b, "code", 1);
	return ubus_send_reply (ctx, req, b.head);
}

static const struct blobmsg_policy templatedel_policy[__CFG_MAX] = {
	[TMPLATID] = {.name = "id",.type = BLOBMSG_TYPE_INT32},
};

static int ubus_proc_templatedel(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method,
		       struct blob_attr *msg)
{
	struct blob_attr *tb[__CFG_MAX];
	
	blobmsg_parse(templatedel_policy, __CFG_MAX, tb, blob_data(msg), blob_len(msg));
	
	return templatedel_cb (tb, req);
}

static const struct blobmsg_policy templatelist_policy[__CFG_MAX] = {
	[TMPLATID] = {.name = "id",.type = BLOBMSG_TYPE_INT32},
};

static int ubus_proc_templatelist(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__CFG_MAX];
	tmp_info tmp_array[MAX_TMP_ID+1] = {'\0'};
	int id = ILLEGAL_TMPLATE_ID ;
	int i ;
	tmplat_list *tp = tplist;
	tmplat_list *p = NULL;
	void *arr = NULL;
	char *table = NULL;

	blobmsg_parse(templatelist_policy, __CFG_MAX, tb, blob_data(msg), blob_len(msg));
	
	if (tb[TMPLATID]){
		id = blobmsg_get_u32 (tb[TMPLATID]);
		p = template_find_by_id (id);
	}

	blob_buf_init (&b, 0);
	
	if (p != NULL){
		template_to_blob (&b, p);
		return ubus_send_reply (ctx, req, b.head);
	}
	
	if (id != ILLEGAL_TMPLATE_ID){
		blobmsg_add_u32 (&b, "code", 1);
		blobmsg_add_string (&b, "msg", "template info not found");
		return ubus_send_reply (ctx, req, b.head);
	}

	arr = blobmsg_open_array (&b, "data");
	
	/*show all template list*/
	while (tp->rlink){
		tp = tp->rlink;
		memcpy(&tmp_array[tp->tmplate_info.id],&(tp->tmplate_info),sizeof(tmp_info));
		//print_debug_log("%s,%d id:%d,tp:%d\n",__FUNCTION__,__LINE__,tmp_array[tp->tmplate_info.id].id,tp->tmplate_info.id);
	}

	for(i = 0;i<=MAX_TMP_ID;i++){
		if(tmp_array[i].id != i){
			continue;
		}
		table = blobmsg_open_table (&b, (const char *)&tmp_array[i].id);
		//template_to_blob (&b, &(tmp_array[i]));
		blobmsg_add_string (&b, "name", tmp_array[i].tpname);
		blobmsg_add_u32 (&b, "id", tmp_array[i].id);
		blobmsg_add_string (&b, "ssid", tmp_array[i].tmplat_ssid_info.ssid);
		blobmsg_add_string (&b, "encrypt",  tmp_array[i].tmplat_ssid_info.encrypt);
		blobmsg_add_string (&b, "key",  tmp_array[i].tmplat_ssid_info.key);
		blobmsg_add_u32 (&b, "auth", tmp_array[i].tmplat_ssid_info.auth);
		blobmsg_add_u32 (&b, "type", tmp_array[i].tmplat_ssid_info.type);
		blobmsg_add_u32 (&b, "disabled", tmp_array[i].tmplat_ssid_info.disabled);
		blobmsg_add_u32 (&b, "hidden", tmp_array[i].tmplat_ssid_info.hidden);
		blobmsg_close_table (&b, table);
	}

	blobmsg_close_array (&b, arr);

	return ubus_send_reply (ctx, req, b.head);
}

static const struct blobmsg_policy templateadd_policy[__CFG_MAX] = {
	[SSID] = {.name = "ssid",.type = BLOBMSG_TYPE_STRING},
	[ENCRYPT] = {.name = "encrypt",.type = BLOBMSG_TYPE_STRING},
	[KEY] = {.name = "key",.type = BLOBMSG_TYPE_STRING},
	[NAME] = {.name = "name",.type = BLOBMSG_TYPE_STRING},
	[HIDDEN] = {.name = "hidden",.type = BLOBMSG_TYPE_INT32},
	[DISABLED] = {.name = "disabled",.type = BLOBMSG_TYPE_INT32},
	[TYPE] = {.name = "type",.type = BLOBMSG_TYPE_INT32},
	[AUTH] = {.name = "auth",.type = BLOBMSG_TYPE_INT32},
};

static int ubus_proc_templateadd(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method,
		       struct blob_attr *msg)
{
	struct blob_attr *tb[__CFG_MAX];
	int  hidden = 0;				//default 0,wifi show
	int  disabled = 0;				//default 0,wifi on
	int  type = 0;					//default 0,2.4G
	int  auth = 0;					//default 0,no auth
	char index[64] = {0};
	char res[1024] = {0};
	int id = DEFAULT_TMPLATE_ID +1;
	char *ssid = NULL;
	char *encrypt = NULL;
	char *key = NULL;
	char *tpname = NULL;
	tmplat_list p, *tpl = NULL;

	blobmsg_parse(templateadd_policy, __CFG_MAX, tb, blob_data(msg), blob_len(msg));
	
	if (tb[SSID]){
		ssid = blobmsg_get_string (tb[SSID]);
	}
	
	if (tb[ENCRYPT]){
		encrypt = blobmsg_get_string (tb[ENCRYPT]);
	}
	
	if (tb[KEY]){
		key = blobmsg_get_string (tb[KEY]);
	}
	
	if (tb[NAME]){
		tpname = blobmsg_get_string (tb[NAME]);
	}

	if (tb[HIDDEN]){
		hidden = blobmsg_get_u32 (tb[HIDDEN]);
	}

	if (tb[DISABLED]){
		disabled = blobmsg_get_u32 (tb[DISABLED]);
	}

	if (tb[TYPE]){
		type = blobmsg_get_u32 (tb[TYPE]);
	}
	
	if (tb[AUTH]){
		auth = blobmsg_get_u32 (tb[AUTH]);
	}

	blob_buf_init (&b, 0);
	memset(&p, 0, sizeof(tmplat_list));
	if (ssid == NULL || ssid[0] == 0){
		blobmsg_add_string (&b, "msg", "Need ssid!");
		goto error;
	}else if (strlen(ssid) > MAX_SSID_LEN){
		blobmsg_add_string (&b, "msg", "SSID len must small to 32 bytes!");
		goto error;
	}

	while (1){
		if ((tpl = template_find_by_id(id)) == NULL){
			break;
		}
		id++;
	}
	
	if ( id > MAX_TMP_ID){
		blobmsg_add_string (&b, "msg", "Max have eight template!");
		goto error;
	}

	if (tpname != NULL && tpname[0] != 0){
		strcpy(p.tmplate_info.tpname, tpname);
	}
	
	if (data_range_in(hidden,0,1) == 0){

		blobmsg_add_string (&b, "msg", "hidden value(0 or 1) invalid");
		goto error;
	}else{
		p.tmplate_info.tmplat_ssid_info.hidden = hidden;
	}

	if (data_range_in(disabled,0,1) == 0){
		blobmsg_add_string (&b, "msg", "disabled value(0 or 1) invalid");
		goto error;
	}else{
		p.tmplate_info.tmplat_ssid_info.disabled = disabled;
	}

	if (data_range_in(type,0,1) == 0){
		blobmsg_add_string (&b, "msg", "type value(0 or 1) invalid");
		goto error;
	}else{
		p.tmplate_info.tmplat_ssid_info.type = type;
	}

	if (data_range_in(auth,0,1) == 0){
		blobmsg_add_string (&b, "msg", "auth value(0 or 1) invalid");
		goto error;
	}else{
		p.tmplate_info.tmplat_ssid_info.auth = auth;
	}

	strcpy (&(p.tmplate_info.tmplat_ssid_info.ssid[0]), ssid);
	p.tmplate_info.id = id;

	if (encrypt != NULL && encrypt[0] != 0){
		/*need encrypt*/
		if (strcasecmp(encrypt, "none") != 0){
			if (strcasecmp(encrypt,"psk") == 0 ){
				strcpy (&(p.tmplate_info.tmplat_ssid_info.encrypt[0]), encrypt);
			}else{
				blobmsg_add_string (&b, "msg", "the encrypt just support 'psk' method!");
				goto error;
			}

			if (key == NULL || key[0] == 0 ){
				blobmsg_add_string (&b, "msg", "Need key!");
				goto error;
			}else{
				if (strlen(key) < 8 || strlen(key) > MAX_SSID_LEN){
					blobmsg_add_string (&b, "msg", "the key length must greater than or equal 8,and must less than 32!");
					goto error;
				}
				strcpy (&(p.tmplate_info.tmplat_ssid_info.key[0]), key);
			}
		}else{/*none*/
			strcpy (&(p.tmplate_info.tmplat_ssid_info.encrypt[0]), "none");
			strcpy (&(p.tmplate_info.tmplat_ssid_info.key[0]), "");
		}
	}else{/*default none encrypt*/
		strcpy (&(p.tmplate_info.tmplat_ssid_info.encrypt[0]), "none");
		strcpy (&(p.tmplate_info.tmplat_ssid_info.key[0]), "");
	}
	
	if (template_insert_by_id (&p) <= 0){
		goto error;
	}
	
	sprintf (index, "id=%d", p.tmplate_info.id);
	format_tmp_cfg (&p, res);
	file_write(TP_LIST_FILE, index, res);
	/*sort the tplist file*/
	file_sort_by_key(TP_LIST_FILE,3,"=");

	blobmsg_add_u32 (&b, "code", 0);
	
	return ubus_send_reply (ctx, req, b.head);

error:
	blobmsg_add_u32 (&b, "code", 2);
	return ubus_send_reply (ctx, req, b.head);
}

static const struct blobmsg_policy apdel_policy[__CFG_MAX] = {
	[MAC] = {.name = "mac",.type = BLOBMSG_TYPE_STRING},
	[SN] = {.name = "sn",.type = BLOBMSG_TYPE_STRING},
};

static int ubus_proc_apdel(struct ubus_context *ctx, struct ubus_object *obj,
		 struct ubus_request_data *req, const char *method,
		 struct blob_attr *msg)
{
	struct blob_attr *tb[__CFG_MAX];
	unsigned char mac_value[ETH_ALEN] = {0};
	char index[64] = {'\0'};
	char *mac = NULL;
	char *sn = NULL;
	ap_status_entry *ap = NULL;
	struct hlist_head *head =NULL;

	blobmsg_parse(apdel_policy, __CFG_MAX, tb, blob_data(msg), blob_len(msg));
	if (tb[MAC]){
		mac = blobmsg_get_string (tb[MAC]);
	}
	
	if (tb[SN]){
		sn = blobmsg_get_string (tb[SN]);
	}
	
	blob_buf_init (&b, 0);
	/*use the mac to find the ap exist*/
	if ( mac != NULL){
		mac_string_to_value((unsigned char *)mac,mac_value);
		head = &aplist.hash[aplist_entry_hash(mac_value)];
		ap = aplist_entry_find(head,mac_value);

		if ( ap == NULL ){
			blobmsg_add_u32 (&b, "code", 1);
			blobmsg_add_string (&b, "msg", "not find this ap!");
			goto end;
		}
		
		if ( sn && sn[0] != 0){
			if (strcmp(ap->apinfo.sn ,sn) != 0){
				ap = NULL;
				blobmsg_add_string (&b, "msg", "the sn not matched the mac address!");
			}
		}
		
		if (ap == NULL){
			blobmsg_add_u32 (&b, "code", 1);
			goto end;
		}
	}else{
		blobmsg_add_u32 (&b, "code", 1);
		blobmsg_add_string (&b, "msg", "need mac address!");
		goto end;
	}
	
	sprintf (index, "mac=%s", mac);
	aplist_entry_remove(mac_value);
	file_spec_content_del(AP_LIST_FILE, index);
	blobmsg_add_u32 (&b, "code", 0);

end:
	return ubus_send_reply (ctx, req, b.head);
}

static const struct blobmsg_policy apcmd_policy[__CFG_MAX] = {
	[MAC] = {.name = "mac",.type = BLOBMSG_TYPE_STRING},
	[SN] = {.name = "sn",.type = BLOBMSG_TYPE_STRING},
	[CMD] = {.name = "cmd",.type = BLOBMSG_TYPE_STRING},
	[ADDR] = {.name = "addr",.type = BLOBMSG_TYPE_STRING},
};

static int ubus_proc_apcmd(struct ubus_context *ctx, struct ubus_object *obj,
		 struct ubus_request_data *req, const char *method,
		 struct blob_attr *msg)
{
	struct blob_attr *tb[__CFG_MAX];
	unsigned char mac_value[ETH_ALEN] = {0};
	int len = 0;
	char *mac = NULL;
	char *addr = NULL;
	char *cmd = NULL;
	char *sn = NULL;
	ap_status_entry *ap = NULL;
	struct hlist_head *head =NULL;

	blobmsg_parse(apcmd_policy, __CFG_MAX, tb, blob_data(msg), blob_len(msg));
	
	if (tb[MAC]){
		mac = blobmsg_get_string (tb[MAC]);
	}
	
	if (tb[SN]){
		sn = blobmsg_get_string (tb[SN]);
	}
	
	if (tb[CMD]){
		cmd = blobmsg_get_string (tb[CMD]);
	}
	
	blob_buf_init (&b, 0);
	/*use the mac to find the ap exist*/
	if ( mac != NULL){
		mac_string_to_value((unsigned char *)mac,mac_value);
		head = &aplist.hash[aplist_entry_hash(mac_value)];
		ap = aplist_entry_find(head,mac_value);
		
		if ( ap == NULL ){
			blobmsg_add_u32 (&b, "code", 1);
			blobmsg_add_string (&b, "msg", "not find this ap!");
			goto error;
		}

		if ( sn && sn[0] != 0){
			if (strcmp(ap->apinfo.sn ,sn) != 0){
				ap = NULL;
				blobmsg_add_string (&b, "msg", "the sn not matched the mac address!");
			}
		}
		
		if (ap == NULL){
			blobmsg_add_u32 (&b, "code", 1);
			goto error;
		}
	}else{
		blobmsg_add_u32 (&b, "code", 1);
		blobmsg_add_string (&b, "msg", "need mac address!");
		goto error;
	}

	if (ap->online == OFF){
		blobmsg_add_string (&b, "msg", "ap off-line");
		goto error;
	}
	
	if (cmd == NULL || cmd[0] == 0){
		blobmsg_add_string (&b, "msg", "mac invalid or need command");
		goto error;
	}
	
	if (strcasecmp(cmd, "reboot") == 0){
		ap->ud.type = AP_CMD;
		ap->ud.session = SPROTO_REQUEST;
		ap->cmd.cmd = REBOOT;
		if ((len = send_data_to_ap (ap)) <= 0){
			goto error;
		}else{
			ap->cmd.status = AP_CMD_SENDED_FLAG;
		}
	}else if (strcasecmp(cmd, "upgrade") == 0){
		
		if (tb[ADDR]){
			addr = blobmsg_get_string (tb[ADDR]);
		}
		
		if (addr == NULL || addr[0] == 0){
			goto error;
		}
		ap->ud.type = AP_CMD;
		ap->ud.session = SPROTO_REQUEST;
		ap->cmd.cmd = UPGRADE;
		strcpy (ap->cmd.addr, addr);
		if ((len = send_data_to_ap (ap)) <= 0){
			goto error;
		}
	}
	
	blobmsg_add_u32 (&b, "code", 0);
	ubus_send_reply (ctx, req, b.head);
	
	return UBUS_STATUS_OK;

error:
	blobmsg_add_u32 (&b, "code", 2);
	
	return ubus_send_reply (ctx, req, b.head);
}


static const struct ubus_method acd_methods[] = {
	UBUS_METHOD_MASK ("apinfo", ubus_proc_apinfo, apinfo_policy, 1 << MAC),
	UBUS_METHOD_MASK ("apedit", ubus_proc_apedit, apedit_policy, 1 << MAC | 1 << NAME | 1 << TMPLATID | 1 << CHANNEL | 1 << TXPOWER | 1<< AIP),
	UBUS_METHOD_MASK ("templatedit", ubus_proc_templatedit, templatedit_policy, 1 << TMPLATID | 1 << SSID | 1 << ENCRYPT | 1 << NAME | 1 << KEY | 1<<AUTH | 1<<TYPE | 1<< DISABLED | 1<<HIDDEN | 1<<EDIT_FLAG),
	UBUS_METHOD_MASK ("templatelist", ubus_proc_templatelist, templatelist_policy, 1 << TMPLATID),
	UBUS_METHOD_MASK ("templateadd", ubus_proc_templateadd, templateadd_policy, 1 << SSID | 1 << ENCRYPT | 1 << NAME | 1 << KEY | 1<<AUTH | 1<<TYPE | 1<< DISABLED | 1<<HIDDEN ),
	UBUS_METHOD_MASK ("templatedel", ubus_proc_templatedel, templatedel_policy, 1 << TMPLATID),
	UBUS_METHOD_MASK ("apdel", ubus_proc_apdel, apdel_policy,  1 << MAC | 1 << SN),
	UBUS_METHOD_MASK ("apcmd", ubus_proc_apcmd, apcmd_policy, 1 << MAC | 1 << SN | 1 << CMD | 1 << ADDR),
};

static struct ubus_object_type acd_object_type = UBUS_OBJECT_TYPE ("acd", acd_methods);

static struct ubus_object acd_object = {
	.name = "acd",
	.type = &acd_object_type,
	.methods = acd_methods,
	.n_methods = ARRAY_SIZE (acd_methods),
};

static void server_main(void)
{
	int ret;

	ret = ubus_add_object (ctx, &acd_object);
	
	if (ret){
		fprintf (stderr, "Failed to add object: %s\n", ubus_strerror (ret));
	}

	return;
}

static void run_server(void)
{
	server.cb = server_cb;
	server.fd = usock(USOCK_TCP | USOCK_SERVER | USOCK_IPV4ONLY | USOCK_NUMERIC, "0.0.0.0", port);
	
	if (server.fd < 0) {
		fprintf (stderr, "Failed to listen on port %s\n", port);
		sleep(3);
		run_server();
		return;
	}

	uloop_fd_add (&server, ULOOP_READ | ULOOP_WRITE);
}

static int usage(char *prog)
{
	printf(
			"Usage: %s [OPTIONS] DIRECTORY...\n"
	  "Options:\n"
	  "        -p     set server port\n"
	  "        -d     show debug infomastion\n"
	  "        -s     Set the unix domain socket to connect to\n"
	  "        -v     show software version\n"
	  "\n", prog);
	return 1;
}


int aplist_hash_init(void)
{
	int i ;

	/*for hash and kmem*/
	get_random_bytes(&ap_listdb_salt, sizeof(ap_listdb_salt));

    /*init the aplist  hash*/
    for(i = 0;i < AP_HASH_SIZE;i++){
		INIT_HLIST_HEAD(&(aplist.hash[i]));
	}
	
	return 0;
}

int stalist_hash_init(void)
{
	int i ;

	/*for hash and kmem*/
	get_random_bytes(&sta_listdb_salt, sizeof(sta_listdb_salt));

    /*init the aplist  hash*/
    for(i = 0;i < AP_HASH_SIZE;i++){
		INIT_HLIST_HEAD(&(stalist.hash[i]));
	}

	return 0;
}

void aplist_entry_init(ap_status_entry *aplist_node)
{
	memset(aplist_node,0,sizeof(ap_status_entry));
}

void stalist_entry_init(sta_entry *stalist_node)
{
	memset(stalist_node,0,sizeof(sta_entry));
}

void acd_init(void)
{
	char buf[64] = {0};
	
	if ((tplist = template_entry_init()) == NULL){
		exit (0);
	}
	
	if (sproto_read_entity (APC_SP_FILE) <= 0){
		printf("Can't read sproto");
		exit(0);
	}

	if (access (AP_LIST_FILE, F_OK) != 0){
		sprintf(buf,"touch %s",AP_LIST_FILE);
		system (buf);
	}
	
	if (access (TP_LIST_FILE, F_OK) != 0){
		sprintf(buf,"touch %s",TP_LIST_FILE);
		system (buf);
	}

	aplist_hash_init();
	stalist_hash_init();
	get_ac_info();
	tplist_init ();
	aplist_init ();
	
	return;
}

int main(int argc, char **argv)
{
	int ch;
	const char *ubus_socket = NULL;
	while ((ch = getopt(argc, argv, "dp:s:")) != -1){
		switch(ch) {
			case 'p':
			  port = optarg;
			  break;
			case 'd':
			  debug = stdout;
			  break;
			case 's':
			  ubus_socket = optarg;
			  break;
			default:
			  return usage (argv[0]);
		}
	}
	
	uloop_init ();
	sta_noauth_init();
	signal (SIGPIPE, SIG_IGN);

	ctx = ubus_connect (ubus_socket);
	
	if (!ctx) {
	  fprintf (stderr, "Failed to connect to ubus\n");
	  return -1;
	}

	timeout.cb = set_ac_dns_address;
	sta_timeout.cb = check_station_status;
	ubus_add_uloop (ctx);
	acd_init ();
	run_server ();
	server_main ();
	uloop_timeout_set(&timeout, DNS_SET_INTERVAL);
	uloop_timeout_set(&sta_timeout, STATION_STATUS_CHECK_INTERVAL);
	uloop_run ();

	ubus_free (ctx);
	uloop_done ();

	return 1;
}
