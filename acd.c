#include "acd.h"

const char 	*port 	= "4444"; //acd 服务器监听端口
FILE 		*debug 	= NULL;
static struct uloop_fd 		server;
static struct client 		*next_client = NULL;
static struct sproto 		*spro_new = NULL;	//the protocol
static struct ubus_context  *ctx;
static struct blob_buf b;

unsigned int ap_listdb_salt;
ap_list aplist;	//ap information list
tmplat_list *tplist 	= NULL;
static ap_status_entry p_temp_ap_info;

static void gettime(struct timeval *tv)
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

static void mac_string_to_value(unsigned char *mac,unsigned char *buf)
{
    int i;
    int len;

	if(mac && buf){
		len = strlen((const char *)mac);
		for (i=0;i<(len-5)/2;i++){
			sscanf((const char *)mac+i*3,"%2x",&buf[i]);
		}
	}
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
		ustream_set_read_blocked (s, true);
	}
}

static void client_close(struct ustream *s)
{
	struct client *cl = container_of (s, struct client, s.stream);
	ap_status_entry *ap = NULL;

	print_debug_log ("[debug] [fd:%d connection closed!!]\n", cl->s.fd.fd);
	
	/*if ((ap = find_apmember (NULL, NULL, cl->s.fd.fd)) != NULL){
		free_mem(ap);
	}*/
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


	cl->s.stream.string_data = true;
	cl->s.stream.notify_read = client_read_cb;
	cl->s.stream.notify_state = client_notify_state;

	ustream_fd_init (&cl->s, sfd);
	next_client = NULL;
	print_debug_log("[debug] [New connection] [local ip:%s]\n", inet_ntoa(cl->localaddr.sin_addr));
	print_debug_log("[debug] [New connection] [peer ip:%s fd:%d]\n", inet_ntoa(cl->sin.sin_addr), sfd);
}

void aplist_init(void)
{
	
	int file_size;
	char buf[512] = {'\0'};
	char *p_buf = NULL;
	char key[32] = {'\0'};
	unsigned char mac[6] = {0};
	char value[128] = {'\0'};
	char *p_key_value = NULL;
	char *optstr = NULL;
	tmplat_list *tp = NULL;
	FILE *fp =NULL;
	ap_status_entry *ap = NULL;
	
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
	
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	
	if (file_size == 0){
		fclose(fp);
		return;
	}
	
	fseek(fp,0,SEEK_SET);
	/*get the aplist file content*/
	while((fgets(buf,512,fp))!=NULL){
		/*get the mac address of ap*/
		if (!(strlen(buf) <=1 && buf[0] ==10)){ //排除文件换行无内容情况
			p_buf = buf;
			p_key_value = strtok(p_buf,"|");

			while(p_key_value){			
				memset(key,'\0',sizeof(key));
				memset(value ,'\0',sizeof(value));
				optstr = strstr (p_key_value, "=");
				strncpy (key, p_key_value, optstr - p_key_value);
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
					ap->status = 0;    //init the aplist  set the status to zero
					fill_data (ap, key, value, strlen (value));
				}else{
					break;
				}
				p_key_value = strtok (NULL, "|");
			}
			/*find the aplist id <-> tmplate id,if id not exist,use default tmplate,else use tmplate id*/
			if ((tp = find_template(ap->apinfo.id)) !=NULL && ap){
				memcpy(&(ap->apinfo.wifi_info.ssid_info),&(tp->tmplat_ssid_info),sizeof(tp->tmplat_ssid_info));
			}else if ((tp = find_template (DEFAULT_TMPLATE_ID)) != NULL && ap){
				ap->apinfo.id = tp->id;
				memcpy(&(ap->apinfo.wifi_info.ssid_info),&(tp->tmplat_ssid_info),sizeof(tp->tmplat_ssid_info));
			}
			
			memset(buf,'\0',sizeof(512));
			ap = NULL ;
		}	
	}
	
	fclose(fp);

	return ;
	
}

void tplist_init(void)
{

	int file_size;
	tmplat_list tp;
	char buf[512];
	char key[32] = {'\0'};
	char value[128] = {'\0'};
	char *optstr;
	FILE *fp =NULL;
	char *p_buf = NULL;
	char *p_key_value = NULL;
	
	/*1:read the content from the tplist*/
	if (access(TP_LIST_FILE, F_OK) != 0){
		return;
	}

	if ((fp = fopen(TP_LIST_FILE, "r")) == NULL){
		return;
	}
	
	/*for old tplist file cut the ap_cfg_xx= header line*/
	sprintf(buf,"sed -i 's/^ap_cfg_[0-9]*=//g' %s",TP_LIST_FILE);
	system(buf);
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	if (file_size == 0){
		/*no contents - write the default value for default template*/
		strcpy(buf, "name=default|id=0|ssid=MoreWiFi|encrypt=none|key=");
		file_write(TP_LIST_FILE, "id=0", buf);
		fclose(fp);
		return;
	}

	fseek(fp,0,SEEK_SET);
	/*get the tplist file content*/
	while((fgets(buf,512,fp))!=NULL){
		/*get the mac address of ap*/
		if (!(strlen(buf) <=1 && buf[0] ==10)){ //排除文件换行无内容情况
			p_buf = buf;
			p_key_value = strtok(p_buf,"|");

			while(p_key_value){
				memset(key,'\0',sizeof(key));
				memset(value ,'\0',sizeof(value));
				optstr = strstr (p_key_value, "=");
				strncpy (key, p_key_value, optstr - p_key_value);
				strncpy (value, optstr + 1,strlen(optstr)-1);

				/*fill data in the double link list node*/
				if (strcasecmp(key, "name") == 0){
					strcpy(tp.tpname,value);
				}else if (strcasecmp (key, "id") == 0){
					tp.id = (char )atoi(value);
				}else if (strcasecmp (key, "ssid") == 0){
					strcpy(tp.tmplat_ssid_info.ssid,value);
				}else if (strcasecmp (key, "encrypt") == 0){
					strcpy(tp.tmplat_ssid_info.encrypt,value);
				}else if (strcasecmp (key, "key") == 0){
					strcpy(tp.tmplat_ssid_info.key,key);
				}

				p_key_value = strtok (NULL, "|");
			}
			
			insert_template (&tp);
			memset (&tp, '\0', sizeof (tmplat_list));
			memset(buf,'\0',sizeof(512));
		}
	}
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
	ap_status_entry *apcfg = container_of (ud, ap_status_entry, ud);

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
			fill_encode_data (apcfg, (char *) tagname, (char *) value);
			print_debug_log("[debug] [encode] [%s:] [%s]\n", tagname, (char *)value);
			size_t sz = strlen ((char *) value);
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
		strcpy (value, apcfg->apinfo.wifi_info.ssid_info.ssid);
	}else if (strcasecmp (tagname, "channel") == 0){
		strcpy (value, apcfg->apinfo.wifi_info.channel);
	}else if (strcasecmp (tagname, "encrypt") == 0){
		strcpy (value, apcfg->apinfo.wifi_info.ssid_info.encrypt);
	}else if (strcasecmp (tagname, "key") == 0){
		strcpy (value, apcfg->apinfo.wifi_info.ssid_info.key);
	}else if (strcasecmp (tagname, "txpower") == 0){
		strcpy (value, apcfg->apinfo.wifi_info.txpower);
	}else if (strcasecmp (tagname, "addr") == 0){
		strcpy (value, apcfg->cmd.addr);
	}else if (strcasecmp (tagname, "md5") == 0){
		strcpy (value, apcfg->cmd.md5);
	}
	return;
}

void fill_data(ap_status_entry *apcfg, char *tagname, char *value, int len)
{
	int slen = 0;
	
	if (apcfg == NULL || strlen (value) == 0 || len == 0){
		return;
	}

	if (strcasecmp (tagname, "hver") == 0){
		strncpy (apcfg->apinfo.hver, value, len);
	}else if (strcasecmp (tagname, "model") == 0){
		strncpy (apcfg->apinfo.model, value, len);
	}else if (strcasecmp (tagname, "sver") == 0){
		strncpy (apcfg->apinfo.sver, value, len);
	}else if (strcasecmp (tagname, "sn") == 0){
		strncpy (apcfg->apinfo.sn, value, len);
	}else if (strcasecmp (tagname, "aip") == 0){
		strncpy (apcfg->apinfo.aip, value, len);
	}else if (strcasecmp (tagname, "mac") == 0){
		strncpy ((char *)apcfg->apinfo.apmac, value, len);
	}else if (strcasecmp (tagname, "channel") == 0){
		strncpy (apcfg->apinfo.wifi_info.channel, value, len);
	}else if (strcasecmp (tagname, "id") == 0){
		apcfg->apinfo.id = atoi(value);
	}else if (strcasecmp(tagname, "name") == 0){
		strncpy(apcfg->apname, value, len);
	}else if (strcasecmp(tagname, "txpower") == 0){
		strncpy(apcfg->apinfo.wifi_info.txpower, value, len);
	}else if (strcasecmp(tagname, "stamac") == 0){
		if (apcfg->stamac == NULL){
			if ((apcfg->stamac = calloc(MAC_LEN, 1)) == NULL){
				return;
			}
			apcfg->len = MAC_LEN;
		}
		
		slen = strlen(apcfg->stamac);
		if (apcfg->len - slen < 18){
			apcfg->len += MAC_LEN;
			if ((apcfg->stamac = realloc(apcfg->stamac, apcfg->len)) == NULL){
				return;
			}
		}
		
		char buf[18] = {0};
		strncpy(buf, value, len);
		sprintf(apcfg->stamac + slen, "%s,", buf);
		apcfg->stamac[slen + len + 1] = 0;
	}
	return;
}

int sproto_parser_cb(void *ud, const char *tagname, int type, int index, struct sproto_type *st, void *value, int length)
{
	struct encode_ud *self = ud;
	ap_status_entry *apcfg = container_of (ud, ap_status_entry, ud);
	char val[256] = {0};
	int r;
	
	if (!(tagname && ud && apcfg)){
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
			}
			
			print_debug_log ("[debug] [%s] [%d] [decode] [%s:] [%d]\n", __FUNCTION__,__LINE__, tagname, *(int *) value);
			break;
		
		case SPROTO_TBOOLEAN:
			self->ok = *(int *) value;
			print_debug_log ("[debug] [decode] [%s:] [%d]\n", tagname, *(int *) value);
			break;
		
		case SPROTO_TSTRING:
			strncpy(val, value, length);
			fill_data (apcfg, (char *) tagname, val, length);
			print_debug_log("[debug] [decode] [%s: %s,%d]\n", tagname, val, length);
			break;
		
		case SPROTO_TSTRUCT:
			r = sproto_decode (st, value, length, sproto_parser_cb, self);
			
			if (r < 0 || r != length){
				return r;
			}
			break;
		
		default:
		print_debug_log ("[debug] [unknown type]\n");
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
	ap_status_entry *apcfg = container_of (ud, ap_status_entry, ud);

	if (apcfg->stamac != NULL && ud->type == AP_STATUS){
		free(apcfg->stamac);
		apcfg->len = 0;
		apcfg->stamac = NULL;
	}
	
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
	
	if (ap->stamac != NULL){
		free(ap->stamac);
		ap->stamac = NULL;
		ap->len = 0;
	}
	
	return;
}


int ap_online_proc(ap_status_entry * ap, int sfd, struct sockaddr_in *localaddr)
{
	int len;
	char res[1024 * 2] = {0};
	char index[64] = {0};
	tmplat_list *tp = NULL;
	
	if (ap == NULL || sfd <= 0){
		return 0;
	}
	
	/*when the hash node is new creat,so,use the default tmplate id*/
	if( ap->status ==1){
		if ((tp = find_template (DEFAULT_TMPLATE_ID)) != NULL && ap){
			ap->apinfo.id = tp->id;
			memcpy(&(ap->apinfo.wifi_info.ssid_info),&(tp->tmplat_ssid_info),sizeof(tp->tmplat_ssid_info));
		}
		
		if ((tp = find_template (DEFAULT_TMP_GUEST_ID)) != NULL && ap){
			ap->apinfo.id_guest = tp->id;
			memcpy(&(ap->apinfo.wifi_info.ssid_info_guest),&(tp->tmplat_ssid_info),sizeof(tp->tmplat_ssid_info));	
		}
	}
	
	if (strlen(ap->apinfo.wifi_info.channel) <1){
		strcpy (ap->apinfo.wifi_info.channel, "auto");
	}
	
	if (strlen(ap->apinfo.wifi_info.txpower) <1){
		strcpy (ap->apinfo.wifi_info.txpower, "18");
	}
	
	if (strlen(ap->apname) <1){
		strcpy (ap->apname, "");
	}
	
	strcpy (ap->apinfo.rip, inet_ntoa(localaddr->sin_addr));
	ap->status = 2;
	format_ap_cfg (ap, res);
	sprintf(index,"mac=%s",ap->apinfo.apmac);
	file_write(AP_LIST_FILE, index, res);
	ap->ud.type = AP_INFO;
	ap->ud.session = SPROTO_REQUEST;
	len = send_data_to_ap (ap);
	print_debug_log("%s,%d\n",__FUNCTION__,__LINE__);
	
	return len;
}

int rcv_and_proc_data(char *data, int len, struct client *cl)
{
	int slen;
	int headlen;
	int status = 0;
	char unpack[1024 * 6] = { 0 };
	struct client *p_cltaddr =NULL;
	ap_status_entry *apl = NULL, *ap = NULL;
	
	print_debug_log ("[debug] [rcv] [data len:%d, fd:%d]\n", len, cl->s.fd.fd);
	
	apl = &p_temp_ap_info;
	apl->client_addr = cl;
	apl->online = ON;
	
	/*sproto header parse：type and session*/
	if ((headlen = sproto_header_parser(data, len, &(apl->ud), unpack)) <= 0){
		print_debug_log ("[debug] [error] [sproto header parser failed!!]\n");
		return -1;
	}
	
	/*sproto encoded data parse*/
	if (sproto_parser (unpack, headlen, &apl->ud) <= 0){
		print_debug_log ("[debug] [error] [sproto_parser() failed!]\n");
		goto error;
	}
	
	/*after decode the sproto data ,we creat/update hash list*/
	if ( apl->apinfo.apmac != NULL ){
		/*for_each to find hash node*/
		ap = aplist_entry_insert(apl->apinfo.apmac);
		
		if ( ap ){
			ap->online = apl->online;
			if (ap->status == 1 || ap->status == 0){
				status = 1;
			}
			
			/*ap is online ,judge the socket*/
			if (ap->status == 2){
				if (ap->fd != cl->s.fd.fd){					
					if (ap->client_addr != NULL){
						p_cltaddr = ap->client_addr;
						ustream_free (&p_cltaddr->s.stream);
						close (p_cltaddr->s.fd.fd);
						p_cltaddr->s.fd.fd = 0;
						free (p_cltaddr);
					}
					ap->client_addr = cl;
					ap->fd = cl->s.fd.fd;	
				}
			}else{
				ap->client_addr = cl;
			}
			
			gettime(&ap->last_tv);
			memcpy(&(ap->ud),&(apl->ud),sizeof(ecode_ud_spro));
			memcpy(&(ap->apinfo),&(apl->apinfo) ,sizeof(ap_sys_info));
		}else{
			return -2;
		}
	}
	
	if (ap->ud.session == SPROTO_RESPONSE && ap->ud.ok == RESPONSE_OK){
		ap->ud.ok = 0;
		if (ap->ud.type == AP_CMD){
			free(ap);
			return ACd_STATUS_REBOOT_OK;
		}
		print_debug_log ("[debug] <receive> [response pack]\n");
		
		return ACd_STATUS_OK;
	}else if (ap->ud.session == SPROTO_RESPONSE && ap->ud.ok == RESPONSE_ERROR){
		ap->ud.session = SPROTO_REQUEST;
		slen = send_data_to_ap (ap);
		
		return ACd_STATUS_OK;
	}else if (status ==1  && ap->ud.session == SPROTO_REQUEST){
		return ap_online_proc (ap, cl->s.fd.fd, &cl->localaddr);
	}
	
	ap->ud.session = SPROTO_RESPONSE;
	ap->ud.ok = RESPONSE_OK;
	slen = send_data_to_ap (ap);
	
	return ACd_STATUS_OK;

error:
	ap->ud.session = SPROTO_RESPONSE;
	ap->ud.ok = RESPONSE_ERROR;
	slen = send_data_to_ap (ap);
	print_debug_log ("[debug] <send> [data len:%d]\n", slen);
	
	return -1;
}

int send_data_to_ap (ap_status_entry * ap)
{
	int psize;
	char res[2056] = { 0 };

	if (ap == NULL){
		return -1;
	}

	psize = sproto_encode_data (&ap->ud, res);
	if (ap->fd <= 0){
		return 0;
	}
	
	write (ap->fd, res, psize);
	
	return psize;
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
	char change = false;
	int  i;
	ap_status_entry *ap = NULL;

	blob_buf_init (&b, 0);
	
	/*show all ap info in this AC*/
	for(i = 0;i < AP_HASH_SIZE;i++){
		hlist_for_each_entry(ap, &(aplist.hash[i]), hlist) {	
			if (tpcfg->id == ap->apinfo.id_guest){
				memset(&(ap->apinfo.wifi_info.ssid_info_guest),'\0',sizeof(ap->apinfo.wifi_info.ssid_info_guest));
				memcpy(&(ap->apinfo.wifi_info.ssid_info_guest),&(tpcfg->tmplat_ssid_info),sizeof(tpcfg->tmplat_ssid_info));
				change = true;
			}else{
				memset(&(ap->apinfo.wifi_info.ssid_info),'\0',sizeof(ap->apinfo.wifi_info.ssid_info));
				memcpy(&(ap->apinfo.wifi_info.ssid_info),&(tpcfg->tmplat_ssid_info),sizeof(tpcfg->tmplat_ssid_info));
				change =true;
			}
			
			if (change){
				ap->ud.type = AP_INFO;
				ap->ud.session = SPROTO_REQUEST;
				send_data_to_ap (ap);
				change = false;
			}
		}
	}

	blobmsg_add_u32 (&b, "code", 0);
	
	return ubus_send_reply (ctx, req, b.head);
}

void format_tmp_cfg(tmplat_list *tpcfg, char *res)
{
	char buf[1024] = { 0 };
	
	sprintf (buf + strlen (buf), "name=%s", tpcfg->tpname);
	sprintf (buf + strlen (buf), "|id=%d", tpcfg->id);
	sprintf (buf + strlen (buf), "|ssid=%s", tpcfg->tmplat_ssid_info.ssid);
	sprintf (buf + strlen (buf), "|encrypt=%s", tpcfg->tmplat_ssid_info.encrypt);
	sprintf (buf + strlen (buf), "|key=%s", tpcfg->tmplat_ssid_info.key);
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
	sprintf (tbuf + strlen (tbuf), "|id_guest=%d", ap->apinfo.id_guest);
	sprintf (tbuf + strlen (tbuf), "|txpower=%s", ap->apinfo.wifi_info.txpower);
	sprintf (tbuf + strlen (tbuf), "|hver=%s", ap->apinfo.hver);
	sprintf (tbuf + strlen (tbuf), "|sver=%s", ap->apinfo.sver);
	sprintf (tbuf + strlen (tbuf), "|aip=%s", ap->apinfo.aip);
	sprintf (tbuf + strlen (tbuf), "|channel=%s", ap->apinfo.wifi_info.channel);
	strncpy (res, tbuf, strlen (tbuf));
	res[strlen (res)] = 0;
	
	return;
}

static void template_to_blob(struct blob_buf *buf, tmplat_list *t)
{
	blobmsg_add_string (buf, "name", t->tpname);
	blobmsg_add_u32 (buf, "id", t->id);
	blobmsg_add_string (buf, "ssid", t->tmplat_ssid_info.ssid);
	blobmsg_add_string (buf, "encrypt",  t->tmplat_ssid_info.encrypt);
	blobmsg_add_string (buf, "key",  t->tmplat_ssid_info.key);
	return;
}

static void apinfo_to_json_string(struct blob_buf *buf, ap_status_entry *ap)
{
	char *str = NULL;
	char *mac = NULL;
	char mac_temp[32] = {'\0'};
	void *arr = NULL;
	
	if (buf == NULL || ap == NULL){
		return;
	}
	
	blobmsg_add_string (buf, "name", ap->apname);

	if (ap->online != OFF) {
		struct timeval tv;
		gettime(&tv);
		long td = tv_diff(&tv, &ap->last_tv);
		
		if (td > 30000) {// 30s
			print_debug_log ("[debug] set offline for lost heartbeat %lu\n", td);
			ap->online = OFF;
		}
	}
	
	blobmsg_add_u32 (buf, "online", ap->online);
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

	if (ap->stamac != NULL){
		if (ap->len == 0){
			return;
		}
		
		mac = alloca(ap->len);
		memset(mac, 0, ap->len);
		strcpy(mac, ap->stamac);
		str = strtok(mac, ",");
		arr = blobmsg_open_array (buf, "sta");
		while(str)
		{
			blobmsg_add_string(buf, "", str);
			str = strtok(NULL, ",");
		}
		blobmsg_close_array (buf, arr);
	}

	blobmsg_add_u32 (buf, "id",ap->apinfo.id);
	blobmsg_add_u32 (buf, "id_guest",ap->apinfo.id_guest);
	
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
	char res[1024] = {0};
	char index[64] = {0};
	char id[32][8] = {{0}};
	int template_id;
	unsigned char mac_value[ETH_ALEN] = {0};
	char *mac = NULL;
	char *channel = NULL;
	char *txpower = NULL;
	char *apname = NULL;
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
			if (atoi(channel) > 13 || atoi(channel) < 1){
				blobmsg_add_string (&b, "msg", "channel invalid!");
				goto error;
			}
		}

		memset (ap->apinfo.wifi_info.channel, '\0', sizeof (ap->apinfo.wifi_info.channel));
		strncpy (ap->apinfo.wifi_info.channel, channel, strlen (channel));
	}
	
	if (txpower != NULL && txpower[0] != 0){	
		if (atoi(txpower) > 21 || atoi(txpower) < 1){
			blobmsg_add_string (&b, "msg", "txpower invalid!");
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
			print_debug_log("%s,%d,len:%d\n",__FUNCTION__,__LINE__,i);
			sprintf (id[i++], "%d", blobmsg_get_u32 (attr));
		}
		
		if ( i > AP_MAX_BINDID){
			blobmsg_add_string (&b, "msg", "Max bind 2 template at the same time!");
			goto error;
		}
	}
	
	for (i = 0; id[i][0] != 0; i++){
		template_id = atoi(&id[i][0]);
		if ((tpl = find_template (template_id)) == NULL){
			continue;
		}

		memset (&(ap->apinfo.wifi_info.ssid_info),'\0',sizeof (ap->apinfo.wifi_info.ssid_info));
		memset (&(ap->apinfo.wifi_info.ssid_info_guest),'\0',sizeof (ap->apinfo.wifi_info.ssid_info_guest));
		
		if (atoi(&id[i][0]) == 0 ){
			ap->apinfo.id = template_id;
		}else{
			ap->apinfo.id_guest = template_id;
		}	
		memcpy(&(ap->apinfo.wifi_info.ssid_info),&(tpl->tmplat_ssid_info),sizeof(tpl->tmplat_ssid_info));
	}

	apinfo_to_json_string (&b, ap);
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
	
	print_debug_log("%s,%d\n",__FUNCTION__,__LINE__);
	blobmsg_add_u32 (&b, "code", 0);
	
	return ubus_send_reply (ctx, req, b.head);

error:
	blobmsg_add_u32 (&b, "code", 1);
	
	return ubus_send_reply (ctx, req, b.head);
}

static const struct blobmsg_policy apedit_policy[__CFG_MAX] = {
	[MAC] = {.name = "mac",.type = BLOBMSG_TYPE_STRING},
	[NAME] = {.name = "name",.type = BLOBMSG_TYPE_STRING},
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
	char edit_temp0_flag = false;
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

	if (id < 0){
		blobmsg_add_string (&b, "msg", "Need template id!");
		goto error;
	}
	
	/*the default template can't be modified by user*/
	if ( ( (id == 0 || id ==1) && edit_temp0_flag== false) || (tp = find_template (id)) == NULL){
		blobmsg_add_string (&b, "msg", "template id invalid");
		goto error;
	}
	
	if (ssid != NULL && ssid[0] != 0){
		strcpy (tp->tmplat_ssid_info.ssid, ssid);
	}
	
	if (tpname != NULL && tpname[0] != 0){
		strcpy (tp->tpname, tpname);
	}
	
	if (encrypt != NULL && encrypt[0] != 0){
		strcpy (tp->tmplat_ssid_info.encrypt, encrypt);
		
		if (strcasecmp(tp->tmplat_ssid_info.encrypt, "none") != 0){
			if (key == NULL || key[0] == 0){
				blobmsg_add_string (&b, "msg", "need key");
				goto error;
			}
		}
	}
	
	if (key != NULL && key[0] != 0){
		if (strlen (key) < 8){
			blobmsg_add_string (&b, "msg", "Invalid key");
			goto error;
		}
		strcpy (tp->tmplat_ssid_info.key, key);
	}

	sprintf (index, "id=%d", id);
	format_tmp_cfg (tp, res);
	file_write(TP_LIST_FILE, index, res);
	
	
	return proc_template_edit (tp, req);

error:
	blobmsg_add_u32 (&b, "code", 1);
	
	return ubus_send_reply (ctx, req, b.head);
}

static const struct blobmsg_policy templatedit_policy[__CFG_MAX] = {
	[TMPLATID] = {.name = "id",.type = BLOBMSG_TYPE_INT32},
	[SSID] = {.name = "ssid",.type = BLOBMSG_TYPE_STRING},
	[ENCRYPT] = {.name = "encrypt",.type = BLOBMSG_TYPE_STRING},
	[KEY] = {.name = "key",.type = BLOBMSG_TYPE_STRING},
	[NAME] = {.name = "name",.type = BLOBMSG_TYPE_STRING},
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
	
	if ((tp = find_template (id)) == NULL){
		blobmsg_add_string (&b, "msg", "id error,not found this template");
		goto error;
	}
	
	/*show all ap info in this AC*/
	for(i = 0;i < AP_HASH_SIZE;i++){
		hlist_for_each_entry(ap, &(aplist.hash[i]), hlist) {	
			if (tp->id == ap->apinfo.id_guest){
				memset(&(ap->apinfo.wifi_info.ssid_info_guest),'\0',sizeof(ap->apinfo.wifi_info.ssid_info_guest));
				ap->apinfo.id_guest = ILLEGAL_TMPLATE_ID;
				change = TRUE;
			}else{
				memset(&(ap->apinfo.wifi_info.ssid_info),'\0',sizeof(ap->apinfo.wifi_info.ssid_info));
				
				if ((tp = find_template (DEFAULT_TMPLATE_ID)) != NULL){
					memcpy(&(ap->apinfo.wifi_info.ssid_info),&(tp->tmplat_ssid_info),sizeof(tp->tmplat_ssid_info));
					ap->apinfo.id = DEFAULT_TMPLATE_ID;
					change =TRUE;
				}
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
				change = false;
			}
		}
	}
	
	memset(index,'\0',sizeof(index));
	sprintf (index, "id=%d", id);
	file_spec_content_del(TP_LIST_FILE, index);
	del_template (tplist, id);

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
	int id = ILLEGAL_TMPLATE_ID ;
	tmplat_list *tp = tplist;
	tmplat_list *p = NULL;
	void *arr = NULL;
	char *table = NULL;

	blobmsg_parse(templatelist_policy, __CFG_MAX, tb, blob_data(msg), blob_len(msg));
	
	if (tb[TMPLATID]){
		id = blobmsg_get_u32 (tb[TMPLATID]);
		p = find_template (id);
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
		table = blobmsg_open_table (&b, &tp->id);
		template_to_blob (&b, tp);
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
};

static int ubus_proc_templateadd(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method,
		       struct blob_attr *msg)
{
	struct blob_attr *tb[__CFG_MAX];
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
	
	blob_buf_init (&b, 0);
	memset(&p, 0, sizeof(tmplat_list));
	if (ssid == NULL || ssid[0] == 0){
		blobmsg_add_string (&b, "msg", "Need ssid!");
		goto error;
	}
	while (1){
		if ((tpl = find_template(id)) == NULL){
			break;
		}
		id++;
	}
	
	if (tpname != NULL && tpname[0] != 0){
		strcpy(p.tpname, tpname);
	}
	
	strcpy (&(p.tmplat_ssid_info.ssid[0]), ssid);
	p.id = id;

	if (encrypt != NULL && encrypt[0] != 0){
		strcpy (&(p.tmplat_ssid_info.encrypt[0]), encrypt);
		/*need encrypt*/
		if (strcasecmp(encrypt, "none") != 0){
			if (key == NULL || key[0] == 0 ){
				blobmsg_add_string (&b, "msg", "Need key!");
				goto error;
			}else{
				if (strlen(key) < 8){
					blobmsg_add_string (&b, "msg", "the key length must greater than or equal 8!");
					goto error;
				}
				strcpy (&(p.tmplat_ssid_info.key[0]), key);
			}
			
		}else{/*none*/
			strcpy (&(p.tmplat_ssid_info.encrypt[0]), "none");
			strcpy (&(p.tmplat_ssid_info.key[0]), "");
		}
	}else{/*default none encrypt*/
		strcpy (&(p.tmplat_ssid_info.encrypt[0]), "none");
		strcpy (&(p.tmplat_ssid_info.key[0]), "");
	}
	
	if (insert_template (&p) <= 0){
		goto error;
	}
	
	sprintf (index, "id=%d", p.id);
	format_tmp_cfg (&p, res);
	file_write(TP_LIST_FILE, index, res);

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
				print_debug_log("%s,%d\n",__FUNCTION__,__LINE__);
			}
		}else{
			ap = NULL;
			blobmsg_add_string (&b, "msg", "need the sn!");
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
	
	print_debug_log("%s,%d\n",__FUNCTION__,__LINE__);
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
				print_debug_log("%s,%d\n",__FUNCTION__,__LINE__);
			}
		}else{
			ap = NULL;
			blobmsg_add_string (&b, "msg", "need the sn!");
		}
		
		if (ap == NULL){
			print_debug_log("%s,%d\n",__FUNCTION__,__LINE__);
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
	UBUS_METHOD_MASK ("apedit", ubus_proc_apedit, apedit_policy, 1 << MAC | 1 << NAME | 1 << TMPLATID | 1 << CHANNEL | 1 << TXPOWER),
	UBUS_METHOD_MASK ("templatedit", ubus_proc_templatedit, templatedit_policy, 1 << TMPLATID | 1 << SSID | 1 << ENCRYPT | 1 << NAME | 1 << KEY | 1<<EDIT_FLAG),
	UBUS_METHOD_MASK ("templatelist", ubus_proc_templatelist, templatelist_policy, 1 << TMPLATID),
	UBUS_METHOD_MASK ("templateadd", ubus_proc_templateadd, templateadd_policy, 1 << SSID | 1 << ENCRYPT | 1 << NAME | 1 << KEY),
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

void aplist_entry_init(ap_status_entry aplist_node)
{
	memset(&aplist_node,0,sizeof(ap_status_entry));
}

void acd_init(void)
{
	char buf[64] = {0};
	
	if ((tplist = create_tplist()) == NULL){
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
	aplist_entry_init(p_temp_ap_info);
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
	signal (SIGPIPE, SIG_IGN);

	ctx = ubus_connect (ubus_socket);
	
	if (!ctx) {
	  fprintf (stderr, "Failed to connect to ubus\n");
	  return -1;
	}
	
	ubus_add_uloop (ctx);
	acd_init ();
	run_server ();
	server_main ();
	uloop_run ();

	ubus_free (ctx);
	uloop_done ();

	return 1;
}
