#include "acd.h"

static struct uloop_fd server;
static struct client *next_client = NULL;
static ap_list *aplist = NULL;	//ap information list
tmplat_list *tplist = NULL;
static const char *port = "4444";
static struct sproto *spro_new = NULL;	//the protocol
static FILE *debug = NULL;
char rip[20] = { 0 };
#define MAC_LEN			100

void print_debug_log (const char *form, ...);
int sproto_read_entity (char *filename);
int sproto_encode_data (struct encode_ud *ud, char *res);
void fill_data (ap_list * apcfg, char *tagname, char *value, int len);
void fill_encode_data (ap_list * apcfg, char *tagname, char *value);
void format_ap_cfg (ap_list * apinfo, char *res);
int foreach_aplist (char *mac, char *filename);
void format_tmp_cfg (tmplat_list * tpcfg, char *res);
int proc_tmplate_info (tmplat_list * tpcfg, struct ubus_request_data *req);
int send_data_to_ap (ap_list * ap);
int rcv_and_proc_data (char *data, int len, struct client *cl);
int ap_online_proc (ap_list * ap, int sfd);
void free_mem(ap_list *ap);

int is_ip(const char *str)
{
    struct in_addr addr;
    int ret;

		if (str == NULL)
			return -1;
    ret = inet_pton(AF_INET, str, &addr);
    return ret;
}

tmplat_list *create_tplist(void)
{
  tmplat_list *p = (tmplat_list *) calloc (sizeof (tmplat_list), 1);
  if (p == NULL)
    return NULL;
  p->rlink = NULL;
  p->llink = NULL;
  return p;
}

int insert_template(tmplat_list *s)
{
  tmplat_list *p = tplist, *t;

  t = create_tplist ();
  if (t == NULL || p == NULL || s == NULL)
    return 0;
	strcpy (t->tpname, s->tpname);
  strcpy (t->ssid, s->ssid);
  strcpy (t->id, s->id);
  strcpy (t->encrypt, s->encrypt);
  strcpy (t->key, s->key);
  while (1)
	{
		if (p->rlink == NULL)
		{
			p->rlink = t;
			t->llink = p;
			break;
		}
		p = p->rlink;
	}
  return 1;
}

void del_template(tmplat_list *h, char *id)
{
  tmplat_list *p = h;
  if (p == NULL || id == NULL)
    return;

  while (1)
	{
		if (p->rlink == NULL)
			break;
		p = p->rlink;
		if (strcasecmp (p->id, id) != 0)
			continue;
		if (p->rlink != NULL)
		{
			p->llink->rlink = p->rlink;
			p->rlink->llink = p->llink;
		}
		else
			p->llink->rlink = NULL;
		free (p);
		p = NULL;
		break;
	}
  return;
}

tmplat_list *find_template(char *id)
{
  tmplat_list *p = tplist;

  if (p == NULL || id == NULL)
    return NULL;

  while (p->rlink)
	{
		p = p->rlink;
		if (strcasecmp (p->id, id) == 0)
			return p;
	}
  return NULL;
}

ap_list *create_aplist(void)
{
  ap_list *p = (ap_list *) malloc (sizeof (ap_list));
  if (p == NULL)
    return NULL;
	memset(p, 0, sizeof(ap_list));
  p->rlink = NULL;
  p->llink = NULL;
	p->stamac = NULL;
	p->len = 0;
  return p;
}

ap_list *insert_apmember(ap_list *ap, int id, int fd)
{
  ap_list *p = aplist;

  if (ap == NULL)
    return NULL;
	print_debug_log("[debug] [insert ap] [mac:%s,len:%d]\n", ap->apinfo.apmac, strlen(ap->apinfo.apmac));
	if (strlen(ap->apinfo.apmac) != 17 || strcasecmp(ap->apinfo.apmac, "00:00:00:00:00:00") == 0)
		return NULL;
  ap->fd = fd;
  ap->apid = id;
  while (1)
	{
		if (p->rlink == NULL)
		{
			p->rlink = ap;
			ap->llink = p;
			return ap;
		}
		p = p->rlink;
	}
  return NULL;
}

void del_apmember(char *mac, char *sn)
{
  ap_list *p = aplist;

  if (mac == NULL && sn == NULL)
    return;
  while (p->rlink)
	{
		p = p->rlink;
		if (mac != NULL && strcasecmp (p->apinfo.apmac, mac) != 0)
			continue;
		else if (sn != NULL && strcasecmp (p->apinfo.sn, sn) != 0)
			continue;
		if (p->rlink != NULL)
		{
			p->llink->rlink = p->rlink;
			p->rlink->llink = p->llink;
		}
		else
			p->llink->rlink = NULL;
		if (p->fd > 0)
			close (p->fd);
		if (p->stamac != NULL)
		{
			free(p->stamac);
			p->stamac = NULL;
			p->len = 0;
		}
		free (p);
		p = NULL;
		break;
	}
  print_debug_log ("[debug] [del] [ap:%s]\n", mac);
  return;
}

ap_list *find_apmember(char *mac, char *sn, int fd)
{
  ap_list *p = aplist;

  if (!(mac || sn) && fd <= 0)
    return NULL;

  while (p->rlink)
  {
    p = p->rlink;
    if (fd > 0 && p->fd == fd)
			return p;
		else if((mac != NULL && mac[0] != 0) && strcasecmp(mac, p->apinfo.apmac) == 0)
			return p;
		else if ((sn != NULL && sn[0] != 0) && strcasecmp(sn, p->apinfo.sn) == 0)
			return p;
  }

  return NULL;
}

static void client_read_cb(struct ustream *s, int bytes)
{
  struct client *cl = container_of (s, struct client, s.stream);
  char *str;
	int len = 0,ret;
	do {
      str = ustream_get_read_buf (s, &len);
      if (!str)
				break;

			ret = rcv_and_proc_data (str, len, cl);
			if (ret != ACd_STATUS_REBOOT_OK)
      	ustream_consume (s, len);
	} while(1);

	if (s->w.data_bytes > 256 && !ustream_read_blocked(s)) {
    print_debug_log ("[debug] [Block read, bytes: %d]\n", s->w.data_bytes);
    ustream_set_read_blocked (s, true);
  }
}

static void client_close(struct ustream *s)
{
  struct client *cl = container_of (s, struct client, s.stream);
	ap_list *ap = NULL;

	print_debug_log ("[debug] [fd:%d connection closed!!]\n", cl->s.fd.fd);
	if ((ap = find_apmember (NULL, NULL, cl->s.fd.fd)) != NULL)
  {
		free_mem(ap);
  }
}

static void client_notify_state(struct ustream *s)
{
  if (!s->eof)
    return;

	if (!s->w.data_bytes)
    return client_close (s);
}

static void server_cb(struct uloop_fd *fd, unsigned int events)
{
  struct client *cl;
  unsigned int sl = sizeof (struct sockaddr_in);
  int sfd;

  if (!next_client)
    next_client = calloc (1, sizeof (*next_client));

  cl = next_client;
  sfd = accept (server.fd, (struct sockaddr *) &cl->sin, &sl);
	if (sfd < 0) {
    print_debug_log ("Accept failed\n");
    return;
  }

  cl->s.stream.string_data = true;
  cl->s.stream.notify_read = client_read_cb;
  cl->s.stream.notify_state = client_notify_state;

  ustream_fd_init (&cl->s, sfd);
  next_client = NULL;
	print_debug_log("[debug] [New connection] [ip:%s, fd:%d]\n", inet_ntoa(cl->sin.sin_addr), sfd);
}

void aplist_init(void)
{
  int i, j, spa = 0;
  ap_list *ap = NULL;
  tmplat_list *tp = NULL;
	char buf[2056], *str, name[20], *optstr, optname[30], optval[50], tmp[50] = {0};
  for (i = 1;; i++)
	{
		bzero (name, sizeof (name));
		bzero (buf, sizeof (buf));
		sprintf (name, "ap_cfg_%d", i);
		read_apinfo("aplist", name, buf);
		if (spa > 20)
			break;
		if (strlen(buf) == 0)
		{
			spa++;
			continue;
		}
		spa = 0;
		if ((ap = create_aplist ()) == NULL)
			continue;

		str = strtok (buf, "|");
		while (str)
		{
			bzero (optname, sizeof (optname));
			bzero (optval, sizeof (optname));
			optstr = strstr (str, "=");
			strncpy (optname, str, optstr - str);
			strcpy (optval, optstr + 1);
			for (j = 0; ap_cfg_opt[j] != 0; j++)
			{
			  if (strcasecmp (optname, ap_cfg_opt[j]) == 0)
				{
					fill_data (ap, optname, optval, strlen (optval));
				}
			}
			str = strtok (NULL, "|");
		}
		strcpy (tmp, ap->apinfo.id);
		if ((str = strtok (tmp, ",")) == NULL)
		{
			if ((tp = find_template ("0")) == NULL)
				return;
			sprintf (ap->apinfo.id, "%s,", tp->id);
			sprintf (ap->apinfo.ssid, "%s,", tp->ssid);
			sprintf (ap->apinfo.encrypt, "%s,", tp->encrypt);
			sprintf (ap->apinfo.key, "%s,", tp->key);
		}
		while (str)
		{
			if ((tp = find_template (str)) != NULL)
			{
				sprintf(ap->apinfo.ssid + strlen(ap->apinfo.ssid), "%s,", tp->ssid);
				sprintf(ap->apinfo.encrypt + strlen(ap->apinfo.encrypt), "%s,", tp->encrypt);
				sprintf(ap->apinfo.key + strlen(ap->apinfo.key), "%s,", tp->key);
			}
			str = strtok (NULL, ",");
		}

		ap->apinfo.ssid[strlen (ap->apinfo.ssid) - 1] = 0;
		ap->apinfo.encrypt[strlen (ap->apinfo.encrypt) - 1] = 0;
		ap->apinfo.key[strlen (ap->apinfo.key) - 1] = 0;
		insert_apmember (ap, i, 0);
		ap = NULL;
	}
  return;
}

void tplist_init(void)
{
  int i, err = 0;
  tmplat_list tp;
  char buf[2056], *str, name[20], *optstr, optname[30], optval[50];
  for (i = 0;; i++)
	{
		bzero (name, sizeof (name));
		bzero (buf, sizeof (buf));
		sprintf (name, "template_%d", i);
		read_apinfo("tplist", name, buf);
		if (strlen (buf) == 0)
		{
			err++;
			if (i == 0) {
				strcpy(buf, "name=default|id=0|ssid=MoreWiFi|encrypt=none|key=");
				write_apinfo("tplist", "template_0", buf);
			} else {
				if (err > 8)
					break;
				continue;
			}
		}
		memset (&tp, 0, sizeof (tmplat_list));
		str = strtok (buf, "|");
		while (str)
		{
			bzero (optname, sizeof (optname));
			bzero (optval, sizeof (optname));
			optstr = strstr (str, "=");
			strncpy (optname, str, optstr - str);
			strcpy (optval, optstr + 1);
			if (strcasecmp(optname, "name") == 0)
				strcpy(tp.tpname, optval);
			else if (strcasecmp (optname, "id") == 0)
				strcpy (tp.id, optval);
			else if (strcasecmp (optname, "ssid") == 0)
				strcpy (tp.ssid, optval);
			else if (strcasecmp (optname, "encrypt") == 0)
				strcpy (tp.encrypt, optval);
			else if (strcasecmp (optname, "key") == 0)
				strcpy (tp.key, optval);
			print_debug_log("[debug] [tplist_%d] [%s:%s]\n", i, optname, optval);
			str = strtok (NULL, "|");
		}
		insert_template (&tp);
	}
  return;
}

#ifdef MW200H
int get_loca_ip(void)
{
  int sockfd;
  char *ptr, buf[2048], addrstr[INET_ADDRSTRLEN];
  struct ifconf ifc;
  struct ifreq *ifr;
  struct sockaddr_in *sinptr;
  sockfd = socket (AF_INET, SOCK_DGRAM, 0);
  ifc.ifc_len = sizeof (buf);
  ifc.ifc_req = (struct ifreq *) buf;
  ioctl (sockfd, SIOCGIFCONF, &ifc);
  for (ptr = buf; ptr < buf + ifc.ifc_len; ptr += sizeof (struct ifreq))
	{
		ifr = (struct ifreq *) ptr;
		switch (ifr->ifr_addr.sa_family)
			{
			case AF_INET:
				sinptr = (struct sockaddr_in *) &ifr->ifr_addr;
				if (strcasecmp(ifr->ifr_name, "eth0") == 0){
					strcpy(rip, inet_ntop(AF_INET, &sinptr->sin_addr, addrstr, sizeof(addrstr)));
					rip[strlen (rip)] = 0;
				}
				break;
			default:
				break;
		}
	}
  close (sockfd);
  return 1;
}
#else

static const struct blobmsg_policy lan_policy[__CFG_MAX] = {
	[IPADDR] = { .name = "ipv4-address", .type = BLOBMSG_TYPE_ARRAY},
};

static const struct blobmsg_policy ip_policy[__CFG_MAX] = {
	[ADDR] = { .name = "address", .type = BLOBMSG_TYPE_STRING},
};

static void acd_ubus_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *tb[__CFG_MAX], *attr;
	int len;

	blobmsg_parse(lan_policy, __CFG_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));
	if (!tb[IPADDR]) {
		fprintf(stderr, "No return code received from server\n");
		return;
	}
	blobmsg_for_each_attr(attr, tb[IPADDR], len)
	{
		blobmsg_parse(ip_policy, __CFG_MAX, tb, blobmsg_data(attr), blobmsg_data_len(attr));
		if (tb[ADDR])
		{
			sprintf(rip, "%s", blobmsg_get_string(tb[ADDR]));
			return;
		}
	}
}

int get_loca_ip(void)
{
	uint32_t id;

	if (ubus_lookup_id(ctx, "network.interface.lan", &id)) {
		return -1;
	}

	ubus_invoke(ctx, id, "status", NULL, acd_ubus_cb, NULL, 5000);
	return 0;
}
#endif
int memcat(char *res, char *buf, int slen, int len)
{
  int i;
  if (buf == NULL || len <= 0)
    return 0;
  for (i = 0; i < len; i++)
    {
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
  ap_list *apcfg = container_of (ud, ap_list, ud);

	if (length < 2 * SIZEOF_LENGTH)
		return 0;

	switch (type) {
		case SPROTO_TINTEGER: {
			if (strcasecmp (tagname, "type") == 0)
			  *(uint32_t *) value = self->type;
			else if (strcasecmp (tagname, "session") == 0)
			  *(uint32_t *) value = self->session;
			else if (strcasecmp (tagname, "apcmd") == 0)
			  *(uint32_t *) value = apcfg->cmd.cmd;
			else if (strcasecmp (tagname, "status") == 0)
			  *(uint32_t *) value = apcfg->cmd.status;
			print_debug_log("[debug] [encode] [%s:] [%d]\n", tagname, *(int *)value);
			return 4;
 	 	}
		case SPROTO_TBOOLEAN: {
			if (strcasecmp (tagname, "ok") == 0)
				*(int *) value = self->ok;
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
	if((header_len = sproto_encode(pro_type, header, sizeof(header), sproto_encode_cb, ud)) < 0)
    return 0;
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

void fill_encode_data(ap_list *apcfg, char *tagname, char *value)
{
  if (apcfg == NULL)
    return;
  if (strcasecmp (tagname, "ssid") == 0)
    strcpy (value, apcfg->apinfo.ssid);
  else if (strcasecmp (tagname, "channel") == 0)
    strcpy (value, apcfg->apinfo.channel);
  else if (strcasecmp (tagname, "encrypt") == 0)
    strcpy (value, apcfg->apinfo.encrypt);
  else if (strcasecmp (tagname, "key") == 0)
    strcpy (value, apcfg->apinfo.key);
  else if (strcasecmp (tagname, "txpower") == 0)
    strcpy (value, apcfg->apinfo.txpower);
  else if (strcasecmp (tagname, "addr") == 0)
    strcpy (value, apcfg->cmd.addr);
  else if (strcasecmp (tagname, "md5") == 0)
    strcpy (value, apcfg->cmd.md5);
  return;
}

void fill_data(ap_list *apcfg, char *tagname, char *value, int len)
{
	int slen = 0;
  if (apcfg == NULL || strlen (value) == 0 || len == 0)
    return;

  if (strcasecmp (tagname, "hver") == 0)
    strncpy (apcfg->apinfo.hver, value, len);
  else if (strcasecmp (tagname, "sver") == 0)
    strncpy (apcfg->apinfo.sver, value, len);
  else if (strcasecmp (tagname, "sn") == 0)
    strncpy (apcfg->apinfo.sn, value, len);
  else if (strcasecmp (tagname, "aip") == 0)
    strncpy (apcfg->apinfo.aip, value, len);
  else if (strcasecmp (tagname, "mac") == 0)
    strncpy (apcfg->apinfo.apmac, value, len);
  else if (strcasecmp (tagname, "rip") == 0)
    strncpy (apcfg->apinfo.rip, rip, len);
  else if (strcasecmp (tagname, "channel") == 0)
    strncpy (apcfg->apinfo.channel, value, len);
  else if (strcasecmp (tagname, "id") == 0)
    strncpy (apcfg->apinfo.id, value, len);
	else if (strcasecmp(tagname, "name") == 0)
		strncpy(apcfg->apname, value, len);
	else if (strcasecmp(tagname, "txpower") == 0)
		strncpy(apcfg->apinfo.txpower, value, len);
	else if (strcasecmp(tagname, "stamac") == 0)
	{
		if (apcfg->stamac == NULL)
		{
			if ((apcfg->stamac = calloc(MAC_LEN, 1)) == NULL)
				return;
			apcfg->len = MAC_LEN;
		}
		slen = strlen(apcfg->stamac);
		if (apcfg->len - slen < 18)
		{
			apcfg->len += MAC_LEN;
			if ((apcfg->stamac = realloc(apcfg->stamac, apcfg->len)) == NULL)
				return;
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
  ap_list *apcfg = container_of (ud, ap_list, ud);
	char val[1024] = {0};
	if (!(tagname && ud && apcfg))
		return 0;
	switch (type) {
		case SPROTO_TINTEGER: {
			if (strcasecmp (tagname, "type") == 0)
			  self->type = *(int *) value;
			else if (strcasecmp (tagname, "session") == 0)
			  self->session = *(int *) value;
			else if (strcasecmp (tagname, "apstatus") == 0)
			  apcfg->cmd.status = *(int *) value;
			print_debug_log ("[debug] [decode] [%s:] [%d]\n", tagname, *(int *) value);
			break;
		}
		case SPROTO_TBOOLEAN: {
			self->ok = *(int *) value;
			print_debug_log ("[debug] [decode] [%s:] [%d]\n", tagname, *(int *) value);
			break;
    }
		case SPROTO_TSTRING: {
			strncpy(val, value, length);
			fill_data (apcfg, (char *) tagname, val, length);
			print_debug_log("[debug] [decode] [%s: %s,%d]\n", tagname, val, length);
			break;
    }
		case SPROTO_TSTRUCT: {
			int r = sproto_decode (st, value, length, sproto_parser_cb, self);
			if (r < 0 || r != length)
			  return r;
			break;
		}
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
	ap_list *apcfg = container_of (ud, ap_list, ud);

	if (apcfg->stamac != NULL && ud->type == AP_STATUS)
	{
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

ap_list *find_apid(int id)
{
	ap_list *p = aplist;

	if (p == NULL || id <= 0)
		return NULL;

	while (p->rlink)
	{
		p = p->rlink;
		if (p->apid == id)
			return p;
	}
	return NULL;
}

void free_mem(ap_list *ap)
{
	if (ap == NULL)
		return;

	ap->online = OFF;
	if (ap->cltaddr != NULL)
	{
		ustream_free (&ap->cltaddr->s.stream);
		if (ap->cltaddr->s.fd.fd > 0)
			close(ap->cltaddr->s.fd.fd);
		ap->cltaddr->s.fd.fd = 0;
		ap->fd = 0;
		free (ap->cltaddr);
		ap->cltaddr = NULL;
	}
	if (ap->stamac != NULL)
	{
		free(ap->stamac);
		ap->stamac = NULL;
		ap->len = 0;
	}
	return;
}

int ap_online_proc(ap_list *ap, int sfd)
{
  ap_list *apl = NULL;
  tmplat_list *tp = NULL;
	char res[1024 * 5] = {0}, name[20] = {0};
	int apid = 1;
  if (ap == NULL || sfd <= 0)
    return 0;
  if ((apl = find_apmember (ap->apinfo.apmac, NULL, 0)) == NULL)
	{
		while(1)
		{
			if (find_apid(apid) == NULL)
				break;
			apid++;
		}

		if ((apl = insert_apmember (ap, apid, sfd)) == NULL)
		{
			free_mem(apl);
			print_debug_log("[debug] [add ap to aplist failed!!]\n");
			return 0;
		}
		if ((tp = find_template ("0")) == NULL)
		{
			free_mem(apl);
			print_debug_log("[debug] [find template failed!!]\n");
			return 0;
		}
		strcpy(apl->apname, "");
		strcpy (apl->apinfo.channel, "auto");
		strcpy (apl->apinfo.txpower, "20");
		strcpy (apl->apinfo.ssid, tp->ssid);
		strcpy (apl->apinfo.encrypt, tp->encrypt);
		strcpy (apl->apinfo.key, tp->key);
		strcpy (apl->apinfo.id, "0");
		strcpy (apl->apinfo.rip, rip);
	}
	else
	{
		strcpy (apl->apinfo.aip, ap->apinfo.aip);
		strcpy (apl->apinfo.sn, ap->apinfo.sn);
		strcpy (apl->apinfo.hver, ap->apinfo.hver);
		strcpy (apl->apinfo.sver, ap->apinfo.sver);
		struct client *cl = apl->cltaddr;
		if (cl != NULL)
		{
			ustream_free (&cl->s.stream);
			close (cl->s.fd.fd);
			cl->s.fd.fd = 0;
			free (cl);
		}
		apl->cltaddr = ap->cltaddr;
		apl->fd = sfd;
		if (ap->stamac != NULL)
			free(ap->stamac);
		free(ap);
	}
	format_ap_cfg (apl, res);
	sprintf(name, "ap_cfg_%d", apl->apid);
	write_apinfo("aplist", name, res);
  apl->ud.type = AP_INFO;
  apl->ud.session = SPROTO_REQUEST;
	int len = send_data_to_ap (apl);
  return len;
}

int rcv_and_proc_data(char *data, int len, struct client *cl)
{
  int slen, headlen, status = 0;
  char unpack[1024 * 6] = { 0 };
  ap_list *apl = NULL, *ap = NULL;
	print_debug_log ("[debug] [rcv] [data len:%d, fd:%d]\n", len, cl->s.fd.fd);
	if ((apl = find_apmember (NULL, NULL, cl->s.fd.fd)) == NULL)
  {
    if ((ap = create_aplist ()) == NULL)
			return -2;
    apl = ap;
    status = 1;
		apl->cltaddr = cl;
  }
	apl->online = ON;
	if ((headlen = sproto_header_parser(data, len, &apl->ud, unpack)) <= 0){
    print_debug_log ("[debug] [error] [sproto header parser failed!!]\n");
    return -1;
  }
  if (sproto_parser (unpack, headlen, &apl->ud) <= 0)
  {
    print_debug_log ("[debug] [error] [sproto_parser() failed!]\n");
    goto error;
  }
  if (apl->ud.session == SPROTO_RESPONSE && apl->ud.ok == RESPONSE_OK)
  {
    apl->ud.ok = 0;
    if (apl->ud.type == AP_CMD)
    {
    	free_mem(apl);
			return ACd_STATUS_REBOOT_OK;
    }
    print_debug_log ("[debug] <receive> [response pack]\n");
    return ACd_STATUS_OK;
  }
  else if (apl->ud.session == SPROTO_RESPONSE && apl->ud.ok == RESPONSE_ERROR)
  {
    apl->ud.session = SPROTO_REQUEST;
		slen = send_data_to_ap (apl);
    return ACd_STATUS_OK;
  }
  else if (status && apl->ud.session == SPROTO_REQUEST)
  {
		return ap_online_proc (apl, cl->s.fd.fd);
  }
  apl->ud.session = SPROTO_RESPONSE;
  apl->ud.ok = RESPONSE_OK;
  slen = send_data_to_ap (apl);
	return ACd_STATUS_OK;
error:
  apl->ud.session = SPROTO_RESPONSE;
  apl->ud.ok = RESPONSE_ERROR;
  slen = send_data_to_ap (apl);
  print_debug_log ("[debug] <send> [data len:%d]\n", slen);
  return -1;
}

int send_data_to_ap(ap_list *ap)
{
  int psize;
  char res[2056] = { 0 };

  if (ap == NULL)
    return -1;

  psize = sproto_encode_data (&ap->ud, res);
  if (ap->fd <= 0)
    return 0;
  write (ap->fd, res, psize);
  return psize;
}

void print_debug_log(const char *form ,...)
{
  if (debug == NULL)
    return;

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
  ap_list *p = aplist;
  tmplat_list *tp = NULL;
  char *id, buf[100] = { 0 };

  blob_buf_init (&b, 0);

  while (p->rlink)
	{
	  p = p->rlink;
	  if (strstr (p->apinfo.id, tpcfg->id) == NULL)
			continue;
		strcpy (buf, p->apinfo.id);
	  memset (p->apinfo.ssid, 0, sizeof (p->apinfo.ssid));
	  memset (p->apinfo.encrypt, 0, sizeof (p->apinfo.encrypt));
	  memset (p->apinfo.key, 0, sizeof (p->apinfo.key));
	  id = strtok (buf, ",");
	  while (id)
		{
			if ((tp = find_template (id)) != NULL)
		  {
				sprintf(p->apinfo.ssid + strlen(p->apinfo.ssid), "%s,", tp->ssid);
				sprintf(p->apinfo.encrypt + strlen(p->apinfo.encrypt), "%s,", tp->encrypt);
				sprintf(p->apinfo.key + strlen(p->apinfo.key), "%s,", tp->key);
		  }
			id = strtok (NULL, ",");
		}
	  p->apinfo.ssid[strlen (p->apinfo.ssid) - 1] = 0;
	  p->apinfo.encrypt[strlen (p->apinfo.encrypt) - 1] = 0;
	  p->apinfo.key[strlen (p->apinfo.key) - 1] = 0;
	  p->ud.type = AP_INFO;
	  p->ud.session = SPROTO_REQUEST;
	  send_data_to_ap (p);
	}
  blobmsg_add_u32 (&b, "code", 0);
  return ubus_send_reply (ctx, req, b.head);
}

void format_tmp_cfg(tmplat_list *tpcfg, char *res)
{
  char buf[1024] = { 0 };
	sprintf (buf + strlen (buf), "name=%s", tpcfg->tpname);
  sprintf (buf + strlen (buf), "|id=%s", tpcfg->id);
  sprintf (buf + strlen (buf), "|ssid=%s", tpcfg->ssid);
  sprintf (buf + strlen (buf), "|encrypt=%s", tpcfg->encrypt);
  sprintf (buf + strlen (buf), "|key=%s", tpcfg->key);
  strcpy (res, buf);
  res[strlen (buf)] = 0;
  return;
}

void format_ap_cfg(ap_list *apinfo, char *res)
{
  char tbuf[1024];
  bzero (tbuf, sizeof (tbuf));
  sprintf (tbuf + strlen (tbuf), "mac=%s", apinfo->apinfo.apmac);
	sprintf (tbuf + strlen (tbuf), "|name=%s", apinfo->apname);
  sprintf (tbuf + strlen (tbuf), "|sn=%s", apinfo->apinfo.sn);
  sprintf (tbuf + strlen (tbuf), "|id=%s", apinfo->apinfo.id);
  sprintf (tbuf + strlen (tbuf), "|txpower=%s", apinfo->apinfo.txpower);
  sprintf (tbuf + strlen (tbuf), "|hver=%s", apinfo->apinfo.hver);
  sprintf (tbuf + strlen (tbuf), "|sver=%s", apinfo->apinfo.sver);
  sprintf (tbuf + strlen (tbuf), "|rip=%s", apinfo->apinfo.rip);
  sprintf (tbuf + strlen (tbuf), "|aip=%s", apinfo->apinfo.aip);
  sprintf (tbuf + strlen (tbuf), "|channel=%s", apinfo->apinfo.channel);
  strncpy (res, tbuf, strlen (tbuf));
  res[strlen (res)] = 0;
  return;
}

static void template_to_blob(struct blob_buf *buf, tmplat_list *t)
{
	blobmsg_add_string (buf, "name", t->tpname);
  blobmsg_add_u32 (buf, "id", atoi(t->id));
  blobmsg_add_string (buf, "ssid", t->ssid);
  blobmsg_add_string (buf, "encrypt", t->encrypt);
  blobmsg_add_string (buf, "key", t->key);
  return;
}

static void apinfo_to_json_string(struct blob_buf *buf, ap_list *ap)
{
  char *str = NULL, tmp[100] = { 0 }, *mac = NULL;
  void *arr = NULL;
	if (buf == NULL || ap == NULL)
		return;
	blobmsg_add_string (buf, "name", ap->apname);
  blobmsg_add_u32 (buf, "online", ap->online);
  blobmsg_add_string (buf, "mac", ap->apinfo.apmac);
  blobmsg_add_string (buf, "sn", ap->apinfo.sn);
  blobmsg_add_string (buf, "hver", ap->apinfo.hver);
  blobmsg_add_string (buf, "sver", ap->apinfo.sver);
  blobmsg_add_string (buf, "aip", ap->apinfo.aip);
  blobmsg_add_string (buf, "rip", ap->apinfo.rip);
  blobmsg_add_string (buf, "channel", ap->apinfo.channel);
  blobmsg_add_string (buf, "txpower", ap->apinfo.txpower);

	if (ap->stamac != NULL)
	{
		if (ap->len == 0)
			return;
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
  if ((str = strstr (ap->apinfo.id, ",")) == NULL)
  {
    blobmsg_add_u32 (buf, "id", atoi(ap->apinfo.id));
    return;
  }
  arr = blobmsg_open_array (buf, "id");
  strcpy (tmp, ap->apinfo.id);
  str = strtok (tmp, ",");
  while (str)
  {
    blobmsg_add_u32 (buf, NULL, atoi (str));
    str = strtok (NULL, ",");
  }
  blobmsg_close_array (buf, arr);
  return;
}

int foreach_aplist(char *mac, char *filename)
{
  int i;
  char buf[1024], ap_name[20], *start, *end, locmac[20];

  if (filename == NULL || mac == NULL)
    return -1;

	for (i = 0; ; i++){
    bzero (ap_name, sizeof (ap_name));
    bzero (buf, sizeof (buf));
    sprintf (ap_name, "ap_cfg_%d", i + 1);
    read_apinfo(filename, ap_name, buf);
    if (strlen (buf) == 0)
			break;
    if ((start = strstr (buf, "mac")) == NULL)
			continue;
    if ((end = strstr (start, "|")) == NULL)
			continue;
    bzero (locmac, sizeof (locmac));
    strncpy (locmac, start + 4, end - start - 4);

    if (strcasecmp (mac, locmac) == 0)
			return i;
  }
  return 0;
}

static const struct blobmsg_policy apinfo_policy[__CFG_MAX] = {
  [MAC] = {.name = "mac",.type = BLOBMSG_TYPE_STRING},
  [SN] = {.name = "sn",.type = BLOBMSG_TYPE_STRING},
};

static int ubus_proc_apinfo(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
  struct blob_attr *tb[__CFG_MAX];
  char *mac = NULL, *sn = NULL;
  ap_list *ap = NULL, *p = aplist;
  void *arr = NULL, *table = NULL;

	blobmsg_parse(apinfo_policy, ARRAY_SIZE(apinfo_policy), tb, blob_data(msg), blob_len(msg));
  if (tb[MAC])
    mac = blobmsg_get_string (tb[MAC]);
  if (tb[SN])
    sn = blobmsg_get_string (tb[SN]);
  ap = find_apmember (mac, sn, 0);
  blob_buf_init (&b, 0);
  if (ap != NULL)
  {
    apinfo_to_json_string (&b, ap);
    return ubus_send_reply (ctx, req, b.head);
  }
  if ((mac && mac[0]) || (sn && sn[0]))
  {
    blobmsg_add_u32 (&b, "code", 1);
    blobmsg_add_string (&b, "msg", "not found this ap, mac or sn error");
    return ubus_send_reply (ctx, req, b.head);
  }
  arr = blobmsg_open_array (&b, "data");
  while (p->rlink)
  {
    p = p->rlink;
    table = blobmsg_open_table (&b, NULL);
    apinfo_to_json_string (&b, p);
    blobmsg_close_table (&b, table);
  }
  blobmsg_close_array (&b, arr);
  return ubus_send_reply (ctx, req, b.head);;
}

int apedit_cb(struct blob_attr **tb, struct ubus_request_data *req)
{
	char *mac = NULL, *sn = NULL, *channel = NULL, *txpower = NULL, *apname = NULL
		, res[1024] = {0}, name[20] = {0}, id[30][5] = {{0}};
  ap_list *ap = NULL;
  tmplat_list *tpl = NULL;
  struct blob_attr *attr, *dt;
  int len, i = 0;

  if (tb[MAC])
    mac = blobmsg_get_string (tb[MAC]);
  if (tb[SN])
    sn = blobmsg_get_string (tb[SN]);
  if (tb[CHANNEL])
    channel = blobmsg_get_string (tb[CHANNEL]);
  if (tb[TXPOWER])
    txpower = blobmsg_get_string (tb[TXPOWER]);
	if (tb[NAME])
    apname = blobmsg_get_string (tb[NAME]);
  blob_buf_init (&b, 0);
  if ((ap = find_apmember (mac, sn, 0)) == NULL)
  {
    blobmsg_add_string (&b, "msg", "not found this ap or ap offline!");
		goto error;
  }
	if (channel != NULL && channel[0] != 0)
  {
		if(strcasecmp("auto", channel) != 0)
		{
			if (atoi(channel) > 11 || atoi(channel) < 3)
			{
				blobmsg_add_string (&b, "msg", "channel invalid!");
				goto error;
			}
		}
    memset (ap->apinfo.channel, 0, sizeof (ap->apinfo.channel));
    strncpy (ap->apinfo.channel, channel, strlen (channel));
  }
  if (txpower != NULL && txpower[0] != 0)
  {
  	if (atoi(txpower) > 20 || atoi(txpower) < 1)
  	{
			blobmsg_add_string (&b, "msg", "txpower invalid!");
			goto error;
		}
    memset (ap->apinfo.txpower, 0, sizeof (ap->apinfo.txpower));
    strncpy (ap->apinfo.txpower, txpower, strlen (txpower));
  }
  if (tb[TMPLATID])
  {
    dt = blobmsg_data (tb[TMPLATID]);
    len = blobmsg_data_len (tb[TMPLATID]);
		__blob_for_each_attr(attr, dt, len) {
		sprintf (id[i++], "%d", blobmsg_get_u32 (attr));
    }
    memset (ap->apinfo.id, 0, sizeof (ap->apinfo.id));
    memset (ap->apinfo.ssid, 0, sizeof (ap->apinfo.ssid));
    memset (ap->apinfo.encrypt, 0, sizeof (ap->apinfo.encrypt));
    memset (ap->apinfo.key, 0, sizeof (ap->apinfo.key));
  }

	if (apname != NULL && apname[0] != 0)
  {
    memset (ap->apname, 0, sizeof (ap->apname));
    strncpy (ap->apname, apname, strlen (apname));
  }
  for (i = 0; id[i][0] != 0; i++)
  {
    if ((tpl = find_template (id[i])) == NULL)
			continue;
    sprintf (ap->apinfo.id + strlen (ap->apinfo.id), "%s,", id[i]);
    sprintf (ap->apinfo.ssid + strlen (ap->apinfo.ssid), "%s,", tpl->ssid);
		sprintf(ap->apinfo.encrypt + strlen(ap->apinfo.encrypt), "%s,", tpl->encrypt);
    sprintf (ap->apinfo.key + strlen (ap->apinfo.key), "%s,", tpl->key);
  }
  if (i != 0)
  {
    ap->apinfo.id[strlen (ap->apinfo.id) - 1] = 0;
    ap->apinfo.ssid[strlen (ap->apinfo.ssid) - 1] = 0;
    ap->apinfo.encrypt[strlen (ap->apinfo.encrypt) - 1] = 0;
    ap->apinfo.key[strlen (ap->apinfo.key) - 1] = 0;
  }
  format_ap_cfg (ap, res);
  sprintf (name, "ap_cfg_%d", ap->apid);
  write_apinfo("aplist", name, res);

  ap->ud.type = AP_INFO;
  ap->ud.session = SPROTO_REQUEST;
  if (send_data_to_ap (ap) <= 0)
  {
    blobmsg_add_string (&b, "msg", "Distributed configuration failed");
    goto error;
  }
  blobmsg_add_u32 (&b, "code", 0);
  return ubus_send_reply (ctx, req, b.head);
error:
	blobmsg_add_u32 (&b, "code", 1);
  return ubus_send_reply (ctx, req, b.head);
}

static const struct blobmsg_policy apedit_policy[__CFG_MAX] = {
  [MAC] = {.name = "mac",.type = BLOBMSG_TYPE_STRING},
  [SN] = {.name = "sn",.type = BLOBMSG_TYPE_STRING},
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
	char *ssid = NULL, *key = NULL, *encrypt = NULL, *tpname = NULL
		, name[20] = {0}, res[1024] = {0}, sid[10] = {0};
  tmplat_list *tp = NULL;
  int id = -1;
  char edit_temp0_flag = false;

  if (tb[TMPLATID])
    id = blobmsg_get_u32 (tb[TMPLATID]);
  if (tb[SSID])
    ssid = blobmsg_get_string (tb[SSID]);
  if (tb[ENCRYPT])
    encrypt = blobmsg_get_string (tb[ENCRYPT]);
  if (tb[KEY])
    key = blobmsg_get_string (tb[KEY]);
	if (tb[NAME])
    tpname = blobmsg_get_string (tb[NAME]);
  if (tb[EDIT_FLAG] )
	  edit_temp0_flag = blobmsg_get_bool(tb[EDIT_FLAG]);

  blob_buf_init (&b, 0);
	if (id < 0)
	{
		blobmsg_add_string (&b, "msg", "Need template id!");
    goto error;
	}
	sprintf (sid, "%d", id);
  if ((id == 0 && edit_temp0_flag== false) || (tp = find_template (sid)) == NULL)
  {
    blobmsg_add_string (&b, "msg", "template id invalid");
    goto error;
  }
  if (ssid != NULL && ssid[0] != 0)
    strcpy (tp->ssid, ssid);
	if (tpname != NULL && tpname[0] != 0)
    strcpy (tp->tpname, tpname);
  if (encrypt != NULL && encrypt[0] != 0)
  {
		strcpy (tp->encrypt, encrypt);
		if (strcasecmp(tp->encrypt, "none") != 0)
			if (key == NULL || key[0] == 0)
			{
		    blobmsg_add_string (&b, "msg", "need key");
		    goto error;
		  }
  }
	if (key != NULL && key[0] != 0)
	{
		if (strlen (key) < 8)
		{
			blobmsg_add_string (&b, "msg", "Invalid key");
			goto error;
		}
		strcpy (tp->key, key);
	}

  sprintf (name, "template_%s", sid);
  format_tmp_cfg (tp, res);
  write_apinfo("tplist", name, res);
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
	char *str = NULL, res[1024], name[20], sid[20] = {0}, tmp[100] = {0};
  ap_list *ap = aplist;
  tmplat_list *tp = NULL;
  int id = -1;


  if (tb[TMPLATID])
    id = blobmsg_get_u32 (tb[TMPLATID]);
  blob_buf_init (&b, 0);
  if (id == -1 || id == 0)
  {
  	blobmsg_add_string (&b, "msg", "Need template id!");
    goto error;
  }
  sprintf (sid, "%d", id);
  if ((tp = find_template (sid)) == NULL)
 	{
 		blobmsg_add_string (&b, "msg", "id error,not found this template");
    goto error;
  }
  while (ap->rlink)
	{
	  ap = ap->rlink;
	  if (strstr (ap->apinfo.id, sid) == NULL)
			continue;
		strcpy (tmp, ap->apinfo.id);
	  memset (ap->apinfo.ssid, 0, sizeof (ap->apinfo.ssid));
	  memset (ap->apinfo.encrypt, 0, sizeof (ap->apinfo.encrypt));
	  memset (ap->apinfo.key, 0, sizeof (ap->apinfo.key));
	  memset (ap->apinfo.id, 0, sizeof (ap->apinfo.id));
	  str = strtok (tmp, ",");
	  while (str)
		{
			if (strcasecmp(str, sid) != 0 && (tp = find_template(str)) != NULL)
			{
			  sprintf (ap->apinfo.id + strlen (ap->apinfo.id), "%s,", tp->id);
				sprintf(ap->apinfo.ssid + strlen(ap->apinfo.ssid), "%s,", tp->ssid);
				sprintf(ap->apinfo.encrypt + strlen(ap->apinfo.encrypt), "%s,", tp->encrypt);
				sprintf(ap->apinfo.key + strlen(ap->apinfo.key), "%s,", tp->key);
			}
			str = strtok (NULL, ",");
		}
	  if (strlen (ap->apinfo.id) == 0 && (tp = find_template ("0")) != NULL)
		{
			sprintf (ap->apinfo.id, "%s,", tp->id);
			sprintf (ap->apinfo.ssid, "%s,", tp->ssid);
			sprintf (ap->apinfo.encrypt, "%s,", tp->encrypt);
			sprintf (ap->apinfo.key, "%s,", tp->key);
		}
	  ap->apinfo.id[strlen (ap->apinfo.id) - 1] = 0;
	  ap->apinfo.ssid[strlen (ap->apinfo.ssid) - 1] = 0;
	  ap->apinfo.encrypt[strlen (ap->apinfo.encrypt) - 1] = 0;
	  ap->apinfo.key[strlen (ap->apinfo.key) - 1] = 0;
	  bzero (res, sizeof (res));
	  format_ap_cfg (ap, res);
	  bzero (name, sizeof (name));
	  sprintf (name, "ap_cfg_%d", ap->apid);
	  write_apinfo("aplist", name, res);

	  ap->ud.type = AP_INFO;
	  ap->ud.session = SPROTO_REQUEST;
	  send_data_to_ap (ap);
	}

  bzero (name, sizeof (name));
  sprintf (name, "template_%s", sid);
  del_apinfo("tplist", name);
  del_template (tplist, sid);

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
  tmplat_list *tp = tplist, *p = NULL;
  void *arr = NULL, *table = NULL;
  int id = -1;
  char sid[5] = { 0 };
	blobmsg_parse(templatelist_policy, __CFG_MAX, tb, blob_data(msg), blob_len(msg));
	if (tb[TMPLATID]){
    id = blobmsg_get_u32 (tb[TMPLATID]);
    sprintf (sid, "%d", id);
		p = find_template (sid);
  }

  blob_buf_init (&b, 0);
  if (p != NULL)
  {
    template_to_blob (&b, p);
    return ubus_send_reply (ctx, req, b.head);
  }
  if (id != -1)
  {
    blobmsg_add_u32 (&b, "code", 1);
    blobmsg_add_string (&b, "msg", "template info not found");
    return ubus_send_reply (ctx, req, b.head);
  }

  arr = blobmsg_open_array (&b, "data");
  while (tp->rlink)
  {
    tp = tp->rlink;
    table = blobmsg_open_table (&b, tp->id);
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
	char *ssid = NULL, *encrypt = NULL, *key = NULL, *tpname = NULL, name[20] = {0}, res[1024] = {0}, tid[2];
	int id = 1;
	tmplat_list p, *tpl = NULL;

	blobmsg_parse(templateadd_policy, __CFG_MAX, tb, blob_data(msg), blob_len(msg));
  if (tb[SSID])
		ssid = blobmsg_get_string (tb[SSID]);
  if (tb[ENCRYPT])
		encrypt = blobmsg_get_string (tb[ENCRYPT]);
  if (tb[KEY])
		key = blobmsg_get_string (tb[KEY]);
	if (tb[NAME])
		tpname = blobmsg_get_string (tb[NAME]);
  blob_buf_init (&b, 0);
	memset(&p, 0, sizeof(tmplat_list));
  if (ssid == NULL || ssid[0] == 0)
  {
  	blobmsg_add_string (&b, "msg", "Need ssid!");
    goto error;
  }
  while (1)
	{
		bzero(tid, sizeof(tid));
		sprintf(tid, "%d", id);
		if ((tpl = find_template(tid)) == NULL)
			break;
		id++;
	}
	if (tpname != NULL && tpname[0] != 0)
		strcpy(p.tpname, tpname);
  strcpy (p.ssid, ssid);
  sprintf (p.id, "%d", id);
	if (encrypt != NULL && encrypt[0] != 0)
	{
		strcpy (p.encrypt, encrypt);
		if (strcasecmp(encrypt, "none") != 0)
		{
			if (key == NULL || key[0] == 0)
			{
				blobmsg_add_string (&b, "msg", "Need key!");
				goto error;
			}
		}
		else
			strcpy (p.key, "88888888");
		if (key != NULL && key[0] != 0)
		{
			if (strlen(key) < 8)
			{
				blobmsg_add_string (&b, "msg", "the key length must greater than or equal 8!");
				goto error;
			}
	  	strcpy (p.key, key);
		}
	}
	else
	{
		strcpy (p.encrypt, "none");
		strcpy (p.key, "88888888");
	}
  if (insert_template (&p) <= 0)
    goto error;
  sprintf (name, "template_%s", p.id);
  format_tmp_cfg (&p, res);
  write_apinfo("tplist", name, res);

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
  char *mac = NULL, *sn = NULL, name[20] = { 0 }, buf[20] = {0};
  ap_list *ap = NULL;

	blobmsg_parse(apdel_policy, __CFG_MAX, tb, blob_data(msg), blob_len(msg));
  if (tb[MAC])
    mac = blobmsg_get_string (tb[MAC]);
  if (tb[SN])
    sn = blobmsg_get_string (tb[SN]);
  blob_buf_init (&b, 0);
  ap = find_apmember (mac, sn, 0);
  if (ap == NULL)
  {
    blobmsg_add_u32 (&b, "code", 1);
    blobmsg_add_string (&b, "msg", "not found this ap!");
    goto end;
  }
	strncpy(buf, ap->apinfo.apmac, 20);
  sprintf (name, "ap_cfg_%d", ap->apid);
	free_mem(ap);
  del_apmember (buf, NULL);
  del_apinfo("aplist", name);
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
  char *mac = NULL, *sn = NULL, *addr = NULL, *cmd = NULL;
  ap_list *ap = NULL;
  int len = 0;

	blobmsg_parse(apcmd_policy, __CFG_MAX, tb, blob_data(msg), blob_len(msg));
  if (tb[MAC])
    mac = blobmsg_get_string (tb[MAC]);
  if (tb[SN])
    sn = blobmsg_get_string (tb[SN]);
  if (tb[CMD])
    cmd = blobmsg_get_string (tb[CMD]);
  blob_buf_init (&b, 0);
  ap = find_apmember (mac, sn, 0);

	if (ap == NULL || ap->online == OFF)
	{
 		blobmsg_add_string (&b, "msg", "not found ap or ap off-line");
    goto error;
  }
  if (cmd == NULL || cmd[0] == 0)
 	{
 		blobmsg_add_string (&b, "msg", "mac invalid or need command");
    goto error;
  }
  if (strcasecmp(cmd, "reboot") == 0)
  {
    ap->ud.type = AP_CMD;
    ap->ud.session = SPROTO_REQUEST;
    ap->cmd.cmd = REBOOT;
    if ((len = send_data_to_ap (ap)) <= 0)
			goto error;
  }
  else if (strcasecmp(cmd, "upgrade") == 0)
	{
		if (tb[ADDR])
			addr = blobmsg_get_string (tb[ADDR]);
		if (addr == NULL || addr[0] == 0)
			goto error;
		ap->ud.type = AP_CMD;
		ap->ud.session = SPROTO_REQUEST;
		ap->cmd.cmd = UPGRADE;
		strcpy (ap->cmd.addr, addr);
		if ((len = send_data_to_ap (ap)) <= 0)
			goto error;
	}
  blobmsg_add_u32 (&b, "code", 0);
  ubus_send_reply (ctx, req, b.head);
  return UBUS_STATUS_OK;
error:
  blobmsg_add_u32 (&b, "code", 2);
  return ubus_send_reply (ctx, req, b.head);
}


static const struct ubus_method acd_methods[] = {
  UBUS_METHOD_MASK ("apinfo", ubus_proc_apinfo, apinfo_policy
			, 1 << MAC | 1 << SN),
  UBUS_METHOD_MASK ("apedit", ubus_proc_apedit, apedit_policy
  		, 1 << MAC | 1 << SN | 1 << NAME | 1 << TMPLATID | 1 << CHANNEL | 1 << TXPOWER),
  UBUS_METHOD_MASK ("templatedit", ubus_proc_templatedit, templatedit_policy
  		, 1 << TMPLATID | 1 << SSID | 1 << ENCRYPT | 1 << NAME | 1 << KEY | 1<<EDIT_FLAG),

  UBUS_METHOD_MASK ("templatelist", ubus_proc_templatelist, templatelist_policy
  		, 1 << TMPLATID),
  UBUS_METHOD_MASK ("templateadd", ubus_proc_templateadd, templateadd_policy
  		, 1 << SSID | 1 << ENCRYPT | 1 << NAME | 1 << KEY),
  UBUS_METHOD_MASK ("templatedel", ubus_proc_templatedel, templatedel_policy
  		, 1 << TMPLATID),
  UBUS_METHOD_MASK ("apdel", ubus_proc_apdel, apdel_policy
  		, 1 << 1 << MAC | 1 << SN),
  UBUS_METHOD_MASK ("apcmd", ubus_proc_apcmd, apcmd_policy
  		, 1 << MAC | 1 << SN | 1 << CMD | 1 << ADDR),
};

static struct ubus_object_type acd_object_type =
UBUS_OBJECT_TYPE ("acd", acd_methods);

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
  if (ret)
    fprintf (stderr, "Failed to add object: %s\n", ubus_strerror (ret));

  return;
}

static int run_server(void)
{
  server.cb = server_cb;
	server.fd = usock(USOCK_TCP | USOCK_SERVER | USOCK_IPV4ONLY | USOCK_NUMERIC, "0.0.0.0", port);
	if (server.fd < 0) {
    run_server();
		sleep(3);
  }
  uloop_fd_add (&server, ULOOP_READ | ULOOP_WRITE);

  return 0;
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

void acd_init(void)
{
	if ((aplist = create_aplist()) == NULL || (tplist = create_tplist()) == NULL)
    exit (0);
  if (sproto_read_entity ("/usr/share/apc.sp") <= 0)
  {
		printf("Cannt read sproto");
		exit(0);
  }

  if (access ("/etc/aplist", F_OK) != 0)
	{
		system ("touch /etc/aplist");
	}
  if (access ("/etc/tplist", F_OK) != 0)
	{
		system ("touch /etc/tplist");
	}

	while(is_ip(rip) <= 0)
	{
		get_loca_ip ();
		sleep(2);
	}
  tplist_init ();
  aplist_init ();
  return;
}

int main(int argc, char **argv)
{
  int ch;
  const char *ubus_socket = NULL;
	while ((ch = getopt(argc, argv, "dp:s:")) != -1)
	{
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
