#ifndef _RW_H
#define _RW_H

#include <stdio.h>
#include <stdlib.h>
#include <endian.h>
#include <string.h>
#include <unistd.h>
#include "jhash.h"
#include "list.h"
#include "etherdevice.h"
#include "random.h"
#include "info.h"
#include "acd.h"

#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
# define BB_BIG_ENDIAN 1
# define BB_LITTLE_ENDIAN 0
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
# define BB_BIG_ENDIAN 0
# define BB_LITTLE_ENDIAN 1
#elif defined(_BYTE_ORDER) && _BYTE_ORDER == _BIG_ENDIAN
# define BB_BIG_ENDIAN 1
# define BB_LITTLE_ENDIAN 0
#elif defined(_BYTE_ORDER) && _BYTE_ORDER == _LITTLE_ENDIAN
# define BB_BIG_ENDIAN 0
# define BB_LITTLE_ENDIAN 1
#elif defined(BYTE_ORDER) && BYTE_ORDER == BIG_ENDIAN
# define BB_BIG_ENDIAN 1
# define BB_LITTLE_ENDIAN 0
#elif defined(BYTE_ORDER) && BYTE_ORDER == LITTLE_ENDIAN
# define BB_BIG_ENDIAN 0
# define BB_LITTLE_ENDIAN 1
#elif defined(__386__)
# define BB_BIG_ENDIAN 0
# define BB_LITTLE_ENDIAN 1
#else
# error "Can't determine endianness"
#endif

extern tmplat_list *tplist;
/*file operation API*/
extern int file_write(char *fname, char *tagname, char *value);
extern int file_spec_content_del(char *fname, char *index);
extern int file_sort_by_key(char *fname,int filed,char *key);

/*list API*/
extern tmplat_list *template_find_by_id(char id);
extern void template_del_by_id(tmplat_list *h, char id);
extern int template_insert_by_id(tmplat_list *t);
extern tmplat_list *template_entry_init(void);

/*aplist hash API*/
extern ap_status_entry *aplist_entry_find(struct hlist_head *head, u8_t *addr);
extern ap_status_entry *aplist_entry_creat(struct hlist_head *head,const u8_t *addr);
extern ap_status_entry *aplist_entry_insert(u8_t *addr);
extern void * aplist_entry_remove(u8_t *addr);
extern int aplist_entry_hash(u8_t *addr);

/*stalist hash API*/
extern void * stalist_entry_remove(u8_t *addr);
extern sta_entry *stalist_entry_find(struct hlist_head *head, u8_t *addr);
extern sta_entry *stalist_entry_insert(u8_t *addr);
extern int stalist_entry_hash(u8_t *addr);

#endif



