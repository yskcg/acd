#ifndef _STATION_H
#define _STATION_H

#include "info.h"
#include "rw.h"

#define STATION_ON			1
#define STATION_OFF			0

#define GUEST_LIST_MAC		"GuestListMca_src"


extern sta_entry *stalist_entry_update(sta_entry *sta_info);
#endif
