#ifndef __JSON_PARSE__
#define __JSON_PARSE__
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef JSONC
	#include <json.h>
#else
	#include <json-c/json.h>
	#include <json-c/json_object.h>
#endif

#include "acd.h"

extern int json_parse(const char *json_input,const char *field,char * output);
#endif
