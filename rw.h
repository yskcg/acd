#ifndef _RW_H
#define _RW_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


int write_apinfo(char *fname, char *tagname, char *value);
char *read_apinfo(char *fname, char *tagname, char *value);
void del_apinfo(char *fname, char *tagname);

#endif


