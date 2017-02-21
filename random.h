#ifndef _RANDOM_H
#define _RANDOM_H
#include <fcntl.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#define u16 unsigned short
#define u32 unsigned int
#define u8  char
#define u8_t unsigned char 

extern void get_random_bytes(void *buf, int nbytes);

#endif
