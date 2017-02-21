#include <stdio.h>
#include "random.h"

int get_random_fd(void)
{
    struct timeval	tv;
    static int	fd = -2;
    int		i;
    
	if (fd == -2) {
	gettimeofday(&tv, 0);
	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1){
	    fd = open("/dev/random", O_RDONLY | O_NONBLOCK);
	}
	srand((getpid() << 16) ^ getuid() ^ tv.tv_sec ^ tv.tv_usec);
    }
    /* Crank the random number generator a few times */
    gettimeofday(&tv, 0);
    for (i = (tv.tv_sec ^ tv.tv_usec) & 0x1F; i > 0; i--){
	rand();
    }
    return fd;
}

/*
 * Generate a series of random bytes.  Use /dev/urandom if possible,
 * and if not, use srandom/random.
 */
void get_random_bytes(void *buf, int nbytes)
{
    int i, n = nbytes, fd = get_random_fd();
    int lose_counter = 0;
    unsigned char *cp = (unsigned char *) buf;

    if (fd >= 0) {
	while (n > 0) {
	    i = read(fd, cp, n);
	    if (i <= 0) {
		if (lose_counter++ > 16){
		    break;
		}
		continue;
	    }
	    n -= i;
	    cp += i;
	    lose_counter = 0;
	}
    }

    /*
     * We do this all the time, but this is the only source of
     * randomness if /dev/random/urandom is out to lunch.
     */
    for (cp = buf, i = 0; i < nbytes; i++){
	*cp++ ^= (rand() >> 7) & 0xFF;
    }
}
