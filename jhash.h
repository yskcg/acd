#ifndef _LINUX_JHASH_H
#define _LINUX_JHASH_H

/* jhash.h: Jenkins hash support.
*
* Copyright (C) 2006. Bob Jenkins (bob_jenkins@burtleburtle.net)
*
* http://burtleburtle.net/bob/hash/
*
* These are the credits from Bob's sources:
*
* lookup3.c, by Bob Jenkins, May 2006, Public Domain.
*
* These are functions for producing 32-bit hashes for hash table lookup.
* hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final()
* are externally useful functions.  Routines to test the hash are included
* if SELF_TEST is defined.  You can use this free for any purpose.  It's in
* the public domain.  It has no warranty.
*
* Copyright (C) 2009-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
*
* I've modified Bob's hash to be useful in the Linux kernel, and
* any bugs present are my fault.
* Jozsef
*/


static inline __u32 rol32(__u32 word,unsigned int shift)
{
    return (word << shift) | (word >>(32 -shift));
}


/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)			\
{						\
    c ^= b; c -= rol32(b, 14);		\
    a ^= c; a -= rol32(c, 11);		\
    b ^= a; b -= rol32(a, 25);		\
    c ^= b; c -= rol32(b, 16);		\
    a ^= c; a -= rol32(c, 4);		\
    b ^= a; b -= rol32(a, 14);		\
    c ^= b; c -= rol32(b, 24);		\
}

/* An arbitrary initial parameter */
#define JHASH_INITVAL		0xdeadbeef


/* __jhash_nwords - hash exactly 3, 2 or 1 word(s) */
static inline u32 __jhash_nwords(u32 a, u32 b, u32 c, u32 initval)
{
    a += initval;
    b += initval;
    c += initval;

    __jhash_final(a, b, c);

    return c;
}

static inline u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
    return __jhash_nwords(a, b, c, initval + JHASH_INITVAL + (3 << 2));
}

static inline u32 jhash_2words(u32 a, u32 b, u32 initval)
{
    return __jhash_nwords(a, b, 0, initval + JHASH_INITVAL + (2 << 2));
}

static inline u32 jhash_1word(u32 a, u32 initval)
{
    return __jhash_nwords(a, 0, 0, initval + JHASH_INITVAL + (1 << 2));
}

#endif /* _LINUX_JHASH_H */
