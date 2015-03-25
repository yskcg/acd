
LDFLAGS += -ljson-c -lblobmsg_json -lm -ldl -lubox -luci -lubus

all:acd

rw.o:rw.c rw.h
	@$(CC) -Wall -g -c rw.c rw.h
	
sproto.o:sproto.c sproto.h msvcint.h
	@$(CC) -Wall -g -c sproto.c sproto.h msvcint.h
	
acd.o:acd.c acd.h
	@$(CC) -Wall -g -c acd.c
	
acd:acd.o sproto.o rw.o
	@$(CC) -Wall -g -o acd acd.o sproto.o rw.o $(LDFLAGS)
#	@lua apc.lua

	
clean:
	@rm -rf acd
	@rm -rf *bak
	@rm -rf *.o
