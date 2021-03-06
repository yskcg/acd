
LDFLAGS += -ljson-c -lblobmsg_json -lm -ldl -lubox -luci -lubus

all:acd

random.o:random.c random.h 
	@$(CC) -Wall -g -c random.c random.h 

rw.o:rw.c rw.h jhash.h list.h etherdevice.h random.h info.h acd.h
	@$(CC) -Wall -g -c rw.c rw.h jhash.h list.h etherdevice.h random.h info.h acd.h
	
sproto.o:sproto.c sproto.h msvcint.h
	@$(CC) -Wall -g -c sproto.c sproto.h msvcint.h

station.o:station.c station.h 
	@$(CC) -Wall -g -c station.c station.h

json_parse.o:json_parse.c json_parse.h
	@$(CC) -Wall -g -c json_parse.c

acd.o:acd.c acd.h  
	@$(CC) -Wall -g -c acd.c acd.h 
	
acd:acd.o sproto.o rw.o random.o station.o json_parse.o
	@$(CC) -Wall -g -o acd acd.o random.o station.o json_parse.o sproto.o rw.o  $(LDFLAGS)
#	@lua apc.lua

	
clean:
	@rm -rf acd
	@rm -rf *bak
	@rm -rf *.o
