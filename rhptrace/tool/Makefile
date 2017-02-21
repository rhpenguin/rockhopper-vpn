
CC = gcc
CFLAGS = -g -O0 -Wall -fno-strict-aliasing
LDFLAGS =
LIBS = -lpthread

RHP_INCS = -I../include/ -I/usr/include/libxml2
CFLAGS += $(RHP_INCS)

all: rhp_trace_start_stop rhp_trace_helper rhp_trace

rhp_trace_start_stop: rhp_trace_start_stop.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o rhp_trace_start_stop rhp_trace_start_stop.c

rhp_trace_helper: rhp_trace_helper.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o rhp_trace_helper rhp_trace_helper.c

rhp_trace: rhp_trace_util.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o rhp_trace rhp_trace_util.c -lxml2

clean:
	rm -f *.o rhp_trace_start_stop rhp_trace_helper rhp_trace

