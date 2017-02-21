
TARGET = librhptrace
CC = gcc
#CFLAGS = -fPIC -g -O2 -Wall -DRHP_TRACE_LIB_DEBUG -D_GNU_SOURCE -D_REENTRANT
CFLAGS = -fPIC -g -O2 -Wall -fno-strict-aliasing -D_GNU_SOURCE -D_REENTRANT
LDFLAGS = -Wl,-soname,$(TARGET).so
LIBS = -lpthread

OBJS = rhp_trace_lib.o

RHP_INCS = -I../include/
CFLAGS += $(RHP_INCS)

all: $(OBJS)
	$(CC) -shared $(LDFLAGS) -o $(TARGET).so $(OBJS) $(LIBS)

clean:
	rm -f *.o *.so.*

