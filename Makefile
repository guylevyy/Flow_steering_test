CC = gcc
CFLAGS += -g -O2 -Wall -W
#-Werror
LDFLAGS += -libverbs -lvl -lpthread
OBJECTS = main.o resources.o test_traffic.o
TARGETS = steering_test

all: $(TARGETS)

steering_test: $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

main.o: main.c types.h test_traffic.h resources.h main.h
	$(CC) -c $(CFLAGS) $<

resources.o: resources.c resources.h types.h main.h
	$(CC) -c $(CFLAGS) $<

test_traffic.o: test_traffic.c test_traffic.h types.h resources.h main.h
	$(CC) -c $(CFLAGS) $<

clean:
	rm -f $(OBJECTS) $(TARGETS)

