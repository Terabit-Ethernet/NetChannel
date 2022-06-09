liburing-path = /home/sigcomm22/liburing
CFLAGS := -Wall -Werror -g -fno-strict-aliasing -O3 -I..

BINS := netdriver_test netdriver_test_multithread  pingpong_server pingpong_server_async server iouring_bench iouring_bench_nc

OBJS := $(patsubst %,%.o,$(BINS))
	
LIB_SRCS := test_utils.cc
LIB_OBJS := $(patsubst %.c,%.o,$(patsubst %.cc,%.o,$(LIB_SRCS)))
	
.SECONDARY: $(OBJS) $(LIB_OBJS)

all: $(BINS)
	
iouring_bench: iouring_bench.o $(LIB_OBJS)
	g++ $(CFLAGS) $^ -L$(liburing-path)/src/ -lpthread -luring -o $@

iouring_bench.o: iouring_bench.c test_utils.h
	cc -c $(CFLAGS) $< -o $@ -I$(liburing-path)/src/include/

iouring_bench_nc: iouring_bench_nc.o $(LIB_OBJS)
	g++ $(CFLAGS) $^ -L$(liburing-path)/src/ -lpthread -luring -o $@

iouring_bench_nc.o: iouring_bench_nc.c test_utils.h
	cc -c $(CFLAGS) $< -o $@ -I$(liburing-path)/src/include/

# This seems to be the only way to disable the built-in implicit rules
# for %:%.c and %:%.cc.
.SUFFIXES:
	
%: %.o $(LIB_OBJS)
	g++ $(CFLAGS) $^ -lpthread -o $@
	
%.o: %.cc test_utils.h 
	g++ -c $(CFLAGS) -std=c++17 $< -o $@
	
%.o: %.c test_utils.h 
	cc -c $(CFLAGS) $< -o $@
	
clean:
	rm -f $(BINS) $(OBJS) $(LIB_OBJS)

# The following target is useful for debugging Makefiles; it
# prints the value of a make variable.
print-%:
	@echo $* = $($*)
	
