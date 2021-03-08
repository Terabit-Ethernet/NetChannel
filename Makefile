# Makefile to build ND as a Linux module.

obj-m += nd_module.o
nd_module-y = 	 nd_host.o\
				 nd_sock.o\
				 nd_hashtables.o \
				 nd_pq.o \
				 nd_page_pool.o\
				 nd_incoming.o\
				 nd_outgoing.o \
				 nd_data_copy.o\
				 nd.o \
				 nd_target.o\
				 nd_plumbing.o

# nd.o \
#             ndlite.o \
#             nd_offload.o \
#             nd_tunnel.o \
#  			/nd_diag.o
MY_CFLAGS += -g
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	
check:
	../ndLinux/scripts/kernel-doc -none *.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	
# The following targets are useful for debugging Makefiles; they
# print the value of a make variable in one of several contexts.
print-%:
	@echo $* = $($*)
	
printBuild-%:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) $@
	
printClean-%:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) $@
	
