#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

// overwriting socket for netdriver
typedef int (*real_socket_t)(int, int, int);
int real_socket(int domain, int type, int protocol)
{
  if((type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) != SOCK_STREAM){
     return ((real_socket_t) dlsym(RTLD_NEXT, "socket")) (domain, type, protocol);
  }
  else
     return ((real_socket_t) dlsym(RTLD_NEXT, "socket")) (domain, SOCK_DGRAM, IPPROTO_VIRTUAL_SOCK);
}

int socket(int domain, int type, int protocol)
{
    return real_socket(domain, type, protocol);
}
