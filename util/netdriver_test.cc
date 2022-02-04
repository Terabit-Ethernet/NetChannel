/* Copyright (c) 2019, Stanford University
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

// This file contains a collection of tests for the Linux implementation
// of Homa
//
// Usage:
// homaTest host:port [options] op op ...
//
// host:port gives the location of a server to invoke
// Each op specifies a particular test to perform
#include <ctime>
#include<chrono>
#include <errno.h>
#include <iostream>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <inttypes.h>
#include <vector>
#include <thread>

//#include "../uapi_linux_nd.h"
#include "test_utils.h"
#ifndef ETH_MAX_MTU
#define ETH_MAX_MTU	0xFFFFU
#endif

#ifndef UDP_SEGMENT
#define UDP_SEGMENT		103
#endif

/* Determines message size in bytes for tests. */
int length = 1000000;

/* How many iterations to perform for the test. */
int count = 100;

/* Used to generate "somewhat random but predictable" contents for buffers. */
int seed = 12345;

/**
 * close_fd() - Helper method for "close" test: sleeps a while, then closes
 * an fd
 * @fd:   Open file descriptor to close.
 */
void close_fd(int fd)
{
	// sleep(1);
	if (close(fd) >= 0) {
		printf("Closed fd %d\n", fd);
	} else {
		printf("Close failed on fd %d: %s\n", fd, strerror(errno));
	}
}

// /**
//  * send_fd() - Helper method for "poll" test: sleeps a while, then sends
//  * a request to a socket.
//  * @fd:      File descriptor for a Homa socket; used to send the message.
//  * @addr:    Where to send the message.
//  * @request: Request message to send.
//  */
// void send_fd(int fd, struct sockaddr *addr, char *request)
// {
// 	uint64_t id;
// 	int status;
	
// 	sleep(1);
// 	status = homa_send(fd, request, length, addr, sizeof(*addr), &id);
// 	if (status < 0) {
// 		printf("Error in homa_send: %s\n",
// 			strerror(errno));
// 	} else {
// 		printf("Homa_send succeeded, id %lu\n", id);
// 	}
// }

// /**
//  * shutdown_fd() - Helper method for "close" test: sleeps a while, then shuts
//  * down an fd
//  * @fd:   Open file descriptor to shut down.
//  */
// void shutdown_fd(int fd)
// {
// 	sleep(1);
// 	if (shutdown(fd, 0) >= 0) {
// 		printf("Shutdown fd %d\n", fd);
// 	} else {
// 		printf("Shutdown failed on fd %d: %s\n", fd, strerror(errno));
// 	}
// }

/**
 * print_help() - Print out usage information for this program.
 * @name:   Name of the program (argv[0])
 */
void print_help(const char *name)
{
	printf("Usage: %s host:port [options] op op ...\n\n"
		"host:port describes a server to communicate with, and each op\n"
		"selects a particular test to run (see the code for available\n"
		"tests). The following options are supported:\n\n"
		"--count      Number of times to repeat a test (default: 1000)\n"
		"--length     Size of messages, in bytes (default: 100)\n"
		"--sp       src port of connection \n"
		"--seed       Used to compute message contents (default: 12345)\n",
		name);
}

// /**
//  * test_close() - Close a Homa socket while a thread is waiting on it.
//  */
// void test_close()
// {
// 	int result, fd;
// 	int message[100000];
// 	struct sockaddr source;
// 	uint64_t id = 0;

// 	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
// 	if (fd < 0) {
// 		printf("Couldn't open Homa socket: %s\n",
// 			strerror(errno));
// 		exit(1);
// 	}
// 	std::thread thread(close_fd, fd);
// 	result = homa_recv(fd, message, sizeof(message), HOMA_RECV_RESPONSE,
// 			&id, &source, sizeof(source));
// 	if (result > 0) {
// 		printf("Received %d bytes\n", result);
// 	} else {
// 		printf("Error in recvmsg: %s\n",
// 			strerror(errno));
// 	}
// }

// /**
//  * test_fill_memory() - Send requests to a server, but never read responses;
//  * eventually, this will cause memory to fill up.
//  * @fd:       Homa socket.
//  * @dest:     Where to send the request
//  * @request:  Request message.
//  */
// void test_fill_memory(int fd, struct sockaddr *dest, char *request)
// {
// 	uint64_t id;
// 	int status;
// 	int completed = 0;
// 	size_t total = 0;
// #define PRINT_INTERVAL 1000
// 	char buffer[length];
// 	struct sockaddr_in src_addr;
// 	ssize_t received;
// 	uint64_t start = rdtsc();

// 	for (int i = 1; i <= count; i++) {
// 		status = homa_send(fd, request, length, dest,
// 				sizeof(*dest), &id);
// 		if (status < 0) {
// 			printf("Error in homa_send: %s\n",
// 				strerror(errno));
// 			sleep(1);
// 		}
// 		total += length;
// 		if ((i % PRINT_INTERVAL) == 0) {
// 			printf("%lu MB sent (%d RPCs)\n", total/1000000, i);
// 		}
// 	}
// 	total = 0;
// 	for (int i = 1; i <= count; i++) {
// 		id = 0;
// 		received = homa_recv(fd, buffer, length, HOMA_RECV_RESPONSE,
// 				&id, (struct sockaddr *) &src_addr,
// 				sizeof(src_addr));
// 		if (received < 0) {
// 			printf("Error in homa_recv for id %lu: %s\n",
// 				id, strerror(errno));
// 		} else {
// 			total += received;
// 			completed++;
// 		}
// 		if ((i % PRINT_INTERVAL) == 0) {
// 			printf("%lu MB received (%d RPCs)\n", total/1000000, i);
// 		}
// 	}
// 	uint64_t end = rdtsc();
// 	double tput = total;
// 	tput = tput / to_seconds(end-start);
// 	double timePer = to_seconds(end-start) / completed;
// 	printf("%d/%d RPCs succeeded, average goodput %.1f MB/sec (%.1f us/RPC)\n",
// 		completed, count, tput*1e-06, timePer*1e06);
// }

// /**
//  * test_invoke() - Send a request and wait for response.
//  * @fd:       Homa socket.
//  * @dest:     Where to send the request
//  * @request:  Request message.
//  */
// void test_invoke(int fd, struct sockaddr *dest, char *request)
// {
// 	uint64_t id = 0;
// 	char response[1000000];
// 	struct sockaddr_in server_addr;
// 	int status;
// 	ssize_t resp_length;

// 	status = homa_send(fd, request, length, dest,
// 			sizeof(*dest), &id);
// 	if (status < 0) {
// 		printf("Error in homa_send: %s\n",
// 			strerror(errno));
// 	} else {
// 		printf("Homa_send succeeded, id %lu\n", id);
// 	}
// 	resp_length = homa_recv(fd, response, sizeof(response),
// 		HOMA_RECV_RESPONSE, &id, (struct sockaddr *) &server_addr,
// 		sizeof(server_addr));
// 	if (resp_length < 0) {
// 		printf("Error in homa_recv: %s\n",
// 			strerror(errno));
// 		return;
// 	}
// 	int seed = check_buffer(response + 2*sizeof32(int),
// 				resp_length - 2*sizeof32(int));
// 	printf("Received message from %s with %lu bytes, "
// 		"seed %d, id %lu\n",
// 		print_address(&server_addr), resp_length, seed, id);
// }

// /**
//  * test_ioctl() - Measure round-trip time for an ioctl kernel call that
//  * does nothing but return an error.
//  * @fd:       Homa socket.
//  * @count:    Number of reads to issue.
//  */
// void test_ioctl(int fd, int count)
// {
// 	char buffer[100];
// 	int status;
// 	uint64_t start;
// 	uint64_t times[count];

// 	for (int i = -10; i < count; i++) {
// 		start = rdtsc();
// 		status = ioctl(fd, 123456, buffer);
// 		if ((status >= 0) || (errno != EINVAL)) {
// 			printf("Unexpected return from ioctl: result %d, "
// 					"errno %s\n",
// 					status, strerror(errno));
// 			return;
// 		}
// 		if (i >= 0)
// 			times[i] = rdtsc() - start;
// 	}
// 	print_dist(times, count);
// }

// /**
//  * test_poll() - Receive a message using the poll interface.
//  * @fd:       Homa socket.
//  * @request:  Request message.
//  */
// void test_poll(int fd, char *request)
// {
// 	uint64_t id;
// 	int result;
// 	int message[100000];
// 	struct pollfd poll_info = {
// 		.fd =     fd,
// 		.events = POLLIN,
// 		.revents = 0
// 	};
// 	struct sockaddr_in source;
// 	struct sockaddr_in addr;
// 	addr.sin_family = AF_INET;
// 	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
// 	addr.sin_port = htons(500);
	
// 	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
// 		printf("Couldn't bind socket to Homa port %d: %s\n",
// 				ntohl(addr.sin_port), strerror(errno));
// 		return;
// 	}
	
// 	std::thread thread(send_fd, fd, (struct sockaddr *) &addr, request);
// 	thread.detach();
	
// 	result = poll(&poll_info, 1, -1);
// 	if (result > 0) {
// 		printf("Poll succeeded with mask 0x%x\n", poll_info.revents);
// 	} else {
// 		printf("Poll failed: %s\n", strerror(errno));
// 		return;
// 	}
	
// 	result = homa_recv(fd, message, sizeof(message), HOMA_RECV_REQUEST,
// 			&id, (struct sockaddr *) &source, sizeof(source));
// 	if (result < 0) {
// 		printf("homa_recv failed: %s\n", strerror(errno));
// 	} else {
// 		printf("homa_recv returned %d bytes from port %d\n",
// 				result, ntohs(source.sin_port));
// 	}
// }

// /**
//  * test_read() - Measure round-trip time for a read kernel call that
//  * does nothing but return an error.
//  * @fd:       Homa socket.
//  * @count:    Number of reads to issue.
//  */
// void test_read(int fd, int count)
// {
// 	char buffer[100];
// 	int status;
// 	uint64_t start;
// 	uint64_t times[count];

// 	for (int i = -10; i < count; i++) {
// 		start = rdtsc();
// 		status = read(fd, buffer, sizeof(buffer));
// 		if ((status >= 0) || (errno != EINVAL)) {
// 			printf("Unexpected return from read: result %d, "
// 					"errno %s\n",
// 					status, strerror(errno));
// 			return;
// 		}
// 		if (i >= 0)
// 			times[i] = rdtsc() - start;
// 	}
// 	print_dist(times, count);
// }

// /**
//  * test_rtt() - Measure round-trip time for an RPC.
//  * @fd:       Homa socket.
//  * @dest:     Where to send requests.
//  * @request:  Request message.
//  */
// void test_rtt(int fd, struct sockaddr *dest, char *request)
// {
// 	uint64_t id;
// 	char response[1000000];
// 	struct sockaddr_in server_addr;
// 	int status;
// 	ssize_t resp_length;
// 	uint64_t start_cycles = rdtsc(), iter_cycles = rdtsc();
// 	uint64_t times[count];
// 	uint64_t bytes_sent, start_bytes;
// 	double rate;
//     std::chrono::steady_clock::time_point start_clock = std::chrono::steady_clock::now();
//     while(1) {
// 		if(std::chrono::steady_clock::now() - start_clock > std::chrono::seconds(60)) 
// 	            break;
// 	    start_bytes = bytes_sent = 0;
// 	    start_cycles = rdtsc();
// 		for (int i = -10; i < count; i++) {
// 			iter_cycles = rdtsc();
// 			status = homa_send(fd, request, length, dest,
// 					sizeof(*dest), &id);
// 			if (status < 0) {
// 				printf("Error in homa_send: %s\n",
// 						strerror(errno));
// 				return;
// 			}
// 			resp_length = homa_recv(fd, response, sizeof(response),
// 				HOMA_RECV_RESPONSE, &id,
// 				(struct sockaddr *) &server_addr, sizeof(server_addr));
// 			if (i >= 0)
// 				times[i] = rdtsc() - iter_cycles;
// 			bytes_sent += length;
// 			if (resp_length < 0) {
// 				printf("Error in homa_recv: %s\n",
// 						strerror(errno));
// 				return;
// 			}
// 			// if (resp_length != length)
// 			// 	printf("Expected %d bytes in response, received %ld\n",
// 			// 			length, resp_length);
// 		}
// 		uint64_t end_cycles = rdtsc();
// 	    rate = ((double) bytes_sent - start_bytes)/ to_seconds(
// 			end_cycles - start_cycles);
// 		print_dist(times, count);
// 		// printf("Bandwidth at median: %.1f MB/sec\n",
// 		// 		2.0*((double) length)/(to_seconds(times[count/2])*1e06));
// 		printf("Homa throughput using %d byte messages: "
// 			"%.2f GB/sec\n", length, rate*1e-09);
//     }

// }

// /**
//  * test_send() - Send a request; don't wait for response.
//  * @fd:       Homa socket.
//  * @dest:     Where to send the request
//  * @request:  Request message.
//  */
// void test_send(int fd, struct sockaddr *dest, char *request)
// {
// 	uint64_t id;
// 	int status;

// 	status = homa_send(fd, request, length, dest,
// 			sizeof(*dest), &id);
// 	if (status < 0) {
// 		printf("Error in homa_send: %s\n",
// 			strerror(errno));
// 	} else {
// 		printf("Homa_send succeeded, id %lu\n", id);
// 	}
// }

/**
 * test_shutdown() - Shutdown a Homa socket while a thread is waiting on it.
 * @fd:   Homa socket
 */
// void test_shutdown(int fd)
// {
// 	int result;
// 	int message[100000];
// 	struct sockaddr source;
// 	uint64_t id = 0;

// 	std::thread thread(shutdown_fd, fd);
// 	thread.detach();
// 	result = homa_recv(fd, message, sizeof(message), HOMA_RECV_RESPONSE,
// 			&id, &source, sizeof(source));
// 	if (result > 0) {
// 		printf("Received %d bytes\n", result);
// 	} else {
// 		printf("Error in homa_recv: %s\n",
// 			strerror(errno));
// 	}
	
// 	/* Make sure that future reads also fail. */
// 	result = homa_recv(fd, message, sizeof(message), HOMA_RECV_RESPONSE,
// 			&id, &source, sizeof(source));
// 	if (result < 0) {
// 		printf("Second homa_recv call also failed: %s\n",
// 			strerror(errno));
// 	} else {
// 		printf("Second homa_recv call succeeded: %d bytes\n", result);
// 	}
// }

/**
 * test_stream() - measure Homa's throughput in streaming mode by
 * maintaining --count outstanding RPCs at any given time, each with --length
 * bytes of data. Data flows only in one direction
 * @fd:       Homa socket
 * @dest:     Where to send requests
 */
// void test_stream(int fd, struct sockaddr *dest)
// {
// #define MAX_RPCS 100
// 	int *buffers[MAX_RPCS];
// 	int response[100];
// 	ssize_t resp_length;
// 	uint64_t id, end_cycles;
// 	uint64_t start_cycles = 0;
// 	int status, i;
// 	int64_t bytes_sent = 0;
// 	int64_t start_bytes = 0;
// 	double rate;
	
// 	if (count > MAX_RPCS) {
// 		printf("Count too large; reducing from %d to %d\n", count,
// 				MAX_RPCS);
// 		count = MAX_RPCS;
// 	}
// 	for (i = 0; i < count; i++) {
// 		buffers[i] = (int *) malloc(length);
// 		buffers[i][0] = length;
// 		buffers[i][1] = 12;
// 		seed_buffer(buffers[i]+2, length - 2*sizeof32(int), 1000*i);
// 	}
// 	for (i = 0; i < count; i++) {
// 		status = homa_send(fd, buffers[i], length, dest,
// 				sizeof(*dest), &id);
// 		if (status < 0) {
// 			printf("Error in homa_send: %s\n", strerror(errno));
// 			return;
// 		}
// 	}
	
// 	/* Each iteration through the following the loop waits for a
// 	 * response to an outstanding request, then initiates a new
// 	 * request.
// 	 */
// 	while (1){
// 		id = 0;
// 		resp_length = homa_recv(fd, response, sizeof(response),
// 			HOMA_RECV_RESPONSE, &id, NULL, 0);
// 		if (resp_length < 0) {
// 			printf("Error in homa_recv: %s\n",
// 					strerror(errno));
// 			return;
// 		}
// 		if (resp_length != 12)
// 			printf("Expected 12 bytes in response, received %ld\n",
// 					resp_length);
// 		status = homa_send(fd, buffers[(response[2]/1000) %count],
// 				length, dest, sizeof(*dest), &id);
// 		if (status < 0) {
// 			printf("Error in homa_send: %s\n", strerror(errno));
// 			return;
// 		}
// 		bytes_sent += length;
// 		if (bytes_sent > 1001000000)
// 			break;
		
// 		/* Don't start timing until we've sent a few bytes to warm
// 		 * everything up.
// 		 */
// 		if ((start_bytes == 0) && (bytes_sent > 1000000)) {
// 			start_bytes = bytes_sent;
// 			start_cycles = rdtsc();
// 		}
// 	}
// 	end_cycles = rdtsc();
// 	rate = ((double) bytes_sent - start_bytes)/ to_seconds(
// 			end_cycles - start_cycles);
// 	printf("Homa throughput using %d concurrent %d byte messages: "
// 			"%.2f GB/sec\n", count, length, rate*1e-09);
	
// 	for (i = 0; i < count; i++)
// 		free(buffers[i]);
// }

// void test_stream(int fd, struct sockaddr *dest, char *request)
// {
// 	uint64_t id;
// 	// char response[1000000];
// 	// struct sockaddr_in server_addr;
// 	int status;
// 	// ssize_t resp_length;
// 	uint64_t start_cycles = rdtsc();
// 	uint64_t bytes_sent, start_bytes;
// 	double rate;
//     std::chrono::steady_clock::time_point start_clock = std::chrono::steady_clock::now();
//     while(1) {
// 		if(std::chrono::steady_clock::now() - start_clock > std::chrono::seconds(60)) 
// 	            break;
// 	    start_bytes = bytes_sent = 0;
// 	    start_cycles = rdtsc();
// 		for (int i = 0; i < count; i++) {
// 			status = homa_send(fd, request, length, dest,
// 					sizeof(*dest), &id);
// 			if (status < 0) {
// 				printf("Error in homa_send: %s\n",
// 						strerror(errno));
// 				return;
// 			}
// 			bytes_sent += length;

// 			// resp_length = homa_recv(fd, response, sizeof(response),
// 			// 	HOMA_RECV_RESPONSE, &id,
// 			// 	(struct sockaddr *) &server_addr, sizeof(server_addr));

// 			// if (resp_length < 0) {
// 			// 	printf("Error in homa_recv: %s\n",
// 			// 			strerror(errno));
// 			// 	return;
// 			// }
// 			// if (resp_length != length)
// 			// 	printf("Expected %d bytes in response, received %ld\n",
// 			// 			length, resp_length);
// 		}
// 		uint64_t end_cycles = rdtsc();
// 	    rate = ((double) bytes_sent - start_bytes)/ to_seconds(
// 			end_cycles - start_cycles);
// 		// print_dist(times, count);
// 		// printf("Bandwidth at median: %.1f MB/sec\n",
// 		// 		2.0*((double) length)/(to_seconds(times[count/2])*1e06));
// 		printf("Homa throughput using %d byte messages: "
// 			"%.2f Gbps/sec\n", length, rate * 1e-09 * 8);
//     }

// }

/* test correctness */
void send_file(std::string filename, int socket_fd,  struct sockaddr *dest) {
	int buffer_size = 10000000, nread;
	char *buf = (char*)malloc(buffer_size);
	FILE *file = fopen(filename.c_str(), "r");

	if (connect(socket_fd, dest, sizeof(struct sockaddr_in)) == -1) {
		printf("Couldn't connect to dest %s\n", strerror(errno));
		exit(1);
	}
	
	while ((nread = fread(buf, 1, buffer_size, file)) > 0) {
		int write_len = 0;
		while(write_len < nread) {
	    	int result = write(socket_fd, buf + write_len, buffer_size - write_len);	
			if( result < 0 ) {
				if(errno == EMSGSIZE) {
					// printf("Socket write failed: %s %d\n", strerror(errno), result);
					break;
				}
			} else {
				write_len += result;
			}
		}
	}
	if(feof(file)) {
		std::cout << "finish sending" << std::endl;
	}
	fclose(file);
	return;
}

/**
 * test_tcpstream() - Measure throughput of a TCP socket using --length as
 * the size of the buffer for each write system call.
 * @server_name:  Name of the server machine.
 * @port:         Server port to connect to.
 */
void test_tcpstream(char *server_name, int port)
{
	struct addrinfo hints;
	struct addrinfo *matching_addresses;
	struct sockaddr *dest;
	int status;
	int buffer[1000000];
	int64_t bytes_sent = 0;
	int64_t start_bytes = 0;
	uint64_t start_cycles = 0;
	int64_t total_sent = 0;
	double elapsed, rate;
	
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	status = getaddrinfo(server_name, "80", &hints, &matching_addresses);
	if (status != 0) {
		printf("Couldn't look up address for %s: %s\n",
				server_name, gai_strerror(status));
		return;
	}
	dest = matching_addresses->ai_addr;
	((struct sockaddr_in *) dest)->sin_port = htons(port);
	
	int fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		printf("Couldn't open client socket: %s\n", strerror(errno));
		return;
	}
	if (connect(fd, dest, sizeof(struct sockaddr_in)) == -1) {
		printf("Couldn't connect to %s:%d: %s\n", server_name, port,
				strerror(errno));
		return;
	}
	int flag = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	buffer[0] = -1;
	std::chrono::steady_clock::time_point start_clock = std::chrono::steady_clock::now();

	while (1) {
		start_bytes = bytes_sent = 0;
	    start_cycles = rdtsc();

		// if (bytes_sent > 1010000000)
		// 	break;
		if(std::chrono::steady_clock::now() - start_clock > std::chrono::seconds(60)) 
	            break;

	    for (int i = 0; i < count; i++) {
	    	if (write(fd, buffer, 1000000) != 1000000) {
				printf("Socket write failed: %s\n", strerror(errno));
				return;
			}
			bytes_sent += 1000000;
			total_sent += 1000000;
	    }
		/* Don't start timing until we've sent a few bytes to warm
		 * everything up.
		 */
		// if ((start_bytes == 0) && (bytes_sent > 10000000)) {
		// 	start_bytes = bytes_sent;
		// 	start_cycles = rdtsc();
		// }
		elapsed = to_seconds(rdtsc() - start_cycles);
		rate = ((double) bytes_sent - start_bytes) / elapsed;
		printf("TCP throughput using %d byte buffers: %.2f Gb/sec\n",
			length, rate * 1e-09 * 8);	
        if(total_sent > 3000000000)
            break;
	}
}


/**
 * udp_tcpstream() - Measure throughput of a UDP socket using --length as
 * the size of the buffer for each write system call.
 * @server_name:  Name of the server machine.
 * @port:         Server port to connect to.
 */
void test_udpstream(char *server_name, int port)
{
	struct addrinfo hints;
	struct addrinfo *matching_addresses;
	struct sockaddr *dest;
	int status;
	int buffer[1000000];
	int64_t bytes_sent = 0;
	int64_t start_bytes = 0;
	uint64_t start_cycles = 0;
	double elapsed, rate;
	
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	status = getaddrinfo(server_name, "80", &hints, &matching_addresses);
	if (status != 0) {
		printf("Couldn't look up address for %s: %s\n",
				server_name, gai_strerror(status));
		return;
	}
	dest = matching_addresses->ai_addr;
	((struct sockaddr_in *) dest)->sin_port = htons(port);
	
	int fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		printf("Couldn't open client socket: %s\n", strerror(errno));
		return;
	}
	int gso_size = ETH_DATA_LEN - sizeof(struct iphdr) - sizeof(struct udphdr);
	if (setsockopt(fd, SOL_UDP, UDP_SEGMENT, &gso_size, sizeof(gso_size))) {
		return;
	}
	buffer[0] = -1;
	std::chrono::steady_clock::time_point start_clock = std::chrono::steady_clock::now();

	while (1) {
		start_bytes = bytes_sent = 0;
	    start_cycles = rdtsc();

		// if (bytes_sent > 1010000000)
		// 	break;
		if(std::chrono::steady_clock::now() - start_clock > std::chrono::seconds(60)) 
	            break;
	    for (int i = 0; i < count * 100; i++) {
	    	int result = sendto(fd, buffer, 64000, MSG_CONFIRM, dest, sizeof(struct sockaddr_in));			
			if( result < 0 ) {
				printf("Socket write failed: %s %d\n", strerror(errno), result);

				return;
			}
			bytes_sent += result;

	    }
		/* Don't start timing until we've sent a few bytes to warm
		 * everything up.
		 */
		// if ((start_bytes == 0) && (bytes_sent > 10000000)) {
		// 	start_bytes = bytes_sent;
		// 	start_cycles = rdtsc();
		// }
		elapsed = to_seconds(rdtsc() - start_cycles);
		rate = ((double) bytes_sent - start_bytes) / elapsed;
		printf("UDP throughput using %d byte buffers: %.2f Gb/sec\n",
			length, rate * 1e-09 * 8);	
	}
}

/**
 * udp_tcpstream() - Measure throughput of a UDP socket using --length as
 * the size of the buffer for each write system call.
 * @server_name:  Name of the server machine.
 * @port:         Server port to connect to.
 */
void test_ndstream(int fd, struct sockaddr *dest, char* buffer)
{
	// struct addrinfo hints;
	// struct addrinfo *matching_addresses;
	// struct sockaddr *dest;
	// int status;
	// int buffer[1000000];
	int64_t bytes_sent = 0;
	int64_t start_bytes = 0;
	uint64_t start_cycles = 0;
	double elapsed, rate;
	
	// memset(&hints, 0, sizeof(struct addrinfo));
	// hints.ai_family = AF_INET;
	// hints.ai_socktype = SOCK_DGRAM;
	// status = getaddrinfo(server_name, "80", &hints, &matching_addresses);
	// if (status != 0) {
	// 	printf("Couldn't look up address for %s: %s\n",
	// 			server_name, gai_strerror(status));
	// 	return;
	// }
	// dest = matching_addresses->ai_addr;
	// ((struct sockaddr_in *) dest)->sin_port = htons(port);
	
	// int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_VIRTUAL_SOCK);
	// if (fd == -1) {
	// 	printf("Couldn't open client socket: %s\n", strerror(errno));
	// 	return;
	// }
	// int gso_size = ETH_DATA_LEN - sizeof(struct iphdr) - sizeof(struct udphdr);
	// if (setsockopt(fd, SOL_UDP, UDP_SEGMENT, &gso_size, sizeof(gso_size))) {
	// 	return;
	// }
	buffer[0] = -1;
	std::chrono::steady_clock::time_point start_clock = std::chrono::steady_clock::now();

	while (1) {
		start_bytes = bytes_sent = 0;
	    start_cycles = rdtsc();

		// if (bytes_sent > 1010000000)
		// 	break;
		if(std::chrono::steady_clock::now() - start_clock > std::chrono::seconds(60)) 
	            break;

	    for (int i = 0; i < count * 100; i++) {
	    	int result = sendto(fd, buffer, 64000, MSG_CONFIRM, dest, sizeof(struct sockaddr_in));			
			if( result < 0 ) {
				printf("Socket write failed: %s %d\n", strerror(errno), result);

				return;
			}
			bytes_sent += result;

	    }
		/* Don't start timing until we've sent a few bytes to warm
		 * everything up.
		 */
		// if ((start_bytes == 0) && (bytes_sent > 10000000)) {
		// 	start_bytes = bytes_sent;
		// 	start_cycles = rdtsc();
		// }
		elapsed = to_seconds(rdtsc() - start_cycles);
		rate = ((double) bytes_sent - start_bytes) / elapsed;
		printf("ND throughput using %d byte buffers: %.2f Gb/sec\n",
			length, rate * 1e-09 * 8);	
	}
}

void test_ndping(int fd, struct sockaddr *dest, char* buffer)
{
	//struct sockaddr_in* in = (struct sockaddr_in*) dest;
	uint32_t buffer_size = 10000000;
	buffer_size = 256;
	// uint64_t flow_size = 10000000000000;
	int times = 180;
	uint64_t write_len = 0;
	uint64_t start_time = rdtsc();
	if (connect(fd, dest, sizeof(struct sockaddr_in)) == -1) {
		printf("Couldn't connect to dest %s\n", strerror(errno));
		exit(1);
	}
	printf("connect done\n");
	    // for (int i = 0; i < count * 100; i++) {
		while(1) {

	    	int result = write(fd, buffer, buffer_size);	
			uint64_t end = rdtsc();

			if( result < 0 ) {
				if(errno == EMSGSIZE) {
					// printf("Socket write failed: %s %d\n", strerror(errno), result);
					break;
				}
			} else {
				write_len += result;
			}
			if(to_seconds(end-start_time) > times)
				break;
		}
	// }
		printf("%" PRIu64 "\n", write_len);
		// printf("end\n");
		 //    result = write(fd, buffer, 10000);			
			// if( result < 0 ) {
			// 	printf("Socket write failed: %s %d\n", strerror(errno), result);

			// 	return;
			// }
			// bytes_sent += result;

	    // }
		/* Don't start timing until we've sent a few bytes to warm
		 * everything up.
		 */
		// if ((start_bytes == 0) && (bytes_sent > 10000000)) {
		// 	start_bytes = bytes_sent;
		// 	start_cycles = rdtsc();
		// }
	// 	elapsed = to_seconds(rdtsc() - start_cycles);
	// 	rate = ((double) bytes_sent - start_bytes) / elapsed;
	// 	printf("ND throughput using %d byte buffers: %.2f Gb/sec\n",
	// 		length, rate * 1e-09 * 8);	
	// }
}

/**
 * nd_pingping() - Handles messages arriving on a given socket.
 * @fd:           File descriptor for the socket over which messages
 *                will arrive.
 * @client_addr:  Information about the client (for messages).
 */
void test_ndpingpong(int fd, struct sockaddr *dest, char* buffer)
{
	// int flag = 1;
	int times = 90;
	// int cur_length = 0;
	// bool streaming = false;
	uint64_t count = 0;
	// uint64_t total_length = 0;
	uint64_t start_time;
	std::vector<double> latency;
	printf("reach here1\n");
	if (connect(fd, dest, sizeof(struct sockaddr_in)) == -1) {
		printf("Couldn't connect to dest %s\n", strerror(errno));
		exit(1);
	}
	start_time = rdtsc();
	while (1) {
		int copied = 0;
		int rpc_length = 4096;
		// times--;
		// if(times == 0)
		// 	break;
		uint64_t start = rdtsc(), end;
		while(1) {
			int result = write(fd, buffer + copied,
				rpc_length);
			if (result <= 0) {
				printf("goto close\n");
					goto close;
			}
			rpc_length -= result;
			copied += result;
			if(rpc_length == 0)
				break;
			// return;
		}
		copied = 0;
		rpc_length = 4096;
		while(1) {
			int result = read(fd, buffer + copied,
				rpc_length);
			if (result <= 0) {
					printf("goto close2\n");
					goto close;
			}
			// printf("result:%d\n",result);
			// printf("receive rpc times:%d \n", times);
			rpc_length -= result;
			copied += result;
			if(rpc_length == 0)
				break;
			// return;
		}
		end = rdtsc();
		latency.push_back(to_seconds(end-start));
		// printf("finsh time: %f cycles:%lu\n",  to_seconds(end-start), end-start);
		if(to_seconds(end-start_time) > times)
			break;
	//	if (total_length <= 8000000)
	//	 	printf("buffer:%s\n", buffer);
		count++;

	}
		// printf( "total len:%" PRIu64 "\n", total_length);
		// printf("done!");
close:
	sleep(10);

	for(uint32_t i = 0; i < latency.size(); i++) {
		std::cout << "finish time: " << latency[i] << "\n"; 
	}
	return;
}

/**
 * test_whileloop() - do nothing but a while loop
 */
void test_whileloop()
{
	// int flag = 1;
	int times = 1800;
	uint64_t start_time = rdtsc();;
	while (1) {
		uint64_t  end;
		end = rdtsc();
		if(to_seconds(end-start_time) > times)
			break;
	}

	return;
}

/**
 * tcp_ping() - Send a request on a TCP socket and wait for the
 * corresponding response.
 * @fd:       File descriptor corresponding to a TCP connection.
 * @request:  Buffer containing the request message.
 * @length:   Length of the request message.
 */
void tcp_ping(int fd, void *request, int length)
{
	char response[1000000];
	int response_length;
	int *int_response = reinterpret_cast<int*>(response);
	if (write(fd, request, length) != length) {
		printf("Socket write failed: %s\n", strerror(errno));
		exit(1);
	}
	response_length = 0;
	while (true) {
		int num_bytes = read(fd, response + response_length,
				sizeof(response) - response_length);
		if (num_bytes <= 0) {
			if (num_bytes == 0)
				printf("Server closed socket\n");
			else
				printf("Socket read failed: %s\n",
						strerror(errno));
			exit(1);
		}
		response_length += num_bytes;
		if (response_length == 1)
			continue;
		if (response_length < 2*sizeof32(int))
			continue;
		if (response_length < int_response[1])
			continue;
		if (response_length != int_response[1])
			printf("Expected %d bytes in response, got %d\n",
					int_response[1], response_length);
		if (response_length >= sizeof32(response)) {
			printf("Overflowed receive buffer: response_length %d,"
					"buffer[0] %d\n", response_length,
					int_response[0]);
		}
		break;
	}
}

/**
 * test_tcp() - Measure round-trip time for an RPC sent via a TCP socket.
 * @server_name:  Name of the server machine.
 * @port:         Server port to connect to.
 */
void test_tcp(char *server_name, int port)
{
	struct addrinfo hints;
	struct addrinfo *matching_addresses;
	struct sockaddr *dest;
	int status, i;
	int buffer[250000];
	
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	status = getaddrinfo(server_name, "80", &hints, &matching_addresses);
	if (status != 0) {
		printf("Couldn't look up address for %s: %s\n",
				server_name, gai_strerror(status));
		exit(1);
	}
	dest = matching_addresses->ai_addr;
	((struct sockaddr_in *) dest)->sin_port = htons(port);
	
	int stream = socket(PF_INET, SOCK_STREAM, 0);
	if (stream == -1) {
		printf("Couldn't open client socket: %s\n", strerror(errno));
		exit(1);
	}
	if (connect(stream, dest, sizeof(struct sockaddr_in)) == -1) {
		printf("Couldn't connect to %s:%d: %s\n", server_name, port,
				strerror(errno));
		exit(1);
	}
	int flag = 1;
	setsockopt(stream, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	
	/* Warm up. */
	buffer[0] = length;
	buffer[1] = length;
	seed_buffer(&buffer[2], sizeof32(buffer) - 2*sizeof32(int), seed);
	for (i = 0; i < 10; i++)
		tcp_ping(stream, buffer, length);

    std::chrono::steady_clock::time_point start_clock = std::chrono::steady_clock::now();

	while(1) {
		if(std::chrono::steady_clock::now() - start_clock > std::chrono::seconds(60)) 
	        break;
		uint64_t times[count+1];
		for (i = 0; i < count; i++) {
			times[i] = rdtsc();
			tcp_ping(stream, buffer, length);
		}
		times[count] = rdtsc();
		
		for (i = 0; i < count; i++) {
			times[i] = times[i+1] - times[i];
		}
		print_dist(times, count);
		printf("Bandwidth at median: %.1f MB/sec\n",
				2.0*((double) length)/(to_seconds(times[count/2])*1e06));
	}

	return;
}


/**
 * test_udpclose() - Close a UDP socket while a thread is waiting on it.
 */
void test_udpclose()
{
	/* Test what happens if a UDP socket is closed while a
	 * thread is waiting on it. */
	struct sockaddr_in address;
	char buffer[1000];

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		printf("Couldn't open UDP socket: %s\n",
			strerror(errno));
		exit(1);
	}
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_ANY);
	address.sin_port = 0;
	int result = bind(fd,
		reinterpret_cast<struct sockaddr*>(&address),
		sizeof(address));
	if (result < 0) {
		printf("Couldn't bind UDP socket: %s\n",
			strerror(errno));
		exit(1);
	}
	std::thread thread(close_fd, fd);
	thread.detach();
	result = read(fd, buffer, sizeof(buffer));
	if (result >= 0) {
		printf("UDP read returned %d bytes\n", result);
	} else {
		printf("UDP read returned error: %s\n",
			strerror(errno));
	}
}

int main(int argc, char** argv)
{
	int port, nextArg, tempArg, optval;
	unsigned optlen;
	struct sockaddr_in addr_in;
	struct addrinfo *matching_addresses;
	struct sockaddr *dest;
	struct addrinfo hints;
	char *host, *port_name;
	// char buffer[8000000] = "abcdefgh\n";
	char *buffer = (char*)malloc(10000000);
	// buffer[63999] = 'H';
	int status;
	int fd;
	int i;
	int srcPort = 0;
	if ((argc >= 2) && (strcmp(argv[1], "--help") == 0)) {
		print_help(argv[0]);
		exit(0);
	}
	for (i = 0; i < 8000000; i++)
		buffer[i] = (rand()) % 26 + 'a';
//	printf("buffer:%s\n", buffer);
	if (argc < 3) {
		printf("Usage: %s host:port [options] op op ...\n", argv[0]);
		exit(1);
	}
	host = argv[1];
	port_name = strchr(argv[1], ':');
	if (port_name == NULL) {
		printf("Bad server spec %s: must be 'host:port'\n", argv[1]);
		exit(1);
	}
	*port_name = 0;
	port_name++;
	port = get_int(port_name,
			"Bad port number %s; must be positive integer\n");
	for (nextArg = 2; (nextArg < argc) && (*argv[nextArg] == '-');
			nextArg += 1) {
		if (strcmp(argv[nextArg], "--help") == 0) {
			print_help(argv[0]);
			exit(0);
		} else if (strcmp(argv[nextArg], "--count") == 0) {
			if (nextArg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[nextArg]);
				exit(1);
			}
			nextArg++;
			count = get_int(argv[nextArg],
					"Bad count %s; must be positive integer\n");
		} else if (strcmp(argv[nextArg], "--length") == 0) {
			if (nextArg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[nextArg]);
				exit(1);
			}
			nextArg++;
			length = get_int(argv[nextArg],
				"Bad message length %s; must be positive "
				"integer\n");
			if (length > 1000000) {
				length = 1000000;
				printf("Reducing message length to %d\n", length);
			}
		} else if (strcmp(argv[nextArg], "--sp") == 0) {
			if (nextArg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[nextArg]);
				exit(1);
			}
			nextArg++;
			srcPort = get_int(argv[nextArg],
				"Bad srcPort %s; must be positive integer\n");
		} else {
			printf("Unknown option %s; type '%s --help' for help\n",
				argv[nextArg], argv[0]);
			exit(1);
		}
	}
	// get destination address
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	status = getaddrinfo(host, "80", &hints, &matching_addresses);
	if (status != 0) {
		printf("Couldn't look up address for %s: %s\n",
				host, gai_strerror(status));
		exit(1);
	}
	dest = matching_addresses->ai_addr;
	((struct sockaddr_in *) dest)->sin_port = htons(port);
	// int *ibuf = reinterpret_cast<int *>(buffer);
	// ibuf[0] = ibuf[1] = length;
	// seed_buffer(&ibuf[2], sizeof32(buffer) - 2*sizeof32(int), seed);
	tempArg = nextArg;
	for(i = 0; i < count; i++) {
		nextArg = tempArg;

		printf("nextArg:%d\n", nextArg);
		fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_VIRTUAL_SOCK);
		// fd = socket(AF_INET, SOCK_STREAM, 0);

		if (fd < 0) {
			printf("Couldn't open ND socket: %s\n", strerror(errno));
		}
		// int option = 1;
		// if (setsockopt(fd, SOL_VIRTUAL_SOCK, SO_NO_CHECK, (void*)&option, sizeof(option))) {
		// 	return -1;
		// }
		memset(&addr_in, 0, sizeof(addr_in));
		addr_in.sin_family = AF_INET;
		addr_in.sin_port = htons(srcPort + i);
		addr_in.sin_addr.s_addr = inet_addr("192.168.10.116");


		if (bind(fd, (struct sockaddr *) &addr_in, sizeof(addr_in)) != 0) {
			printf("Couldn't bind socket to ND port %d: %s\n", port,
					strerror(errno));
			return -1;
		}

		for ( ; nextArg < argc; nextArg++) {
			// if (strcmp(argv[nextArg], "close") == 0) {
			// 	test_close();
			// } else if (strcmp(argv[nextArg], "fill_memory") == 0) {
			// 	test_fill_memory(fd, dest, buffer);
			// } else if (strcmp(argv[nextArg], "invoke") == 0) {
			// 	test_invoke(fd, dest, buffer);
			// } else if (strcmp(argv[nextArg], "ioctl") == 0) {
			// 	test_ioctl(fd, count);
			// } else if (strcmp(argv[nextArg], "poll") == 0) {
			// 	test_poll(fd, buffer);
			// } else if (strcmp(argv[nextArg], "send") == 0) {
			// 	test_send(fd, dest, buffer);
			// } else if (strcmp(argv[nextArg], "read") == 0) {
			// 	test_read(fd, count);
			// } else if (strcmp(argv[nextArg], "rtt") == 0) {
			// 	test_rtt(fd, dest, buffer);
			// } else if (strcmp(argv[nextArg], "shutdown") == 0) {
			// 	test_shutdown(fd);
			// } else if (strcmp(argv[nextArg], "stream") == 0) {
			// 	test_stream(fd, dest, buffer);
			// } else 
			if (strcmp(argv[nextArg], "tcp") == 0) {
				test_tcp(host, port);
			} else if (strcmp(argv[nextArg], "tcpstream") == 0) {
				test_tcpstream(host, port);
			} else if (strcmp(argv[nextArg], "udpclose") == 0) {
				test_udpclose();
			} else if (strcmp(argv[nextArg], "udpstream") == 0) {
				test_udpstream(host, port);
			} else if (strcmp(argv[nextArg], "ndstream") == 0) {
				test_ndstream(fd, dest, buffer);
			} else if (strcmp(argv[nextArg], "ndping") == 0) {
				printf("call ndping\n");
				test_ndping(fd, dest, buffer);
			} else if (strcmp(argv[nextArg], "tcpping") == 0) {
				fd = socket(AF_INET, SOCK_STREAM, 0);
				printf("call tcpping\n");
				test_ndping(fd, dest, buffer);
			} else if (strcmp(argv[nextArg], "ndpingpong") == 0) {
				printf("call ndpingpong\n");
				optval = 6;
                setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &optval, unsigned(sizeof(optval)));
				test_ndpingpong(fd, dest, buffer);
			} else if (strcmp(argv[nextArg], "whileloop") == 0) {
				printf("call whileloop\n");
				test_whileloop();
			}  else if (strcmp(argv[nextArg], "tcppingpong") == 0) {
				fd = socket(AF_INET, SOCK_STREAM, 0);
				optval = 7;
				setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &optval, unsigned(sizeof(optval)));  
				getsockopt(fd, SOL_SOCKET, SO_PRIORITY, &optval, &optlen);
				printf("optval:%d\n", optval);
				test_ndpingpong(fd, dest, buffer);
			} else if (strcmp(argv[nextArg], "sendfile") == 0) {
				fd = socket(AF_INET, SOCK_STREAM, 0);
				send_file("debug", fd, dest);
			}
			 else {
				printf("Unknown operation '%s'\n", argv[nextArg]);
				exit(1);
			}
		}
		close(fd);
		printf("i:%d\n", i);
	}
	free(buffer);
	exit(0);
}

