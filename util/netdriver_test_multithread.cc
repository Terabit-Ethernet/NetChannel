#include <cassert>
#include <ctime>
#include<chrono>
#include <errno.h>
#include <iostream>
#include <fstream>
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
#include <queue>
#include <thread>
#include <mutex>          // std::mutex
#include <condition_variable> // std::condition_variable

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

void test_ndping(int fd, struct sockaddr *dest)
{
	//struct sockaddr_in* in = (struct sockaddr_in*) dest;
	uint32_t buffer_size = 10000000;
	char *buffer = (char*)malloc(10000000);
	// uint64_t flow_size = 10000000000000;
	int times = 180;
	int i;
	for (i = 0; i < 8000000; i++)
		buffer[i] = (rand()) % 26 + 'a';
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

std::queue<uint64_t> time_q;
std::mutex mtx;           // mutex for critical section
std::condition_variable cv;
int limit = 1024;
bool queue_available() {return time_q.size() < (long unsigned int)limit;}


void test_ndping_send(int fd, struct sockaddr *dest)
{
	//struct sockaddr_in* in = (struct sockaddr_in*) dest;
	// uint32_t buffer_size = 10000000;
	char *buffer = (char*)malloc(1000000);
	// uint64_t flow_size = 10000000000000;
	int times = 60;
	int flag = 0;
	// int i;
	// for (i = 0; i < 8000000; i++)
	// 	buffer[i] = (rand()) % 26 + 'a';
	uint64_t write_len = 0;
	uint64_t start_time = rdtsc();
	int q_depth = 64, count = 0;
	    // for (int i = 0; i < count * 100; i++) {
		while(1) {

	    	int total = 0;
			std::unique_lock<std::mutex> lck(mtx);
			cv.wait(lck, queue_available);
			uint64_t end = rdtsc();
			// flag = (q_depth == count + 1)? MSG_EOR : MSG_EOR;
			count = (count + 1) % q_depth;
			// flag = (limit - time_q.size() == 1)? MSG_EOR: MSG_EOR;
			flag = MSG_EOR;
			while(total < 4096) {
				int result = send(fd, buffer, 4096 - total, flag);	
				if( result < 0 ) {
					if(errno == EMSGSIZE) {
						printf("Socket write failed: %s %d\n", strerror(errno), result);
						break;
					}
				} else {
					write_len += result;
					total += result;
				}
			}
			// time_q.push(end);
			if(to_seconds(end-start_time) > times)
				break;
		
		}
		printf("Throughput: %" PRIu64 " Gbps\n", write_len * 8 / times / 1000000000);
	close(fd);
	return;
}

void test_ndping_recv(int fd, struct sockaddr *dest, int id)
{
	//struct sockaddr_in* in = (struct sockaddr_in*) dest;
	uint32_t buffer_size = 1000000;
	char *buffer = (char*)malloc(1000000);
	std::vector<double> latency;
	std::ofstream file;
	// printf("call recv\n");
	file.open("result_tcp_pingpongasync_" + std::to_string(id));
	// printf("finish initilize file\n");
	// uint64_t flow_size = 10000000000000;
	int times = 70;
	// int i;
	// for (i = 0; i < 8000000; i++)
	// 	buffer[i] = (rand()) % 26 + 'a';
	uint64_t write_len = 0;
	uint64_t start_time = rdtsc();
	    // for (int i = 0; i < count * 100; i++) {
	uint64_t remain = 0;
	while(1) {
		int result = read(fd, buffer, buffer_size);
		if( result < 0 ) {
			if(errno == EMSGSIZE) {
				// printf("Socket write failed: %s %d\n", strerror(errno), result);
				break;
			}
		} else {
			write_len += result;
			remain += result;
		}
		while(remain >= 1024) {
			std::unique_lock<std::mutex> lck(mtx);
			uint64_t end = rdtsc();
			uint64_t start = time_q.front();
			if(time_q.empty())
				assert(false);	
			latency.push_back(to_seconds(end - start));
			time_q.pop();
			remain -= 1024;
			cv.notify_one();
		}
		uint64_t end = rdtsc();
		if(to_seconds(end-start_time) > times)
			break;
	}
	printf("finish\n");
	for(uint32_t i = 0; i < latency.size(); i++) {
		file << "finish time: " << latency[i] << "\n"; 
		// std::cout << "finish time: " << latency[i] << "\n"; 
	}
	file.close();

}
/**
 * tcp_pingping() - Handles messages arriving on a given socket.
 * @fd:           File descriptor for the socket over which messages
 *                will arrive.
 * @client_addr:  Information about the client (for messages).
 */
void test_tcppingpong(int fd, struct sockaddr *dest, int id)
{
	// int flag = 1;
	int times = 90;
	char buffer[5000];
	std::ofstream file;
	file.open("result_tcp_pingpong_"+ std::to_string(id));
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
		file << "finish time: " << latency[i] << "\n"; 
		// std::cout << "finish time: " << latency[i] << "\n"; 
	}
	file.close();
	close(fd);
	return;
}

/**
 * nd_pingping() - Handles messages arriving on a given socket.
 * @fd:           File descriptor for the socket over which messages
 *                will arrive.
 * @client_addr:  Information about the client (for messages).
 */
void test_ndpingpong(int fd, struct sockaddr *dest, int id)
{
	// int flag = 1;
	int times = 90;
	// int cur_length = 0;
	// bool streaming = false;
	uint64_t count = 0;
	// uint64_t total_length = 0;
	char buffer[5000];
	std::ofstream file;
	file.open("result_nd_pingpong_"+ std::to_string(id));
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
		file << "finish time: " << latency[i] << "\n"; 
		// std::cout << "finish time: " << latency[i] << "\n"; 
	}
	file.close();
	close(fd);
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
 	std::vector<std::thread> workers;
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
		} else if (strcmp(argv[nextArg], "--limit") == 0) {
			if (nextArg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[nextArg]);
				exit(1);
			}
			nextArg++;
			limit = get_int(argv[nextArg],
				"Bad limit %s; must be positive integer\n");
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
				workers.push_back(std::thread(test_ndping, fd, dest));
			} else if (strcmp(argv[nextArg], "tcpping") == 0) {
				fd = socket(AF_INET, SOCK_STREAM, 0);
				workers.push_back(std::thread(test_ndping, fd, dest));
			} else if (strcmp(argv[nextArg], "tcpppasync") == 0) {
				fd = socket(AF_INET, SOCK_STREAM, 0);
				std::cout << "limit " <<limit << std::endl;

				if (connect(fd, dest, sizeof(struct sockaddr_in)) == -1) {
					printf("Couldn't connect to dest %s\n", strerror(errno));
					exit(1);
				}
				printf("reach here tcp async\n");
				workers.push_back(std::thread(test_ndping_send, fd, dest));
				// workers.push_back(std::thread(test_ndping_recv, fd, dest, srcPort - 10000));
			} else if (strcmp(argv[nextArg], "ndppasync") == 0) {
				std::cout << "limit " <<limit << std::endl;

				if (connect(fd, dest, sizeof(struct sockaddr_in)) == -1) {
					printf("Couldn't connect to dest %s\n", strerror(errno));
					exit(1);
				}
				printf("reach here\n");
				workers.push_back(std::thread(test_ndping_send, fd, dest));
				// workers.push_back(std::thread(test_ndping_recv, fd, dest, srcPort - 10000));
			} else if (strcmp(argv[nextArg], "ndpingpong") == 0) {
				printf("call ndpingpong\n");
				optval = 6;
				setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &optval, unsigned(sizeof(optval)));  
				// cpu_set_t cpuset;
				// CPU_ZERO(&cpuset);
				workers.push_back(std::thread(test_ndpingpong, fd, dest, i));
				// CPU_SET(i % 2  * 4, &cpuset);
				// pthread_setaffinity_np(workers[workers.size() - 1].native_handle(),
				// 								sizeof(cpu_set_t), &cpuset);
			} else if (strcmp(argv[nextArg], "tcppingpong") == 0) {
				fd = socket(AF_INET, SOCK_STREAM, 0);
				optval = 6;
				setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &optval, unsigned(sizeof(optval)));  
				getsockopt(fd, SOL_SOCKET, SO_PRIORITY, &optval, &optlen);
				printf("optval:%d\n", optval);
				workers.push_back(std::thread(test_tcppingpong, fd, dest, i));
			} 
			 else {
				printf("Unknown operation '%s'\n", argv[nextArg]);
				exit(1);
			}
		}
	}
//       std::this_thread::sleep_for (std::chrono::seconds(100));

	for(unsigned i = 0; i < workers.size(); i++) {
		workers[i].join();
	}
	free(buffer);
	exit(0);
}

