 #include <arpa/inet.h>
#include <atomic>
#include <chrono>         // std::chrono::seconds

#include <iostream>

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <thread>
#include <vector>
#include "test_utils.h"
#include <sys/resource.h>
#include <mutex>          // std::mutex
#include <condition_variable> // std::condition_variable
//#include "../uapi_linux_nd.h"
/* Log events to standard output. */
bool verbose = false;

int port = 4000;

/* True that a specific format is expected for incoming messages, and we
 * should check that incoming messages conform to it.
 */
bool validate = false;

void nd_pingpong_async(int fd, struct sockaddr_in source);

struct Agg_Stats {
	std::atomic<unsigned long> total_bytes;
	std::atomic<unsigned long> interval_bytes;
	uint64_t start_cycle;
	int interval_sec;
};

struct Agg_Stats agg_stats;
void init_agg_stats(struct Agg_Stats* stats, int interval_sec) {
	atomic_store(&stats->total_bytes, (unsigned long)0);
	atomic_store(&stats->interval_bytes, (unsigned long)0);
	stats->start_cycle = rdtsc();
	stats->interval_sec = interval_sec;
}

void aggre_thread(struct Agg_Stats *stats) {
	int time = 0;
	init_agg_stats(stats, 1);
	while(1) {
		uint64_t start_cycle = rdtsc();
		uint64_t end_cycle;
		double rate;
		double bytes;
    	std::this_thread::sleep_for (std::chrono::seconds(stats->interval_sec));
    	end_cycle = rdtsc();
    	bytes = atomic_load(&stats->interval_bytes);
    	rate = (bytes)/ to_seconds(end_cycle - start_cycle);
	printf("[%d] Throughput: " "%.2f Gbps  bytes: %f time: %f\n", time, rate * 1e-09 * 8, (double) bytes, to_seconds(
		end_cycle - start_cycle));
    	atomic_store(&stats->interval_bytes, (unsigned long)0);
	time += 1;
	}
}

/**
 * nd_pingpong() - Handles messages arriving on a given socket.
 * @fd:           File descriptor for the socket over which messages
 *                will arrive.
 * @client_addr:  Information about the client (for messages).
 */
void nd_pingpong(int fd, struct sockaddr_in source)
{
	// int flag = 1;
	int optval = 7;
	unsigned optlen = 0;
	char *buffer = (char*)malloc(2359104);
	// int times = 10000;
	// int cur_length = 0;
	// bool streaming = false;
	uint64_t count = 0;
	uint64_t total_length = 0;
	// uint64_t start_cycle = 0, end_cycle = 0;
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	int which = PRIO_PROCESS;
	id_t pid;
	int ret;
	printf("reach here\n");
	pid = getpid();
	//ret = setpriority(which, pid, -20);
	//std::cout << "ret "<< ret << std::endl;
	ret = getpriority(which, pid);
	std::cout << "priority " << ret << std::endl;
	// int *int_buffer = reinterpret_cast<int*>(buffer);
	if (verbose)
		printf("New ND socket from %s\n", print_address(&source));
	// setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	if (getsockname(fd, (struct sockaddr *)&sin, &len) == -1)
	    perror("getsockname");
	else
	    printf("port number %d\n", ntohs(sin.sin_port));
	// start_cycle = rdtsc();
	printf("start connection\n");
	setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &optval, unsigned(sizeof(optval)));   
	getsockopt(fd, SOL_SOCKET, SO_PRIORITY, &optval, &optlen);
	printf("optval:%d\n", optval);

	// printf("sizeof buffer:%ld\n", sizeof(buffer));
	while (1) {
		int copied = 0;
		int rpc_length = 4096;
		// times--;
		while(1) {
			int result = read(fd, buffer + copied,
				rpc_length);
			if (result <= 0) {
					goto close;
			}
			rpc_length -= result;
			copied += result;
			// total_length += result;

			if(rpc_length == 0)
				break;
			// return;
		}
		copied = 0;
		rpc_length = 4096;
		// if(times == -1)
		// 	break;
		while(1) {
			int result = write(fd, buffer + copied,
				rpc_length);
			if (result <= 0) {
					goto close;
			}
			rpc_length -= result;
			copied += result;
			// total_length += result;
			// printf("send rpc\n");
			if(rpc_length == 0)
				break;
			// return;
		}
	//	if (total_length <= 8000000)
	//	 	printf("buffer:%s\n", buffer);
		count++;
		// if (result == 0)
		// 	break;
		// std::atomic_fetch_add(&agg_stats.interval_bytes, (unsigned long)result);
		// std::atomic_fetch_add(&agg_stats.total_bytes, (unsigned long)result);
	}
		printf( "total len:%" PRIu64 "\n", total_length);
		printf("done!");
	if (verbose)
		printf("Closing TCP socket from %s\n", print_address(&source));
close:
	close(fd);
	free(buffer);
}

/**
 * print_help() - Print out usage information for this program.
 * @name:   Name of the program (argv[0])
 */
void print_help(const char *name)
{
	printf("Usage: %s [options]\n\n"
		"The following options are supported:\n\n"
		"--help       Print this message and exit\n"
		"--port       (First) port number to use (default: 4000)\n"
		"--num_ports  Number of ports to open (default: 1)\n"
		"--validate   Validate contents of incoming messages (default: false\n"
		"--verbose    Log events as they happen (default: false)\n",
		name);
}

/**
 * tcp_connection() - Handles messages arriving on a given socket.
 * @fd:           File descriptor for the socket over which messages
 *                will arrive.
 * @client_addr:  Information about the client (for messages).
 */
void tcp_connection(int fd, struct sockaddr_in source)
{
	int flag = 1;
	char buffer[1000000];
	int cur_length = 0;
	bool streaming = false;
	uint64_t count = 0;
	uint64_t total_length = 0;
	uint64_t start_cycle = 0, end_cycle = 0;
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	int *int_buffer = reinterpret_cast<int*>(buffer);
	if (verbose)
		printf("New TCP socket from %s\n", print_address(&source));
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	if (getsockname(fd, (struct sockaddr *)&sin, &len) == -1)
	    perror("getsockname");
	else
	    printf("port number %d\n", ntohs(sin.sin_port));
	start_cycle = rdtsc();
	while (1) {
		int result = read(fd, buffer + cur_length,
				sizeof(buffer) - cur_length);
		if (result < 0) {
			if (errno == ECONNRESET)
				break;
			printf("Read error on socket: %s", strerror(errno));
			exit(1);
		}
		total_length += result;
		count++;
		if (result == 0)
			break;
		if(count % 1000 == 0) {
			end_cycle = rdtsc();
			
			double rate = ((double) total_length)/ to_seconds(
				end_cycle - start_cycle);
			total_length = 0;

			start_cycle = rdtsc();
			if(count != 0) {
				printf("TCP throughput: "
				"%.2f Gbps\n", rate * 1e-09 * 8);
			}
		}
		/* The connection can be used in two modes. If the first
		 * word received is -1, then the connection is in streaming
		 * mode: we just read bytes and throw them away. If the
		 * first word isn't -1, then it's in message mode: we read
		 * full messages and respond to them.
		 */
		if (streaming)
			continue;
		if (int_buffer[0] < 0) {
			streaming = true;
			continue;
		}
		cur_length += result;

		/* First word of request contains expected length in bytes. */
		if ((cur_length >= 2*sizeof32(int))
				&& (cur_length >= int_buffer[0])) {
			if (cur_length != int_buffer[0])
				printf("Received %d bytes but buffer[0] = %d, "
					"buffer[1] = %d\n",
					cur_length, int_buffer[0],
					int_buffer[1]);
			if (validate) {
				int seed = check_buffer(&int_buffer[2],
					int_buffer[0] - 2*sizeof32(int));
				if (verbose)
					printf("Received message from %s with "
						"%d bytes, seed %d\n",
						print_address(&source),
						int_buffer[0], seed);
			} else if (verbose)
				printf("Received message from %s with %d "
					"bytes\n",
					print_address(&source), int_buffer[0]);
			cur_length = 0;
			if (int_buffer[1] <= 0)
				continue;
			if (write(fd, buffer, int_buffer[1]) != int_buffer[1]) {
				printf("Socket write failed: %s\n",
						strerror(errno));
				exit(1);
			};
		}
	}
	if (verbose)
		printf("Closing TCP socket from %s\n", print_address(&source));
	close(fd);
}

/**
 * tcp_server() - Opens a TCP socket, accepts connections on that socket
 * (one thread per connection) and processes messages on those connections.
 * @port:  Port number on which to listen.
 */
void tcp_server(int port)
{
	int listen_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (listen_fd == -1) {
		printf("Couldn't open server socket: %s\n", strerror(errno));
		exit(1);
	}
	int option_value = 1;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &option_value,
			sizeof(option_value)) != 0) {
		printf("Couldn't set SO_REUSEADDR on listen socket: %s",
			strerror(errno));
		exit(1);
	}
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(listen_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr))
			== -1) {
		printf("Couldn't bind to port %d: %s\n", port, strerror(errno));
		exit(1);
	}
	while (1) {
		struct sockaddr_in client_addr;
		socklen_t addr_len = sizeof(client_addr);
		if (listen(listen_fd, 1000) == -1) {
			printf("Couldn't listen on socket: %s", strerror(errno));
			exit(1);
		}
		int stream = accept(listen_fd,
				reinterpret_cast<sockaddr *>(&client_addr),
				&addr_len);
		if (stream < 0) {
			printf("Couldn't accept incoming connection: %s",
				strerror(errno));
			exit(1);
		}
		std::thread thread(nd_pingpong_async,stream, client_addr);
		thread.detach();
	}
}

/**
 * nd_connection() - Handles messages arriving on a given socket.
 * @fd:           File descriptor for the socket over which messages
 *                will arrive.
 * @client_addr:  Information about the client (for messages).
 */
void nd_connection(int fd, struct sockaddr_in source)
{
	// int flag = 1;
	char *buffer = (char*)malloc(2359104);
	// int cur_length = 0;
	// bool streaming = false;
	uint64_t count = 0;
	uint64_t total_length = 0;
	// uint64_t start_cycle = 0, end_cycle = 0;
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	// int *int_buffer = reinterpret_cast<int*>(buffer);
	if (verbose)
		printf("New ND socket from %s\n", print_address(&source));
	// setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	if (getsockname(fd, (struct sockaddr *)&sin, &len) == -1)
	    perror("getsockname");
	else
	    printf("port number %d\n", ntohs(sin.sin_port));
	// start_cycle = rdtsc();
	printf("start connection\n");
	// printf("sizeof buffer:%ld\n", sizeof(buffer));
	while (1) {
		int result = read(fd, buffer,
				2359104);
		// setbuf(stdout, NULL);
		// printf("result:%d\n", result);
		
		// printf("'%.*s'\n", result, buffer);
		// fflush(stdout);
		// while(1) {
					
		// }
		if (result < 0) {
			// if (errno == ECONNRESET)
				break;
		
			// return;
		}
	//	if (total_length <= 8000000)
	//	 	printf("buffer:%s\n", buffer);
		total_length += result;
		count++;
		if (result == 0)
			break;
		std::atomic_fetch_add(&agg_stats.interval_bytes, (unsigned long)result);
		std::atomic_fetch_add(&agg_stats.total_bytes, (unsigned long)result);

		// if(count % 1000 == 0) {
		// 	end_cycle = rdtsc();
		// 	printf("count:%lu\n", count);
		// 	double rate = ((double) total_length)/ to_seconds(
		// 		end_cycle - start_cycle);
		// 	// if(count != 0) {
		// 	// 	printf("ND throughput: "
		// 	// 	"%.2f Gbps, bytes: %f, time: %f\n", rate * 1e-09 * 8, (double) total_length, to_seconds(
		// 	// 	end_cycle - start_cycle));
		// 	// }
		// 	total_length = 0;

		// 	start_cycle = rdtsc();
		// }
		// /* The connection can be used in two modes. If the first
		//  * word received is -1, then the connection is in streaming
		//  * mode: we just read bytes and throw them away. If the
		//  * first word isn't -1, then it's in message mode: we read
		//  * full messages and respond to them.
		//  */
		// if (streaming)
		// 	continue;
		// if (int_buffer[0] < 0) {
		// 	streaming = true;
		// 	continue;
		// }
		// cur_length += result;

		// /* First word of request contains expected length in bytes. */
		// if ((cur_length >= 2*sizeof32(int))
		// 		&& (cur_length >= int_buffer[0])) {
		// 	if (cur_length != int_buffer[0])
		// 		printf("Received %d bytes but buffer[0] = %d, "
		// 			"buffer[1] = %d\n",
		// 			cur_length, int_buffer[0],
		// 			int_buffer[1]);
		// 	if (validate) {
		// 		int seed = check_buffer(&int_buffer[2],
		// 			int_buffer[0] - 2*sizeof32(int));
		// 		if (verbose)
		// 			printf("Received message from %s with "
		// 				"%d bytes, seed %d\n",
		// 				print_address(&source),
		// 				int_buffer[0], seed);
		// 	} else if (verbose)
		// 		printf("Received message from %s with %d "
		// 			"bytes\n",
		// 			print_address(&source), int_buffer[0]);
		// 	cur_length = 0;
		// 	if (int_buffer[1] <= 0)
		// 		continue;
		// 	if (write(fd, buffer, int_buffer[1]) != int_buffer[1]) {
		// 		printf("Socket write failed: %s\n",
		// 				strerror(errno));
		// 		exit(1);
		// 	};
		// }
	}
		printf( "total len:%" PRIu64 "\n", total_length);
		printf("done!");
	if (verbose)
		printf("Closing TCP socket from %s\n", print_address(&source));
	close(fd);
	free(buffer);
}

/**
 * udp_server()
 *
 */
void udp_server(int port)
{
	char buffer[1000000];
	int result = 0;
	uint64_t start_cycle = 0, end_cycle = 0;
	uint64_t total_length = 0;
	int count = 0;

	int listen_fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (listen_fd == -1) {
		printf("Couldn't open server socket: %s\n", strerror(errno));
		exit(1);
	}
	int option_value = 1;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &option_value,
			sizeof(option_value)) != 0) {
		printf("Couldn't set SO_REUSEADDR on listen socket: %s",
			strerror(errno));
		exit(1);
	}
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(listen_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr))
			== -1) {
		printf("Couldn't bind to port %d: %s\n", port, strerror(errno));
		exit(1);
	}
	// struct timeval tv;
	// tv.tv_usec = 100 * 1000;
	// if (setsockopt(listen_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
	// 	return;
	while (1) {
		struct sockaddr_in client_addr;
		socklen_t addr_len = sizeof(client_addr);

		result = recvfrom(listen_fd, (char *)buffer, sizeof(buffer),  
                MSG_WAITALL, ( struct sockaddr *) &client_addr, 
                &addr_len);
		printf("%s\n", buffer);
		printf("%c\n", buffer[10000]);
		if (result < 0) {
			if (errno == ECONNRESET)
				break;
			printf("Read error on socket: %s", strerror(errno));
			exit(1);
		}
		if (result == 0)
			break;
		if(count % 50000 == 0) {
			end_cycle = rdtsc();
			
			double rate = ((double) total_length)/ to_seconds(
				end_cycle - start_cycle);
			total_length = 0;

			start_cycle = rdtsc();
			if(count != 0) {
				printf("UDP throughput: "
				"%.2f Gbps\n", rate * 1e-09 * 8);
			}
		}
		total_length += result;
		count += 1;
	}

}

std::mutex mtx;           // mutex for critical section
std::condition_variable cv;
unsigned long pending_req = 0;
bool req_available() {return pending_req >= 1024;}

void nd_pingpong_read(int fd) {
	char *buffer = (char*)malloc(2359104);
	while(1) {
		int result = read(fd, buffer, 2359104);
		if (result <= 0) {
				goto close;
		}
		std::unique_lock<std::mutex> lck(mtx);
		pending_req += result;
		std::atomic_fetch_add(&agg_stats.interval_bytes, (unsigned long)result);
		// cv.notify_one();
	}
close:
	free(buffer);
}

void nd_pingpong_write(int fd) {
	char *buffer = (char*)malloc(2359104);
	while(1) {
		std::unique_lock<std::mutex> lck(mtx);
		cv.wait(lck, req_available);
		int result = write(fd, buffer, 1024);
		if (result <= 0) {
			goto close;
		}
		pending_req -= result;
	}
close:
	free(buffer);
	close(fd);
}

void nd_pingpong_async(int fd, struct sockaddr_in source) {
	// int flag = 1;
	int optval = 0;
	unsigned optlen = 0;
	// int times = 10000;
	// int cur_length = 0;
	// bool streaming = false;
	// uint64_t start_cycle = 0, end_cycle = 0;
	// struct sockaddr_in sin;
	// int *int_buffer = reinterpret_cast<int*>(buffer);
	// start_cycle = rdtsc();
	setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &optval, unsigned(sizeof(optval)));   
	getsockopt(fd, SOL_SOCKET, SO_PRIORITY, &optval, &optlen);
	std::thread thread(nd_pingpong_read, fd);
	thread.detach();
	// std::thread thread2(nd_pingpong_write, fd);
	// thread2.detach();
}
/**
 * nd_server()
 *
 */
void nd_server(int port)
{
	// char buffer[1000000];
	// int result = 0;
	// uint64_t start_cycle = 0, end_cycle = 0;
	// uint64_t total_length = 0;
	// int count = 0;
	int i = 0;
	int listen_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_VIRTUAL_SOCK);
	// int listen_fd = socket(PF_INET, SOCK_STREAM, 0);

	if (listen_fd == -1) {
		printf("Couldn't open server socket: %s\n", strerror(errno));
		exit(1);
	}
	int option_value = 1;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR | SO_NO_CHECK, &option_value,
			sizeof(option_value)) != 0) {
		printf("Couldn't set SO_REUSEADDR on listen socket: %s",
			strerror(errno));
		exit(1);
	}
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(listen_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr))
			== -1) {
		printf("Couldn't bind to port %d: %s\n", port, strerror(errno));
		exit(1);
	}
	// struct timeval tv;
	// tv.tv_usec = 100 * 1000;
	// if (setsockopt(listen_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
	// 	return;
	while (1) {
		struct sockaddr_in client_addr;
		socklen_t addr_len = sizeof(client_addr);
		if (listen(listen_fd, 1000) == -1) {
			printf("Couldn't listen on socket: %s", strerror(errno));
			exit(1);
		}
		int stream = accept(listen_fd,
				reinterpret_cast<sockaddr *>(&client_addr),
				&addr_len);
		if (stream < 0) {
			printf("Couldn't accept incoming connection: %s\n",
				strerror(errno));
			exit(1);
		}
		// std::thread thread(nd_pingpong, stream, client_addr);
		std::thread thread(nd_pingpong_async, stream, client_addr);
		// std::thread thread(nd_connection, stream, client_addr);
		// cpu_set_t cpuset;
		// CPU_ZERO(&cpuset);
		// CPU_SET((i) % 2 * 4, &cpuset);
		// pthread_setaffinity_np(thread.native_handle(), sizeof(cpu_set_t), &cpuset);
		thread.detach();
		i += 1;	
	}
	// while (1) {
	// 	struct sockaddr_in client_addr;
	// 	socklen_t addr_len = sizeof(client_addr);

	// 	result = recvfrom(listen_fd, (char *)buffer, sizeof(buffer),  
 //                MSG_WAITALL, ( struct sockaddr *) &client_addr, 
 //                &addr_len);
	// 	// printf("%s", buffer);
	// 	// printf("%c\n",  buffer[63999]);
	// 	// printf("len: %d\n", result);
	// 	if (result < 0) {
	// 		if (errno == ECONNRESET)
	// 			break;
	// 		printf("Read error on socket: %s", strerror(errno));
	// 		exit(1);
	// 	}
	// 	if (result == 0)
	// 		break;
	// 	if(count % 50000 == 0) {
	// 		end_cycle = rdtsc();
			
	// 		double rate = ((double) total_length)/ to_seconds(
	// 			end_cycle - start_cycle);
	// 		total_length = 0;

	// 		start_cycle = rdtsc();
	// 		if(count != 0) {
	// 			printf("ND throughput: "
	// 			"%.2f Gbps\n", rate * 1e-09 * 8);
	// 		}
	// 	}
	// 	total_length += result;
	// 	count += 1;
	// }

}

int main(int argc, char** argv) {
	int next_arg;
	int num_ports = 1;
	std::string ip;
	if ((argc >= 2) && (strcmp(argv[1], "--help") == 0)) {
		print_help(argv[0]);
		exit(0);
	}
	
	for (next_arg = 1; next_arg < argc; next_arg++) {
		if (strcmp(argv[next_arg], "--help") == 0) {
			print_help(argv[0]);
			exit(0);
		} else if (strcmp(argv[next_arg], "--port") == 0) {
			if (next_arg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[next_arg]);
				exit(1);
			}
			next_arg++;
			port = get_int(argv[next_arg],
					"Bad port %s; must be positive integer\n");
		} else if (strcmp(argv[next_arg], "--ip") == 0) {
			if (next_arg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[next_arg]);
				exit(1);
			}
			next_arg++;
			ip = std::string(argv[next_arg]);
		} 
		else if (strcmp(argv[next_arg], "--num_ports") == 0) {
			if (next_arg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[next_arg]);
				exit(1);
			}
			next_arg++;
			num_ports = get_int(argv[next_arg],
				"Bad num_ports %s; must be positive integer\n");
		} else if (strcmp(argv[next_arg], "--validate") == 0) {
			validate = true;
		} else if (strcmp(argv[next_arg], "--verbose") == 0) {
			verbose = true;
		} else {
			printf("Unknown option %s; type '%s --help' for help\n",
				argv[next_arg], argv[0]);
			exit(1);
		}
	}
 	std::vector<std::thread> workers;

	workers.push_back(std::thread(tcp_server, port));
	workers.push_back(std::thread(udp_server, port));
	workers.push_back(std::thread(nd_server, port));
	workers.push_back(std::thread(aggre_thread, &agg_stats));
	for(int i = 0; i < num_ports; i++) {
		workers[i].join();
	}
}
