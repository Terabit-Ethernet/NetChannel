// io_uring benchmark client
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>

#include <liburing.h>
#include "test_utils.h"

#define BUF_SIZE 10000000
#define SEND_SIZE 10000000
#define RX_BUF_SIZE 2097152
#define MSG_SIZE 4096
#define QUEUE_DEPTH 32

int send_longflow(const char *host, int port, int duration) {
    
    struct sockaddr_in saddr;
	struct io_uring ring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int sockfd, ret;
    char *buf;

    buf = (char *) malloc(BUF_SIZE * sizeof(char));
    memset(buf, '1', BUF_SIZE);

    struct iovec iov = {
		.iov_base = buf,
		.iov_len = SEND_SIZE,
	};

    ret = io_uring_queue_init(64, &ring, 0);
	if (ret) {
		fprintf(stderr, "queue init failed: %d\n", ret);
		return 1;
	}

    memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	inet_pton(AF_INET, host, &saddr.sin_addr);

    // sockfd = socket(AF_INET, SOCK_STREAM, 0);
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_VIRTUAL_SOCK);
	if (sockfd < 0) {
		perror("socket");
		return 1;
	}

    ret = connect(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0) {
		perror("connect");
		return 1;
	}
    printf("Connected\n");

    uint64_t write_len = 0;
    uint64_t start_time = rdtsc();
    while(1) {

        sqe = io_uring_get_sqe(&ring);
	    io_uring_prep_send(sqe, sockfd, iov.iov_base, iov.iov_len, 0);
	    sqe->user_data = 1;

        ret = io_uring_submit(&ring);
	    if (ret <= 0) {
		    fprintf(stderr, "submit failed: %d\n", ret);
            close(sockfd);
		    return 1;
	    }

        ret = io_uring_wait_cqe(&ring, &cqe);
        if (cqe->res == -EINVAL) {
            fprintf(stderr, "send not supported\n");
            close(sockfd);
            return 1;
        }
        if(cqe->res <= 0) {
            fprintf(stderr, "CQE with <= bytes sent\n");
            close(sockfd);
            return 1;
        }
        
        write_len += cqe->res;

        io_uring_cqe_seen(&ring, cqe);

        uint64_t end = rdtsc();
        if(to_seconds(end-start_time) > duration) {
            break;
        }

    }

    printf("Throughput: %lf Gbps\n", (double)write_len * 8 / ((double) duration * 1e9));

    close(sockfd);
    free(buf);
    return 0;


}

int send_shortflow(const char *host, int port, int duration) {
    
    struct sockaddr_in saddr;
	struct io_uring ring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int sockfd, ret;
    char *buf;

    buf = (char *) malloc(BUF_SIZE * sizeof(char));
    memset(buf, '1', BUF_SIZE);

    struct iovec iov = {
		.iov_base = buf,
		.iov_len = MSG_SIZE,
	};

    ret = io_uring_queue_init(64, &ring, 0);
	if (ret) {
		fprintf(stderr, "queue init failed: %d\n", ret);
		return 1;
	}

    memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	inet_pton(AF_INET, host, &saddr.sin_addr);

    // sockfd = socket(AF_INET, SOCK_STREAM, 0);
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_VIRTUAL_SOCK);

	if (sockfd < 0) {
		perror("socket");
		return 1;
	}

    ret = connect(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0) {
		perror("connect");
		return 1;
	}
    printf("Connected\n");

    uint64_t write_len = 0;
    uint64_t start_time = rdtsc();
    while(1) {

        sqe = io_uring_get_sqe(&ring);
	    io_uring_prep_send(sqe, sockfd, iov.iov_base, iov.iov_len, MSG_EOR);
	    sqe->user_data = 1;

        ret = io_uring_submit(&ring);
	    if (ret <= 0) {
		    fprintf(stderr, "submit failed: %d\n", ret);
            close(sockfd);
		    return 1;
	    }

        ret = io_uring_wait_cqe(&ring, &cqe);
        if (cqe->res == -EINVAL) {
            fprintf(stderr, "send not supported\n");
            close(sockfd);
            return 1;
        }
        if(cqe->res <= 0) {
            fprintf(stderr, "CQE with <= 0 bytes sent\n");
            close(sockfd);
            return 1;
        }
        
        write_len += cqe->res;

        io_uring_cqe_seen(&ring, cqe);

        uint64_t end = rdtsc();
        if(to_seconds(end-start_time) > duration) {
            break;
        }

    }

    printf("Throughput: %lf Gbps\n", (double)write_len * 8 / ((double) duration * 1e9));

    close(sockfd);
    free(buf);
    return 0;


}

int send_shortflow_qd(const char *host, int port, int duration) {
    
    struct sockaddr_in saddr;
	struct io_uring ring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int sockfd, ret;
    char *buf;
    int i;

    buf = (char *) malloc(BUF_SIZE * sizeof(char));
    memset(buf, '1', BUF_SIZE);

    struct iovec iov = {
		.iov_base = buf,
		.iov_len = MSG_SIZE,
	};

    ret = io_uring_queue_init(64, &ring, 0);
	if (ret) {
		fprintf(stderr, "queue init failed: %d\n", ret);
		return 1;
	}

    memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	inet_pton(AF_INET, host, &saddr.sin_addr);

 //   sockfd = socket(AF_INET, SOCK_STREAM, 0);
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_VIRTUAL_SOCK);

	if (sockfd < 0) {
		perror("socket");
		return 1;
	}

    ret = connect(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0) {
		perror("connect");
		return 1;
	}
    printf("Connected\n");

    uint64_t write_len = 0;
    uint64_t start_time = rdtsc();

    for(i = 0; i < QUEUE_DEPTH; i++) {
        sqe = io_uring_get_sqe(&ring);
	    io_uring_prep_send(sqe, sockfd, iov.iov_base, iov.iov_len, MSG_EOR);
	    sqe->user_data = 1;
    }


    ret = io_uring_submit(&ring);
    if (ret <= 0) {
        fprintf(stderr, "submit failed: %d\n", ret);
        close(sockfd);
        return 1;
    }

    while(1) {

        ret = io_uring_wait_cqe(&ring, &cqe);
        if (cqe->res == -EINVAL) {
            fprintf(stderr, "send not supported\n");
            close(sockfd);
            return 1;
        }
        if(cqe->res <= 0) {
            fprintf(stderr, "CQE with <= 0 bytes sent\n");
            close(sockfd);
            return 1;
        }
        
        write_len += cqe->res;

        io_uring_cqe_seen(&ring, cqe);

        uint64_t end = rdtsc();
        if(to_seconds(end-start_time) > duration) {
            break;
        }

        sqe = io_uring_get_sqe(&ring);
	    io_uring_prep_send(sqe, sockfd, iov.iov_base, iov.iov_len, MSG_EOR);
	    sqe->user_data = 1;

        ret = io_uring_submit(&ring);
	    if (ret <= 0) {
		    fprintf(stderr, "submit failed: %d\n", ret);
            close(sockfd);
		    return 1;
	    }


    }

    printf("Throughput: %lf Gbps\n", (double)write_len * 8 / ((double) duration * 1e9));

    close(sockfd);
    free(buf);
    return 0;


}

int send_shortflow_sqpoll(const char *host, int port, int duration) {
    
    struct sockaddr_in saddr;
	struct io_uring ring;
    struct io_uring_params p = { };
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int sockfd, ret;
    char *buf;

    buf = (char *) malloc(BUF_SIZE * sizeof(char));
    memset(buf, '1', BUF_SIZE);

    struct iovec iov = {
		.iov_base = buf,
		.iov_len = MSG_SIZE,
	};

    p.flags = IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF;
    p.sq_thread_cpu = 4;

    ret = io_uring_queue_init_params(64, &ring, &p);
	if (ret) {
		fprintf(stderr, "queue init failed: %d\n", ret);
		return 1;
	}

    memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	inet_pton(AF_INET, host, &saddr.sin_addr);

//    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_VIRTUAL_SOCK);

	if (sockfd < 0) {
		perror("socket");
		return 1;
	}

    ret = connect(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0) {
		perror("connect");
		return 1;
	}
    printf("Connected\n");

    ret = io_uring_register_files(&ring, &sockfd, 1);
    if(ret) {
        fprintf(stderr, "file reg failed\n");
        close(sockfd);
        return ret;
    }

    uint64_t write_len = 0;
    uint64_t start_time = rdtsc();
    while(1) {

        sqe = io_uring_get_sqe(&ring);
	    io_uring_prep_send(sqe, 0, iov.iov_base, iov.iov_len, MSG_EOR);
        sqe->flags |= IOSQE_FIXED_FILE;
	    sqe->user_data = 1;

        ret = io_uring_submit(&ring);
	    if (ret <= 0) {
		    fprintf(stderr, "submit failed: %d\n", ret);
            close(sockfd);
		    return 1;
	    }

        ret = io_uring_wait_cqe(&ring, &cqe);
        if (cqe->res == -EINVAL) {
            fprintf(stderr, "send not supported\n");
            close(sockfd);
            return 1;
        }
        if(cqe->res <= 0) {
            fprintf(stderr, "CQE with <= 0 bytes sent\n");
            if(cqe->res < 0) {
                fprintf(stderr, "cqe error: %s\n", strerror(-ret));
            }
            close(sockfd);
            return 1;
        }
        
        write_len += cqe->res;

        io_uring_cqe_seen(&ring, cqe);

        uint64_t end = rdtsc();
        if(to_seconds(end-start_time) > duration) {
            break;
        }

    }

    printf("Throughput: %lf Gbps\n", (double)write_len * 8 / ((double) duration * 1e9));

    close(sockfd);
    free(buf);
    return 0;


}

int send_shortflow_fullpoll(const char *host, int port, int duration) {
    
    struct sockaddr_in saddr;
	struct io_uring ring;
    struct io_uring_params p = { };
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int sockfd, ret;
    char *buf;
    int i;

    buf = (char *) malloc(BUF_SIZE * sizeof(char));
    memset(buf, '1', BUF_SIZE);

    struct iovec iov = {
		.iov_base = buf,
		.iov_len = MSG_SIZE,
	};

    p.flags = IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF;
    p.sq_thread_cpu = 4;

    ret = io_uring_queue_init_params(64, &ring, &p);
	if (ret) {
		fprintf(stderr, "queue init failed: %d\n", ret);
		return 1;
	}

    memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	inet_pton(AF_INET, host, &saddr.sin_addr);

//    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_VIRTUAL_SOCK);

	if (sockfd < 0) {
		perror("socket");
		return 1;
	}

    ret = connect(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0) {
		perror("connect");
		return 1;
	}
    printf("Connected\n");

    ret = io_uring_register_files(&ring, &sockfd, 1);
    if(ret) {
        fprintf(stderr, "file reg failed\n");
        close(sockfd);
        return ret;
    }

    uint64_t write_len = 0;
    uint64_t start_time = rdtsc();

    for(i = 0; i < QUEUE_DEPTH; i++) {
        sqe = io_uring_get_sqe(&ring);
	    io_uring_prep_send(sqe, 0, iov.iov_base, iov.iov_len, MSG_EOR);
        sqe->flags |= IOSQE_FIXED_FILE;
	    sqe->user_data = 1;
    }


    ret = io_uring_submit(&ring);
    if (ret <= 0) {
        fprintf(stderr, "submit failed: %d\n", ret);
        close(sockfd);
        return 1;
    }

    while(1) {

        while(1) {
            // Poll for completion
            ret = io_uring_peek_cqe(&ring, &cqe);
            if(ret == 0) {
                break;
            }
        }

        if (cqe->res == -EINVAL) {
            fprintf(stderr, "send not supported\n");
            close(sockfd);
            return 1;
        }
        if(cqe->res <= 0) {
            fprintf(stderr, "CQE with <= 0 bytes sent\n");
            if(cqe->res < 0) {
                fprintf(stderr, "cqe error: %s\n", strerror(-(cqe->res)));
            }
            close(sockfd);
            return 1;
        }
        
        write_len += cqe->res;

        io_uring_cqe_seen(&ring, cqe);

        uint64_t end = rdtsc();
        if(to_seconds(end-start_time) > duration) {
            break;
        }

        sqe = io_uring_get_sqe(&ring);
	    io_uring_prep_send(sqe, 0, iov.iov_base, iov.iov_len, MSG_EOR);
        sqe->flags |= IOSQE_FIXED_FILE;
	    sqe->user_data = 1;

        ret = io_uring_submit(&ring);
	    if (ret <= 0) {
		    fprintf(stderr, "submit failed: %d\n", ret);
            close(sockfd);
		    return 1;
	    }

    }

    printf("Throughput: %lf Gbps\n", (double)write_len * 8 / ((double) duration * 1e9));

    close(sockfd);
    free(buf);
    return 0;


}

int send_shortflow_legacy(const char *host, int port, int duration) {
    
    struct sockaddr_in saddr;
	int sockfd, ret;
    char *buf;

    buf = (char *) malloc(BUF_SIZE * sizeof(char));
    memset(buf, '1', BUF_SIZE);

    struct iovec iov = {
		.iov_base = buf,
		.iov_len = MSG_SIZE,
	};

    memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	inet_pton(AF_INET, host, &saddr.sin_addr);

//    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_VIRTUAL_SOCK);

	if (sockfd < 0) {
		perror("socket");
		return 1;
	}

    ret = connect(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0) {
		perror("connect");
		return 1;
	}
    printf("Connected\n");

    uint64_t write_len = 0;
    uint64_t start_time = rdtsc();
    while(1) {

        ret = send(sockfd, iov.iov_base, iov.iov_len, MSG_EOR);
        if(ret < 0) {
            perror("socket send failed");
            close(sockfd);
            return -1;
        }
        
        write_len += ret;

        uint64_t end = rdtsc();
        if(to_seconds(end-start_time) > duration) {
            break;
        }

    }

    printf("Throughput: %lf Gbps\n", (double)write_len * 8 / ((double) duration * 1e9));

    close(sockfd);
    free(buf);
    return 0;


}

int accept_connection(const char *host, int port, int *sock) {
    
    int ret, listen_fd;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

    
    // listen_fd = socket(PF_INET, SOCK_STREAM, 0);
    listen_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_VIRTUAL_SOCK);

    if(listen_fd == -1) {
        perror("listen socket create failed");
        return -1;
    }

    int option_value = 1;
    ret = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR | SO_NO_CHECK, &option_value,
			sizeof(option_value));
    if(ret) {
        perror("setsockopt failed");
        return ret;
    }

    ret = bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr));
    if(ret) {
        perror("socket bind failed");
        return ret;
    }

    if (listen(listen_fd, 1000) == -1) {
		perror("listen failed");
		return -1;
	}

    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int sockfd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if(sockfd < 0) {
        perror("socket accept failed");
        return -1;
    }

    *sock = sockfd;
    return 0;

}

int recv_longflow(const char *host, int port) {
	struct io_uring ring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int sockfd, ret;
    char *buf;

    buf = (char *) malloc(RX_BUF_SIZE * sizeof(char));
    memset(buf, '1', RX_BUF_SIZE);

    struct iovec iov = {
		.iov_base = buf,
		.iov_len = RX_BUF_SIZE,
	};

    printf("listening for connection\n");
    ret = accept_connection(host, port, &sockfd);
    if(ret) {
        fprintf(stderr, "connection accept failed: %d\n", ret);
        return 1;
    }
    printf("accepted connection\n");

    ret = io_uring_queue_init(64, &ring, 0);
	if (ret) {
		fprintf(stderr, "queue init failed: %d\n", ret);
		return 1;
	}

    while(1) {
        sqe = io_uring_get_sqe(&ring);
        io_uring_prep_recv(sqe, sockfd, iov.iov_base, iov.iov_len, 0);
        sqe->user_data = 2;

        ret = io_uring_submit(&ring);
        if (ret <= 0) {
            fprintf(stderr, "submit failed: %s\n", strerror(-ret));
            close(sockfd);
            return 1;
        }

        ret = io_uring_wait_cqe(&ring, &cqe);
        if (ret) {
		    fprintf(stdout, "wait_cqe: %d\n", ret);
		    close(sockfd);
            return 1;
	    }

        if (cqe->res == -EINVAL) {
		    fprintf(stderr, "recv not supported, skipping\n");
		    close(sockfd);
            return 1;
        }

        if(cqe->res == 0) {
            break;
        }

        if (cqe->res < 0) {
		    fprintf(stderr, "failed cqe: %d\n", cqe->res);
		    close(sockfd);
            return 1;
	    }

        io_uring_cqe_seen(&ring, cqe);
	}

    close(sockfd);
    return 0;

}

int recv_longflow_legacy(const char *host, int port) {
	int sockfd, ret;
    char *buf;

    buf = (char *) malloc(RX_BUF_SIZE * sizeof(char));
    memset(buf, '1', RX_BUF_SIZE);

    struct iovec iov = {
		.iov_base = buf,
		.iov_len = RX_BUF_SIZE,
	};

    printf("listening for connection\n");
    ret = accept_connection(host, port, &sockfd);
    if(ret) {
        fprintf(stderr, "connection accept failed: %d\n", ret);
        return 1;
    }
    printf("accepted connection\n");

    while(1) {

        ret = recv(sockfd, iov.iov_base, iov.iov_len, 0);
        if(ret == 0){
            break;
        }
        if(ret < 0) {
            perror("recv failed");
            close(sockfd);
            return -1;
        }

	}

    close(sockfd);
    return 0;

}

// usage: ./iouring_client <action> <host> <port> <duration>
int main(int argc, char *argv[]) {

    int ret;

    if(argc < 4) {
        fprintf(stderr, "Invalid args\n");
        return 1;
    }

    const char *action = argv[1];
    const char *host = argv[2];
    int port = atoi(argv[3]);

    if(strcmp(action, "client") == 0) {
        if(argc < 5) {
            fprintf(stderr, "Missing args\n");
            return 1;
        }
        int duration = atoi(argv[4]);

        ret = send_longflow(host, port, duration);
        if(ret) {
            fprintf(stderr, "send_longflow failed\n");
            return ret;
        }
    } else if(strcmp(action, "client-shortflows") == 0) {
        if(argc < 5) {
            fprintf(stderr, "Missing args\n");
            return 1;
        }
        int duration = atoi(argv[4]);

        ret = send_shortflow(host, port, duration);
        if(ret) {
            fprintf(stderr, "send_shortflow failed\n");
            return ret;
        }
    } else if(strcmp(action, "client-shortflows-sqpoll") == 0) {
        if(argc < 5) {
            fprintf(stderr, "Missing args\n");
            return 1;
        }
        int duration = atoi(argv[4]);

        ret = send_shortflow_sqpoll(host, port, duration);
        if(ret) {
            fprintf(stderr, "send_shortflow_sqpoll failed\n");
            return ret;
        }
    } else if(strcmp(action, "client-shortflows-qd") == 0) {
        if(argc < 5) {
            fprintf(stderr, "Missing args\n");
            return 1;
        }
        int duration = atoi(argv[4]);

        ret = send_shortflow_qd(host, port, duration);
        if(ret) {
            fprintf(stderr, "send_shortflow_sqpoll failed\n");
            return ret;
        }
    }
    else if(strcmp(action, "client-shortflows-fullpoll") == 0) {
        if(argc < 5) {
            fprintf(stderr, "Missing args\n");
            return 1;
        }
        int duration = atoi(argv[4]);

        ret = send_shortflow_fullpoll(host, port, duration);
        if(ret) {
            fprintf(stderr, "send_shortflow_fullpoll failed\n");
            return ret;
        }
    }
    else if(strcmp(action, "client-shortflows-legacy") == 0) {
        if(argc < 5) {
            fprintf(stderr, "Missing args\n");
            return 1;
        }
        int duration = atoi(argv[4]);

        ret = send_shortflow_legacy(host, port, duration);
        if(ret) {
            fprintf(stderr, "send_shortflow_legacy failed\n");
            return ret;
        }
    }
     else if(strcmp(action, "server") == 0) {
        ret = recv_longflow(host, port);
        if(ret) {
            fprintf(stderr, "recv_longflow failed\n");
            return ret;
        }
    } else if(strcmp(action, "server-legacy") == 0) {
        ret = recv_longflow_legacy(host, port);
        if(ret) {
            fprintf(stderr, "recv_longflow_legacy failed\n");
            return ret;
        }
    }

    return 0;
}
