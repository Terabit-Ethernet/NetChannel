/* ND Connection Listerning Port */
struct nd_conn_port {
	struct socket		*sock;
	struct work_struct	accept_work;
	// struct nvmet_port	*nport;
	struct sockaddr_storage addr;
	void (*data_ready)(struct sock *);
};
