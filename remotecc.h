#ifndef remotecc_h
#define remotecc_h


typedef struct remotecc_handler_s
{
	int sock;
	int status;
	char username[128];
	char passwd[128];
	char runcommand[1024];
	char argv[1024];
	uint64_t rfsize;

	LIBSSH2_SESSION *session;

	LIBSSH2_SFTP *sftp_session;
}remotecc_handler_t;

struct remotecc_module
{
	remotecc_handler_t *(*init)(const char*username,
		const char *passwd, const char *runcommand,
		const char *ipaddr, const char *argv, 
		remotecc_handler_t *handler);	
	int (*handler)(remotecc_handler_t *handler);	
	int (*destroy)(remotecc_handler_t *handler);
};

extern struct remotecc_module remotecc_module;

#endif
