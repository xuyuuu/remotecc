#include <stdio.h>
#include <stdint.h>

#include "libssh2.h"
#include "libssh2_config.h"
#include "libssh2_sftp.h"

#include "transport.h"
#include "crypto.h"
#include "openssl.h"
#include "comp.h"
#include "mac.h"

#include "remotecc.h"

void
usage(void)
{
	printf("-u username\n\
-p password\n\
-i ipaddr\n\
-r command\n\
-h for help\n");
}

int main(int argc, char **argv)
{
	int opt, umode = 0, pmode = 0, imode = 0, rmode = 0;
	char username[256] = {0}, passwd[256] = {0},
	     ipaddr[20] = {0}, command[256] = {0}, argvs[256] = {0};

	while((opt = getopt(argc, argv, "u:p:i:r:h")) != -1){
		switch (opt){
		case 'u':	
			umode = 1;
			strncpy(username, optarg, strlen(optarg));
			break;
		case 'p':
			pmode = 1;
			strncpy(passwd, optarg, strlen(optarg));
			break;
		case 'i':
			imode = 1;
			strncpy(ipaddr, optarg, strlen(optarg));
			break;
		case 'r':
			rmode = 1;
			sscanf(optarg, "%s %[^0-9]", command, argvs);
			//strncpy(command, optarg, strlen(optarg));
			break;
		case 'h':
			usage();
			_exit(0);
		default:
			fprintf(stderr, "Arguments Is Error \n");
			usage();
			_exit(0);
		}
	}

	if(!umode || !pmode || !imode || !rmode){
			fprintf(stderr, "Arguments Is Error \n");
			usage();
			return 0;
	}
printf("command: %s   argv: %s\n", command, argvs);
	return 0;
	remotecc_handler_t handler, *p;
	p = remotecc_module.init(username, passwd, command,
			ipaddr, argvs, &handler);

	if(0 == p->status)
		remotecc_module.handler(p);

	remotecc_module.destroy(p);

	return 0;
}
