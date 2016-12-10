#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "libssh2.h"
#include "libssh2_config.h"
#include "libssh2_sftp.h"

#include "transport.h"
#include "crypto.h"
#include "openssl.h"
#include "comp.h"
#include "mac.h"

#include "remotecc.h"


static int remotecc_module_inside_inside_waitsocket(int sock, LIBSSH2_SESSION *session)
{
	int rc, mask;
	fd_set fd;
	fd_set *writefd = NULL;
	fd_set *readfd = NULL;
	struct timeval timeout;

	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	FD_ZERO(&fd);
	FD_SET(sock, &fd);

	mask = libssh2_session_block_directions(session);
	if(mask & LIBSSH2_SESSION_BLOCK_INBOUND)
		readfd = &fd;
	if(mask & LIBSSH2_SESSION_BLOCK_OUTBOUND)
		writefd = &fd;

	rc = select(sock + 1, readfd, writefd, NULL, &timeout);

	return rc;
}

static remotecc_handler_t *
remotecc_module_inside_init(const char *username, 
const char *passwd, const char *runcommand, const char *ipaddr, const char *argv, remotecc_handler_t *handler)
{
	int sockfd = 0;;
	struct sockaddr_in sin;
	remotecc_handler_t *phandler = handler;
	LIBSSH2_SESSION *session;
	LIBSSH2_SFTP *sftp_session;

	handler->sock = 0;
	handler->status = -1;
	handler->session = NULL;
	handler->sftp_session = NULL;
	if(username)
		strncpy(handler->username, username, sizeof(handler->username) - 1);
	else
		goto out;


	if(passwd)
		strncpy(handler->passwd, passwd, sizeof(handler->passwd) - 1);
	else
		goto out;

	if(runcommand)
		strncpy(handler->runcommand, runcommand, sizeof(handler->runcommand) - 1);
	else
		goto out;

	if(argv)
		strncpy(handler->argv, argv, strlen(argv));
	else
		goto out;

	if(!ipaddr)
		goto out;

	if(libssh2_init (0))
		goto out;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	handler->sock = sockfd;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(22);
	if(!inet_pton(AF_INET, ipaddr, &sin.sin_addr))
		goto out;
	if (connect(sockfd, (struct sockaddr*)(&sin),
				sizeof(struct sockaddr_in)) != 0)
		goto out;

	session = libssh2_session_init();
	if(!session)
		goto out;
	handler->session = session;

	if(libssh2_session_handshake(session, sockfd))
		goto out;

	//libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
	if(libssh2_userauth_password(session, username, passwd))
		goto out;

	sftp_session = libssh2_sftp_init(session);
	if(!sftp_session)
		goto out;
	handler->sftp_session = sftp_session;
	libssh2_session_set_blocking(session, 1);
		
	handler->status = 0;
out:

	return phandler;
}

static int
remotecc_module_inside_inside_pushcommand(remotecc_handler_t *handler)
{
	int ret = -1, nread = 0, rc = 0;
	char remotecc_file[256] = {0}, local_file[256] = {0}, 
		buff[1024*100] = {0}, *ptr;
	FILE *fp;
	LIBSSH2_SFTP_HANDLE *sftp_handle;
    	LIBSSH2_SFTP_ATTRIBUTES attrs;

	if(!handler)
		goto out;

	sprintf(remotecc_file, "/tmp/%s", handler->runcommand);
	sprintf(local_file, "./%s", handler->runcommand);
	fp = fopen(local_file, "r+");
	if(!fp)
		goto out;
	
	sftp_handle =
		libssh2_sftp_open(handler->sftp_session, remotecc_file,

		LIBSSH2_FXF_WRITE|LIBSSH2_FXF_READ|LIBSSH2_FXF_CREAT,
		LIBSSH2_SFTP_S_IRUSR|LIBSSH2_SFTP_S_IWUSR|LIBSSH2_SFTP_S_IXUSR|
		LIBSSH2_SFTP_S_IRGRP|LIBSSH2_SFTP_S_IROTH);
	if(!sftp_handle)
		goto out;

	do{
		nread = fread(buff, 1, sizeof(buff), fp);
		if(nread <= 0)
			break;
		ptr = buff;
		do{
			rc = libssh2_sftp_write(sftp_handle, ptr, nread);
			if(rc < 0)
				break;
			ptr += rc;
			nread -= rc;
		}while(nread);
	}while(rc > 0);

	while((rc = libssh2_sftp_fstat_ex(sftp_handle, &attrs, 0)) == LIBSSH2_ERROR_EAGAIN)
		remotecc_module_inside_inside_waitsocket(handler->sock, handler->session);
	if(rc)
		handler->rfsize = 0;
	else
		handler->rfsize = attrs.filesize;

	if(sftp_handle)
		libssh2_sftp_close(sftp_handle);


	ret = 0;
out:
	if(fp)
		fclose(fp);

	return ret;
}


static int
remotecc_module_inside_inside_runcommand(remotecc_handler_t *handler)
{
	int ret = -1, rc = 0;
	char cmd[1024] = {0};	
	LIBSSH2_CHANNEL *channel = NULL;

	sprintf(cmd, "/tmp/%s %s", handler->runcommand, handler->argv);

	while((channel = libssh2_channel_open_session(handler->session)) == NULL &&
		libssh2_session_last_error(handler->session,NULL,NULL,0) == LIBSSH2_ERROR_EAGAIN)
		remotecc_module_inside_inside_waitsocket(handler->sock, handler->session);
	if(!channel)
		goto out;

	while((rc = libssh2_channel_exec(channel, cmd)) == LIBSSH2_ERROR_EAGAIN)
		remotecc_module_inside_inside_waitsocket(handler->sock, handler->session);
	if(rc)
		goto out;

	while(1){
		do{
			char buffer[0x4000];
			rc = libssh2_channel_read(channel, buffer, sizeof(buffer));
			if(rc > 0){
				int i;
				fprintf(stderr, "We read:\n");
				for( i=0; i < rc; ++i )
					fputc( buffer[i], stderr);
				fprintf(stderr, "\n");
			}
			else{
				/*
				if(rc != LIBSSH2_ERROR_EAGAIN)
					fprintf(stderr, "libssh2_channel_read returned %d\n", rc);
				*/
			}
		}while(rc > 0);

		if( rc == LIBSSH2_ERROR_EAGAIN )
			remotecc_module_inside_inside_waitsocket(handler->sock, handler->session);
		else
			break;
	}
	while((rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN)
		remotecc_module_inside_inside_waitsocket(handler->sock, handler->session);

	if(rc){
		goto out;
//ret = libssh2_channel_get_exit_status(channel);
//		libssh2_channel_get_exit_signal(channel, &exitsignal,
//			NULL, NULL, NULL, NULL, NULL);
	}

	ret = 0;
out:
	if(channel)
		libssh2_channel_free(channel);

	return ret;
}

static int
remotecc_module_inside_inside_popcommand(remotecc_handler_t *handler)
{
	int ret = -1, file_len = 0;
	char remotecc_file[256] = {0};
	if(!handler)
		goto out;
	if(!handler->rfsize)
		goto out;

	sprintf(remotecc_file, "/tmp/%s", handler->runcommand);
	
	while(libssh2_sftp_unlink_ex(handler->sftp_session, remotecc_file, strlen(remotecc_file)) == LIBSSH2_ERROR_EAGAIN)
		remotecc_module_inside_inside_waitsocket(handler->sock, handler->session);

	ret = 0;
out:
	return ret;

}

static int 
remotecc_module_inside_handler(remotecc_handler_t *handler)
{
	int ret = -1;
	if(remotecc_module_inside_inside_pushcommand(handler))
		goto out;

	if(remotecc_module_inside_inside_runcommand(handler))
		goto out;

	if(remotecc_module_inside_inside_popcommand(handler))
		goto out;

	ret = 0;
out:
	return ret;
}


static int remotecc_module_inside_destroy(remotecc_handler_t *handler)
{
	int ret = -1;

	if(!handler)
		goto err;

	if(handler->sftp_session)
		libssh2_sftp_shutdown(handler->sftp_session);
	if(handler->session){
		libssh2_session_disconnect(handler->session, "Bye Bye !");
		libssh2_session_free(handler->session);
	}
	if(handler->sock)
		close(handler->sock);
	libssh2_exit();

	ret = 0;
err:
	return ret;
}


struct remotecc_module remotecc_module = 
{
	.init		= remotecc_module_inside_init,
	.handler	= remotecc_module_inside_handler,
	.destroy	= remotecc_module_inside_destroy,
};





