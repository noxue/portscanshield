/*!
	\file portscanshield.c
*/

#include "portscanshield.h"
#include "pss_log.h"
#include "pss_config.h"
#include "ip_knock_info.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <grp.h>

extern volatile struct pss_config_vars pss_configuration;

void pss_drop_rights( void ) {

	if( setregid( pss_configuration.gid, pss_configuration.gid ) == -1 ) {
		pss_fatal( "Rights drop failed (setregid)! Error #%d: %s\n", errno, strerror(errno) );
	}

	if( setgroups( 0, NULL ) == -1 ) {
		pss_fatal( "Rights drop failed (setgroups)! Error #%d: %s\n", errno, strerror(errno) );
	}

	if( setreuid( pss_configuration.uid, pss_configuration.uid ) == -1 ) {
		pss_fatal( "Rights drop failed (setreuid)! Error #%d: %s\n", errno, strerror(errno) );
	}

}

void ban_ip( const char *ip ) {

	assert( ip != NULL );

	char *ip_tab_pos = strstr( pss_configuration.ban_cmd, BANSTRING_IP_TAG );
	int num_of_bstr_to_copy = ip_tab_pos - pss_configuration.ban_cmd;

	char *ban_string = malloc( strlen( pss_configuration.ban_cmd ) + strlen(ip) - strlen( BANSTRING_IP_TAG ) + 1 );

	strncpy( ban_string, pss_configuration.ban_cmd, num_of_bstr_to_copy );
	ban_string[ num_of_bstr_to_copy ] = '\0';
	strcat( ban_string, ip );
	strcat( ban_string, pss_configuration.ban_cmd + num_of_bstr_to_copy + strlen( BANSTRING_IP_TAG ) );

	pss_log( "Banning IP %s with command %s!\n", ip, ban_string );

	#ifndef BANSTRING_NOEXEC
		system( ban_string );
	#endif

	free( ban_string );

}

void pss_setup_sniff_sockets( int *sniff_sockfd_tcp, int *sniff_sockfd_udp ) {

	assert( sniff_sockfd_tcp != NULL && sniff_sockfd_udp != NULL );

	if( (*sniff_sockfd_tcp = socket( AF_INET, SOCK_RAW, IPPROTO_TCP ) ) == -1 ) {
		pss_fatal( "TCP sniffing socked create failed! Error #%d: %s\n", errno, strerror(errno) );
	}

	if( fcntl( *sniff_sockfd_tcp, F_SETFL, O_NONBLOCK ) == -1 ) {
		pss_fatal( "TCP sniffing socked flag set failed! Error #%d: %s\n", errno, strerror(errno) );
	}

	if( (*sniff_sockfd_udp = socket( AF_INET, SOCK_RAW, IPPROTO_UDP ) ) == -1 ) {
		pss_fatal( "UDP sniffing socked create failed! Error #%d: %s\n", errno, strerror(errno) );
	}

	if( fcntl( *sniff_sockfd_udp, F_SETFL, O_NONBLOCK ) ) {
		pss_fatal( "UDP sniffing socked flag set failed! Error #%d: %s\n", errno, strerror(errno) );
	}

}

/*!
	\brief Creates epoll object and adds two sniffing sockets to observe.
	\param sniff_sockfd_tcp, sniff_sockfd_udp Created Sniffing sockets.
	\return Epoll object.
*/
static int epoll_obj_prepare( int sniff_sockfd_tcp, int sniff_socfd_udp ) {

	int epoll_obj = epoll_create1(0);
	if( ( epoll_obj = epoll_create1(0) ) == -1 ) {
		pss_fatal( "Epoll object create failed! Error #%d: %s\n", errno, strerror(errno) );
	}

	struct epoll_event epoll_e_tcp, epoll_e_udp;

	memset( &epoll_e_tcp, 0x00, sizeof( struct epoll_event ) );
	memset( &epoll_e_udp, 0x00, sizeof( struct epoll_event ) );

	epoll_e_tcp.data.fd = sniff_sockfd_tcp;
	epoll_e_tcp.events = EPOLLIN;
	epoll_e_udp.data.fd = sniff_socfd_udp;
	epoll_e_udp.events = EPOLLIN;

	if( epoll_ctl( epoll_obj, EPOLL_CTL_ADD, sniff_sockfd_tcp, &epoll_e_tcp ) == -1 ) {
		pss_fatal( "Sniffing TCP socket registration in epoll object failed! Error: #%d: %s\n",
					errno, strerror(errno) );
	}

	if( epoll_ctl( epoll_obj, EPOLL_CTL_ADD, sniff_socfd_udp, &epoll_e_udp ) == -1 ) {
		pss_fatal( "Sniffing UDP socket registration in epoll object failed! Error: #%d: %s\n",
					errno, strerror(errno) );
	}

	return epoll_obj;

}

/*!
	\brief Fetches IP and port from raw data bytes, containing structs ip and tcp/udp hdr.
	\param buf Raw data bytes.
	\param ip Under this address fetched IP will be stored.
	\param port Uder this address fetched port number will be stored.
	\param prot_type Protocol type, procols_type enum. Used to choose tcp/udp headers.
*/
static void fetch_ip_port_from_buf( const uint8_t *buf, char **ip, int *port, int prot_type ) {

	assert( buf != NULL && ip != NULL && port != NULL );

	*ip = strdup( inet_ntoa( ((struct ip *)buf)->ip_src ) );

	if( prot_type == P_TCP ) {
		*port = ntohs( ((struct tcphdr *)(buf + sizeof(struct ip)))->dest );
	} else if( prot_type == P_UDP ) {
		*port = ntohs( ((struct udphdr *)(buf + sizeof(struct ip)))->dest );
	} else {
		pss_log( "Wrong parameter passed to fetch_ip_port_from_buf() function.\n" );
	}

}

void pss_run( void ) {

	int sniff_sock_tcp, sniff_sock_udp;
	pss_setup_sniff_sockets( &sniff_sock_tcp, &sniff_sock_udp );

	int epoll_obj = epoll_obj_prepare( sniff_sock_tcp, sniff_sock_udp );

	struct epoll_event *events_happened = calloc( MAX_EPOLL_EVENTS, sizeof( struct epoll_event ) );
	
	uint8_t ip_tcp_buf[ sizeof(struct ip) + sizeof(struct tcphdr) ] = { 0 };
	uint8_t ip_udp_buf[ sizeof(struct ip) + sizeof(struct udphdr) ] = { 0 };

	pss_drop_rights();

	struct vector *ips_knocked_tcp = vector_create();
	struct vector *ips_knocked_udp = vector_create();

	extern volatile int superloop_exit_flag;

	while( !superloop_exit_flag ) { //!< Superloop: runs until signal sets superloop_exit_flag to 1.
		
		int events_happened_count = epoll_wait( epoll_obj, events_happened, MAX_EPOLL_EVENTS, -1 );

		if( events_happened_count == -1 ) {
			if( errno != EINTR ) { // Don't write unuseful message after signal.
				pss_log( "epoll_wait() failed! Error #%d: %s\n", errno, strerror(errno) );
			}
			continue;
		}

		int i = 0;
		for( i = 0; i < events_happened_count; ++i ) {

			if( events_happened[i].data.fd == sniff_sock_tcp ) {

				if( read( sniff_sock_tcp, ip_tcp_buf, sizeof(ip_tcp_buf) ) != -1 ) {

					char *ip = NULL;
					int port = 0;
					fetch_ip_port_from_buf( ip_tcp_buf, &ip, &port, P_TCP );
					ip_knocked( ip, port, ips_knocked_tcp, P_TCP );

					free( ip );

				} else {
					pss_log( "TCP sniffing socket read() failed! Error #%d: %s\n", errno, strerror(errno) );
				}

			} else if( events_happened[i].data.fd == sniff_sock_udp ) {

				if( read( sniff_sock_udp, ip_udp_buf, sizeof(ip_udp_buf) ) != -1 ) {

					char *ip = NULL;
					int port = 0;
					fetch_ip_port_from_buf( ip_udp_buf, &ip, &port, P_UDP );
					ip_knocked( ip, port, ips_knocked_udp, P_UDP );

					free( ip );

				} else {
					pss_log( "UDP sniffing socket read() failed! Error #%d: %s\n", errno, strerror(errno) );
				}

			}

		}

	}

	// Let's clean up a little, shall we.
	free( events_happened );

	vector_free( &ips_knocked_tcp, free );
	vector_free( &ips_knocked_udp, free );

}
