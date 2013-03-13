/*
*
*	PortScanShield
*
*/

/*
	TODO:
		- pid check
		- SIGUSR1 reload conf tcp/udp ports
		- whitelist masks (?)
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "config.h"
#include "pss_functions.h"

int size = -1;
int while_arg = 0;

// Signal callback's
void breakwhile( int sig );
void reload_config( int sig );

// config vars
int write_to_syslog = 0;
int banafter;			// port connection's limit
char* banstring;		// template of after-conn-limit-cmd
int* tcpports;		// trap-ports
int* udpports;
int uid;					// uid and gid to which pss will be set
int gid;
char** whitelist_ip;
int tcpports_size;
int udpports_size;
#ifdef BSD
int ipfw_divertedsock_rulenum;
int ipfw_divertedsock_port;
#endif
// config vars end

char* cmd;	// command executed after exceed of connections per IP

int main( int argc, char** argv ) {

	if( argc > 1 ) {
		if( strcmp( argv[1], "--daemonize" ) || strcmp( argv[1], "-d" ) ) {
			daemon( 1, 0 ); // change to 0 if static conf (?)
		}
	}

	char** iparr = NULL;	// array of IP's which were connecting to server
	int* hitarr = NULL;	// array of number of IP connections
	char* msg = NULL;
	int whitelist_ip_ctr = 0;

	int maxipnum = 0;
	int portknocked = 0;
	int ipindex;

	int i = 0;

	i = read_config();

	#ifdef DEBUG
		printf( " --- [ DEBUG ] ---\n" );
		printf( "write_to_syslog = %i\n"
				"banafter = %i\n"
				"tcpsize = %i\n"
				"udpsize = %i\n"
				"uid = %i\n"
				"gid = %i\n", write_to_syslog, banafter, tcpports_size, udpports_size, uid, gid );
		printf( "banstring = %s\n", banstring );
		for( i = 0; i <= tcpports_size; i++ ) printf( "tcpports[%i] = %i\n", i, tcpports[i] );
		for( i = 0; i <= udpports_size; i++ ) printf( "udpports[%i] = %i\n", i, udpports[i] );
		printf( " --- [ DEBUG ] --- " );
	#endif

	// weird stuff with asynch sockets
	struct ip *iphdrs;
	fd_set master, read_fds;
	int fdmax;

	FD_ZERO( &master );
	FD_ZERO( &read_fds );

	// Linux lets app to read rawsock data without binding to port, to do the same
	// in BSD it's necessary to set up diverted sockets.
	#ifdef BSD
		char ipfw_cmd[64];
		for( i = 0; i <= tcpports_size; i++ ) {
			sprintf( ipfw_cmd, "ipfw -q add %i divert %i tcp from any to any %i in", ipfw_divertedsock_rulenum, ipfw_divertedsock_port, tcpports[i] );
			system( ipfw_cmd );
			memset( ipfw_cmd, '\0', sizeof(ipfw_cmd) );
		}
		
		for( i = 0; i <= udpports_size; i++ ) {
			sprintf( ipfw_cmd, "ipfw -q add %i divert %i udp from any to any %i in", ipfw_divertedsock_rulenum, ipfw_divertedsock_port, udpports[i] );
			system( ipfw_cmd );
			memset( ipfw_cmd, '\0', sizeof(ipfw_cmd) );
		}

		int sockfddivert;
		if( ( sockfddivert = socket( AF_INET, SOCK_RAW, IPPROTO_DIVERT ) ) == -1 ) {
			pinfo( "Divert socket error", write_to_syslog );
			sprintf( ipfw_cmd, "ipfw delete %i", ipfw_divertedsock_rulenum );
			system( ipfw_cmd );
			return -1;
		}
		// fcntl(sockfddivert, F_SETFL, O_NONBLOCK);

		struct sockaddr_in ds_sin;
		ds_sin.sin_family = AF_INET;
		ds_sin.sin_port = htons( ipfw_divertedsock_port );
		ds_sin.sin_addr.s_addr = htonl( INADDR_ANY );
		if( bind( sockfddivert, (struct sockaddr*)&ds_sin, sizeof(struct sockaddr_in) ) == -1 ) {
			pinfo( "Divert socket bind() error", write_to_syslog );
			sprintf( ipfw_cmd, "ipfw delete %i", ipfw_divertedsock_rulenum );
			system( ipfw_cmd );
			return -1;
		}
		fdmax = sockfddivert;
		FD_SET( sockfddivert, &master );
	#else
		int tcpp, udpp;
		int sockfdudp, sockfdtcp;
		if( ( sockfdtcp = socket( PF_INET, SOCK_RAW, IPPROTO_TCP ) ) == -1 ){
			pinfo( "TCP socket error", write_to_syslog );
			return -1;
		} // tcp socket create
		fcntl( sockfdtcp, F_SETFL, O_NONBLOCK );

		if( ( sockfdudp = socket( PF_INET, SOCK_RAW, IPPROTO_UDP ) ) == -1 ) {
			pinfo( "UDP socket error", write_to_syslog );
			return -1;
		} // udp socket create
		fcntl( sockfdudp, F_SETFL, O_NONBLOCK );

		if( sockfdudp > sockfdtcp ) {
			fdmax = sockfdudp;
		} else {
			fdmax = sockfdtcp;
		} // set fdmax

		FD_SET( sockfdudp, &master );
		FD_SET( sockfdtcp, &master );
	#endif

	// signal handling
	signal( SIGINT, breakwhile );
	signal( SIGQUIT, breakwhile );
	signal( SIGUSR1, reload_config );

	setregid( gid, gid );
	setgroups( 0, NULL );
	setreuid( uid, uid );

	pinfo( "Daemon running.", write_to_syslog );

	char buffer[8192];	// buffer for socks data
	while( while_arg == 0 ) {	// main loop
	
		read_fds = master;
		if( select( fdmax+1, &read_fds, NULL, NULL, NULL ) == -1 ) {
			if( while_arg == 0 ) {
				pinfo("select() error", write_to_syslog);
			}
			continue;
		} // select()

		for( i = 3; i <= fdmax; i++ ) {
		
			if( FD_ISSET(i, &read_fds) ) {
			
				read( i, buffer, 8192 );
				iphdrs = (struct ip*)( buffer );
				char* soip = inet_ntoa( iphdrs->ip_src );

				// Is IP on the whitelist?
				if( whitelist_ip_ctr != 0 ) {
					if( ip_in_array( whitelist_ip, soip, whitelist_ip_ctr ) != -1 ) {
						continue;
					}
				}

				#ifdef BSD
					if( i == sockfddivert ) {
						portknocked = 1;
					}
				#else
					if( i == sockfdtcp ) {
						struct tcphdr *tcphdrs;
						tcphdrs = (struct tcphdr*)( buffer + sizeof(struct ip) );
						tcpp = ntohs( tcphdrs->dest );
						if( in_arr( tcpp, tcpports, tcpports_size ) == 0 ) {
							#ifdef DEBUG
								printf( "[DEBUG][TCP] %s:%i\n", soip, tcpp );
							#endif
							portknocked = 1;	// TCP connection
						} // ports
					} // sockfdtcp

					if( i == sockfdudp ) {
						struct udphdr *udphdrs;
						udphdrs = (struct udphdr*)( buffer + sizeof(struct ip) );
						udpp = ntohs( udphdrs->dest );
						if( in_arr( udpp, udpports, udpports_size ) == 0 ) {
							#ifdef DEBUG
								printf( "[DEBUG][UDP] %s:%i\n", soip, udpp );
							#endif
							portknocked = 1;	// UDP connection
						} // ports
					} // sockfdudp
				#endif

				if( portknocked == 1 ) {
					if( maxipnum == 0 ) {	// index of the last array elem is zero, init the array and add new IP
						iparr = malloc( sizeof(char*) );
						iparr[maxipnum] = malloc( strlen(soip) + 1 );
						sprintf( iparr[maxipnum], "%s", soip );
						hitarr = malloc( sizeof(int*) );
						hitarr[maxipnum] = 1;
						maxipnum += 1;
					} else {	// there is something in arr
						ipindex = ip_in_array( iparr, soip, maxipnum );
						if( ipindex == -1 ) {	// no connecting IP, add it
							iparr = realloc( iparr, ( maxipnum * sizeof(char*) ) + sizeof(char*) );
							iparr[maxipnum] = malloc( strlen(soip) + 1 );
							sprintf( iparr[maxipnum], "%s", soip );
							hitarr = realloc( hitarr, ( maxipnum * sizeof(int*) ) + sizeof(int*) );
							hitarr[maxipnum] = 1;
							maxipnum += 1;
						} else {	// connecting IP already in arr, increment connection counter
							hitarr[ipindex] += 1;
							if( hitarr[ipindex] >= banafter ) {
								size = parsebanstring_size( banstring, soip );
								if( size == -1 ) {
									pinfo( "{IPNUM} not found in banstring!", write_to_syslog );
									while_arg = 1;
									continue;
								}
								cmd = malloc( size );
								parsebanstring( banstring, soip, cmd, size );
								msg = malloc( 28 + strlen(soip) + strlen(cmd) + 1 );	// 28 - info text len
								sprintf( msg, "Banning IP %s with command \"%s\"", soip, cmd );
								pinfo( msg, write_to_syslog );
								free( msg );
								/////////////////////////////////////////////////// system(cmd);
								free( cmd );
							} // hitarr >= banafter

							if( maxipnum >= IP_ARRAY_LIMIT ) {	// max arr size exceeded, clear
								for( i = 0; i < maxipnum; i++ ) {
									free( iparr[i] );
								} // for i
								free( iparr );
								free( hitarr );
								maxipnum = 0;
							} // maxipnum = IP_ARRAY_LIMIT
						} // if ip in array
					}
					portknocked = 0;
				}
			} // if [ FD_ISSET ]
		} // for [ i ]
	} // while true

	// cleanin'
	if( whitelist_ip_ctr != 0 ) {
		for( i = 0; i < whitelist_ip_ctr; i++ ) {
			free( whitelist_ip[i] );
		}
		free( whitelist_ip );
	}
	if( maxipnum != 0 ) {
		for( i = 0; i < maxipnum; i++ ) {
			free( iparr[i] );
		} // for i
		free( iparr );
		free( hitarr );
	}

	#ifdef BSD
		sprintf( ipfw_cmd, "ipfw delete %i", ipfw_divertedsock_rulenum );	// delete the diverted sockets rule
		system( ipfw_cmd );
	#endif

	pinfo( "Shutting down.", write_to_syslog );

	return 0;	// returns 0
} // main

void breakwhile( int sig ) {
	if(sig == SIGINT || sig == SIGQUIT) while_arg = 1;
}

void reload_config( int sig ) {
	if(sig == SIGUSR1) read_config();
}

// - ende -