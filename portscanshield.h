/*!
	\file portscanshield.h
	\brief Main portscanshield code. Handles initialization, new connections (port knocks) and
			main daemon work.
*/

#ifndef __PORTSCANSHIELD_H__
#define __PORTSCANSHIELD_H__

#include "pss_config.h"

// #define BANSTRING_NOEXEC //!< Don't really execute banstring

#define MAX_EPOLL_EVENTS 128

/*!
	\brief Protocol type enum.
*/
enum protocols_type { P_TCP, P_UDP };

/*!
	\brief Drops root rights to UID and GID specified in config file.
*/
void pss_drop_rights( void );

/*!
	\brief Executes ban command, specified in config file.
	\param ip IP to ban.
*/
void ban_ip( const char *ip );

/*!
	\brief Setups two raw sockets for TCP and UDP, used to sniff port knocks.
	\param sniff_sockfd_tcp, sniff_sockfd_udp Newly created sniffing sockets will be placed under those addresses.
*/
void pss_setup_sniff_sockets( int *sniff_sockfd_tcp, int *sniff_sockfd_udp );

/*!
	\brief Main portscanshield loop.
*/
void pss_run( void );

#endif
