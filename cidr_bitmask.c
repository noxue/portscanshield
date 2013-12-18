/*!
	\file cidr_bitmask.c
*/

#include "cidr_bitmask.h"
#include "pss_log.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

uint32_t cidr_to_bitmask( uint8_t cidr ) {

	if( cidr >= 31 ) { // Two lsb are reserved.
		pss_fatal( "Can't set bitmask equal or greater than 31! Tried to set bitmask 0x%.2x (%u).\n", cidr, cidr );
	}

	return (uint32_t)0xFFFFFFFF << (32 - cidr);

}

uint32_t ip_to_uint( const char *ip ) {
	
	struct in_addr iaddr;
	inet_pton( AF_INET, ip, &iaddr );
	
	return ntohl( iaddr.s_addr );

}

char *uint_to_ip( uint32_t ip ) {

	struct in_addr iaddr;
	iaddr.s_addr = htonl( ip );
	char *ret = malloc( INET_ADDRSTRLEN );
	memset( ret, 0x00, INET_ADDRSTRLEN );
	inet_ntop( AF_INET, &iaddr, ret, INET_ADDRSTRLEN );

	return ret;

}
