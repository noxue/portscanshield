/*!
	\file cidr_bitmask.h
	\brief Functions used to calculate CIDR bitmask and make it useful.
*/

#ifndef __CIDR_BITMASK_H__
#define __CIDR_BITMASK_H__

#include <stdint.h>

/*!
	\brief Convert CIDR to bitmask.
	\param cidr CIDR. Have to be less than 31.
	\return CIDR converted to bitmask.
*/
uint32_t cidr_to_bitmask( uint8_t cidr );

/*!
	\brief Converts IP string to 32bit unsigned integer.
	\param ip string ip.
	\return String IP converted to 32bit unsigned integer.
*/
uint32_t ip_to_uint( const char *ip );

/*!
	\brief Converts 32bit int IP to string IP.
	\param ip unsigned 32bit integer representation of IP.
	\return 32bit int converted to string IP.
*/
char *uint_to_ip( uint32_t ip );

#endif
