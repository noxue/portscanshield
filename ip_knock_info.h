/*!
	\file ip_knock_info.h
	\brief Set of functions used to handle knocking IPs.
*/

#ifndef __IP_KNOCK_INFO_H__
#define __IP_KNOCK_INFO_H__

#include "vector_template/vector_template.h"
#include <stdint.h>

#define SHRINK_VECTORS_EVERY_N_KNOCKS 5000 //!< Shrink vectors to minimum size every N knocks.

/*!
	\brief Struct stores information, how many times IP tried to knock.
*/
struct ip_knocked_info {
	uint32_t ip; //!< Knocking IP.
	int knock_count; //!< Number of IP knocks.
};

/*!
	\brief Initialize ip_knocked_info struct based on IP.
	\param ip IP to put into ip_knocked_info (string will be duplicated).
	\return Void pointer to new ip_knocked_info structure.
*/
void *ip_knocked_info_create( const char *ip );

/*!
	\brief Compares two ip_knocked_info structures. Used as a vector_search() comparing function.
	\param el1, el2 ip_knocked_info structures to compare.
	\return 1 if el1 is equal to el2, 0 if not.
*/
int ip_knocked_info_cmp( void *el1, void *el2 );

/*!
	\brief Check's if ip is in ip_knock_stats, if not - adds it, if it is - increments it knock_count.
			If knock_count limit has exceeded, executes ban command.
	\param ip_knock_stats Vector of IP that knocked.
	\param ip Detected knocking IP.
*/
void ip_knocked_handle( struct vector *ip_knock_stats, const char *ip );

/*!
	\brief Handles whitelisting and vector shrinking (if some of elems were deleted).
			Uses, different port list (tcp/udp), based on prot_type.
	\param ip Detected knocking IP.
	\param port Port to which IP knocked.
	\param knock_stats Knocking IPs stats, different for tcp/udp.
	\param prot_type Protocol type, enum protocols_type, defined in portscanshield.h.
*/
void ip_knocked( const char *ip, int port, struct vector *knock_stats, int prot_type );

#endif
