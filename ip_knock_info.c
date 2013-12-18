/*!
	\file ip_knock_info.c
*/

#include "ip_knock_info.h"
#include "portscanshield.h"
#include "pss_log.h"
#include "cidr_bitmask.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

extern volatile struct pss_config_vars pss_configuration;

void *ip_knocked_info_create( const char *ip ) {

	assert( ip != NULL );

	struct ip_knocked_info *r = malloc( sizeof(struct ip_knocked_info) );
	r->ip = ip_to_uint( ip );
	r->knock_count = 0;

	return r;

}

int ip_knocked_info_cmp( void *el1, void *el2 ) {

	if( el1 == NULL || el2 == NULL ) return 0;

	struct ip_knocked_info *k1 = el1, *k2 = el2;
	return ( k1->ip == k2->ip ) ? 1 : 0;

}

void ip_knocked_handle( struct vector *ip_knock_stats, const char *ip ) {

	assert( ip_knock_stats != NULL && ip != NULL );

	struct ip_knocked_info to_find;
	to_find.ip = ip_to_uint( ip );

	int index = vector_search( ip_knock_stats, &to_find, ip_knocked_info_cmp );

	if( index != -1 ) {

		// IP already knocked, check if it should be banned.
		struct ip_knocked_info *knock_info = vector_get( ip_knock_stats, index );
		if( knock_info->knock_count > pss_configuration.max_knock_count ) {
			ban_ip( ip );
			vector_delete_el( ip_knock_stats, index, free );
		} else {
			++knock_info->knock_count;
		}

	} else {

		// IP knocked for the first time, add to vector.
		vector_add( ip_knock_stats, ip_knocked_info_create( ip ) );

	}

}

/*!
	\brief Check if port is in specified in specified port_range.
	\param port Port to check.
	\param p_range Void pointer to port_range struct.
	\return 1 if port is in specified port range, 0 if not.
*/
static int port_in_range( void *port, void *p_range ) {

	if( port == NULL || p_range == NULL ) return 0;

	struct port_range *pr = p_range;

	if( pr->end == -1 ) return ( *(int *)port == pr->start ) ? 1 : 0;

	return ( *(int *)port <= pr->end && *(int *)port >= pr->start ) ? 1 : 0;

}

/*!
	\brief Compares two IP's, respecting bitmask stored in ip_mask_strct.
			Used while checking if IP is in whitelist.
	\param ip IP to compare.
	\param ip_mask_strct Void pointer to ip_mask struct.
	\return 1 if IP is equal to ip_maks_strct's ip, 0 otherwise.
*/
static int ip_bitmask_cmp( void *ip, void *ip_mask_strct ) {

	if( ip == NULL || ip_mask_strct == NULL ) return 0;

	struct ip_mask *ip_m = ip_mask_strct;
	uint32_t knock_ip = ip_to_uint( (const char *)ip );

	if( ip_m->mask != BITMASK_NOT_SET ) {
		return ( (knock_ip & ip_m->mask) == ( ip_m->ip & ip_m->mask ) ) ? 1 : 0;
	} else {
		return ( knock_ip == ip_m->ip ) ? 1 : 0;
	}

}

void ip_knocked( const char *ip, int port, struct vector *knock_stats, int prot_type ) {

	assert( ip != NULL && knock_stats != NULL );

	static int knock_no = 0;

	/* When IP is banned, it is deleted from vector. To not waste to much memory,
	shrink them to minimum size, everytime the counter knock_no hits specified number. */
	if( knock_no % SHRINK_VECTORS_EVERY_N_KNOCKS == 0 ) {
		vector_shrink_to_fit( knock_stats );
	}

	++knock_no;

	if( vector_search( pss_configuration.ip_whitelist, (void *)ip, ip_bitmask_cmp ) != -1 ) {
		return; // Ip whitelisted, ignore.
	}

	// Check if port is specified in config, if yes - take care of the IP.
	if( prot_type == P_TCP ) {

		if( vector_search( pss_configuration.tcp_trap_ports, &port, port_in_range ) != -1 ) {
			ip_knocked_handle( knock_stats, ip );
		}

	} else if( prot_type == P_UDP ) {

		if( vector_search( pss_configuration.udp_trap_ports, &port, port_in_range ) != -1 ) {
			ip_knocked_handle( knock_stats, ip );
		}

	} else {
		pss_log( "Wrong parameter passed to ip_knocked() function.\n" );
	}

}
