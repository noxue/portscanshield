/*!
	\file pss_config.c
*/

#include "pss_config.h"
#include "portscanshield.h"
#include "pss_log.h"
#include "cidr_bitmask.h"
#include <confuse.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*!
	\brief Initialize portscanshield conf.
*/
static void initialize_vars( struct pss_config_vars *vars ) {

	assert( vars != NULL );
	
	vars->ip_whitelist = vector_create();
	vars->tcp_trap_ports = vector_create();
	vars->udp_trap_ports = vector_create();
	vars->ban_cmd = NULL;
	vars->write_to_syslog = 0;
	vars->uid = 0;
	vars->gid = 0;
	vars->max_knock_count = 0;

}

/*!
	\brief Check if there is BANSTRING_IP_TAG in ban_cmd.
	\param ban_cmd Ban cmd, retrieved from config file.
*/
static void validate_bancmd( const char *ban_cmd ) {

	if( strstr( ban_cmd, BANSTRING_IP_TAG ) == NULL ) {
		pss_fatal( "{IPNUM} not found in config file!\n" );
	}

}

/*!
	\brief Parse string specifying port range from config file to port_range structure.
	\param str_port String specifying port range, in format num-num or num.
			E.g. 5-15 - ports 5 to 15 (including 5 and 15), 20 - only one port, 20.
	\return port_range struct created based on str_port. If only one port specified, port_range's
			end port is -1.
*/
static struct port_range *str_to_port_range( const char *str_port ) {

	struct port_range *new_range = malloc( sizeof(struct port_range) );

	new_range->start = atoi( str_port );

	char *p = strchr( str_port, '-' );
	if( p != NULL ) {

		char *port_range_str = (char *)str_port;
		port_range_str += p - str_port + 1; //!< Move pointer to after '-' (range end port)
		new_range->end = atoi( port_range_str );

		if( new_range->start > new_range->end ) {
			pss_fatal( "Wrong ports range! %d (end) is less than %d (start)\n", new_range->end, new_range->start );
		}

	} else {
		new_range->end = -1;
	}

	return new_range;

}

/*!
	\brief Parse string from config file specyfying (whitelisted) IP and it's bit mask.
	\param ip_w_cidr IP with (or without if unused) CIDR notation (IPNUM/CIDR, eg 127.0.0.1/25).
	\return ip_mask structure, created based on ip_w_cidr. If CIDR notation not used,
			ip_mask's mask field is set to BITMASK_NOT_SET.
*/
static struct ip_mask *str_to_ip_mask( const char *ip_w_cidr ) {

	assert( ip_w_cidr != NULL );

	struct ip_mask *new_ip_mask = malloc( sizeof(struct ip_mask) );

	char *p = strchr( ip_w_cidr, '/' );
	if( p != NULL ) {

		int ip_strlen = p - ip_w_cidr + 1;

		char *ip_str = malloc( ip_strlen );

		strncpy( ip_str, ip_w_cidr, ip_strlen );
		ip_str[ ip_strlen-1 ] = '\0';

		new_ip_mask->ip = ip_to_uint( ip_str );
		new_ip_mask->mask = cidr_to_bitmask( atoi( p + 1 ) );

		free( ip_str );

	} else {

		new_ip_mask->ip = ip_to_uint( ip_w_cidr );
		new_ip_mask->mask = BITMASK_NOT_SET;

	}

	return new_ip_mask;

}

void parse_config( const char *conffile, struct pss_config_vars *vars ) {

	assert( conffile != NULL && vars != NULL );

	FILE *fp = NULL;
	if( ( fp = fopen( conffile, "r" ) ) == NULL ) {
		pss_fatal( "File %s does not exist!\n", conffile );
	} else {
		fclose( fp );
	}
	
	initialize_vars( vars );

	cfg_opt_t pss_config_opts[] = {
		CFG_STR_LIST( "tcp_trap_ports", "{}", CFGF_NONE ),
		CFG_STR_LIST( "udp_trap_ports", "{}", CFGF_NONE ),
		CFG_STR_LIST( "whitelist", "{}", CFGF_NONE ),
		CFG_INT( "max_knock_count", 5, CFGF_NONE ),
		CFG_INT( "uid", 0, CFGF_NONE ),
		CFG_INT( "gid", 0, CFGF_NONE ),
		CFG_STR( "banstring", NULL, CFGF_NONE ),
		CFG_BOOL( "write_to_syslog", cfg_true, CFGF_NONE ),
		CFG_END()
	};

	cfg_t *cfg = cfg_init( pss_config_opts, CFGF_NONE );

	if( cfg_parse( cfg, conffile ) == CFG_PARSE_ERROR ) {
		pss_fatal( "Config file parse error!\n" );
		exit(-1);
	}
	
	unsigned int i = 0;
	
	struct ip_mask *new_ip_mask;
	for( i = 0; i < cfg_size( cfg, "whitelist" ); ++i ) {
		char *str = cfg_getnstr( cfg, "whitelist", i );
		new_ip_mask = str_to_ip_mask( str );
		vector_add( vars->ip_whitelist, new_ip_mask );
	}
	
	struct port_range *new_port_r = NULL;

	for( i = 0; i < cfg_size( cfg, "tcp_trap_ports" ); ++i ) {
		new_port_r = str_to_port_range( cfg_getnstr( cfg, "tcp_trap_ports", i ) );
		vector_add( vars->tcp_trap_ports, new_port_r );
	}
	
	for( i = 0; i < cfg_size( cfg, "udp_trap_ports" ); ++i ) {
		new_port_r = str_to_port_range( cfg_getnstr( cfg, "udp_trap_ports", i ) );
		vector_add( vars->udp_trap_ports, new_port_r );
	}

	vars->ban_cmd = strdup( cfg_getstr( cfg, "banstring" ) );
	validate_bancmd( vars->ban_cmd );
	
	vars->uid = cfg_getint( cfg, "uid" );
	vars->gid = cfg_getint( cfg, "gid" );
	vars->max_knock_count = cfg_getint( cfg, "max_knock_count" );
	vars->write_to_syslog = ( cfg_getbool( cfg, "write_to_syslog" ) == cfg_true ? 1 : 0 );

	cfg_free( cfg );

}

void copy_config_vars( struct pss_config_vars *dest, struct pss_config_vars *src ) {

	assert( dest != NULL && src != NULL );

	free_config( dest );

	*dest = *src;

}

/*!
	\brief Print port, used as vector_map() param.
	\param port Void pointer to (int) port to print.
*/
static void print_ports( void *port ) {

	assert( port != NULL );

	struct port_range *pr = port;
	( pr->end == -1 ) ? printf( "%d ", pr->start ) : printf( "%d-%d ", pr->start, pr->end ); ;

}

/*!
	\brief Prints specified IP, used as vector_map() param.
	\param ip IP to print.
*/
static void print_whitelist( void *ip ) {

	assert( ip != NULL );

	struct ip_mask *p = ip;
	char *ip_str = uint_to_ip( p->ip );
	printf( "   - %.8x (%s)", p->ip, ip_str );
	free( ip_str );

	if( p->mask != BITMASK_NOT_SET ) printf( ", mask: %.8x", p->mask );
	printf( "\n" );

}

void print_config_vars( const struct pss_config_vars *config ) {

	assert( config != NULL );
	assert( config->ip_whitelist != NULL && config->tcp_trap_ports != NULL && config->udp_trap_ports != NULL );

	printf( "portscanshield configuration:\n" );

	printf( "-> Whitelisted IPs: \n" );
	vector_map( config->ip_whitelist, print_whitelist );

	printf( "-> TCP trap ports: " );
	vector_map( config->tcp_trap_ports, print_ports );
	printf( "\n" );

	printf( "-> UDP trap ports: " );
	vector_map( config->udp_trap_ports, print_ports );
	printf( "\n" );

	printf( "-> Ban command: %s\n", config->ban_cmd );

	printf( "-> Writing to syslog: %s\n", config->write_to_syslog == 1 ? "yes" : "no" );

	printf( "-> Rights dropped to: uid %d, gid %d\n", config->uid, config->gid );

	printf( "-> Max trap ports knock for one IP: %d\n", config->max_knock_count );

	printf( "End portscanshield configuration.\n\n" );

}

void free_config( struct pss_config_vars *config ) {

	assert( config != NULL );

	struct vector *tmp = config->ip_whitelist;
	vector_free( &tmp, free );

	tmp = config->tcp_trap_ports;
	vector_free( &tmp, free );

	tmp = config->udp_trap_ports;
	vector_free( &tmp, free );

	free( config->ban_cmd );

}
