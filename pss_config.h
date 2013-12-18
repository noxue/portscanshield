/*!
	\file pss_config.h
	\brief Functions used to parse, verify and handle config file and structure.
*/

#ifndef __PSS_CONFIG_H__
#define __PSS_CONFIG_H__

#include "vector_template/vector_template.h"
#include <stdint.h>

//!< Tag that will be replaced (in banstring) with IP that exceeded max knock count time.
#define BANSTRING_IP_TAG "{IPNUM}"

#define VECTOR_GETINT( vector_ptr, index ) ( *(int *)vector_get( vector_ptr, index ) )

#define BITMASK_NOT_SET 0x01 //!< LSB set - mask is invalid. Using it as not_set info.

/*!
	\brief Port range structure.
*/
struct port_range {
	int start;
	int end;
};

/*!
	\brief IP and mask structure. Used in whitelists.
*/
struct ip_mask {
	uint32_t ip; //!< IP (whitelisted)
	uint32_t mask; //!< Bitmask for IP.
};

/*!
	\brief portscanshield configuration structure.
*/
struct pss_config_vars {
	struct vector *ip_whitelist; //!< Vector of whitelisted IPs (struct ip_mask).
	struct vector *tcp_trap_ports; //!< Vector of TCP ports that are observed.
	struct vector *udp_trap_ports; //!< Vector of UDP ports that are observed.
	char *ban_cmd; //!< Command to execute on IP, when it exceeds it's knock limit. Must contain BANSTRING_IP_TAG.
	int write_to_syslog; //!< 0 if portscanshield should write to syslog, 1 otherwise.
	int uid, gid; //!< UID and GID to which portscanshield should drop it's rights.
	int max_knock_count; //!< Max port knocks for one IP.
};

/*!
	\brief Parse config file, set conf structure with retrieved vars.
	\param conffile Path & name of config file.
	\param config PSS config structure to fill.
*/
void parse_config( const char *conffile, struct pss_config_vars *config );

/*!
	\brief Copies src configuration struct to dest. Used in SIGUSR1 signal handler, to reload config file.
	\param dest, src Destination and source structures to copy.
*/
void copy_config_vars( struct pss_config_vars *dest, struct pss_config_vars *src );

/*!
	\brief Prints config vars.
	\param config portscanshield configuration struct.
*/
void print_config_vars( const struct pss_config_vars *config );

/*!
	\brief Frees memory allocated for portscanshield conf struct.
	\param config portscanshield conf struct to free.
*/
void free_config( struct pss_config_vars *config );

#endif
