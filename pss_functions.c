#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "pss_functions.h"
#include "config.h"

// Search for int in haystack
int in_arr( int needle, int haystack_arr[], int size ) {
	int i;
	for( i = 0; i <= size; i++ ) {
		if( needle == haystack_arr[i] ) {
			return 0;
		}
	}
	return 1;
}

// get value size from conf
int cutfield_size( char* fieldname, char* string ) {
	unsigned int j = 0, stop = 0;
	char fname[strlen(fieldname) + 2];
	sprintf( fname, "%s%c", fieldname, ':' );

	char *ptr;
	if( ( ptr = strstr( string, fname ) ) != NULL ) {
		if( ptr[strlen(fname)] == ' ' ) {
			ptr += strlen(fname) + 1;
		} else {
			ptr += strlen(fname);
		}
		for( j = 0; j < strlen(ptr); j++ ) {
			if( ptr[j] == ';' || ptr[j] == '\n' ) {
				stop = j;
				break;
			}
		}
		return ( stop + 1 );
    }
	return -1;
}

// get value from conf
int cutfield( char* fieldname, char* string, char* retstr, int size ) {
	char fname[strlen(fieldname) + 2];
	sprintf( fname, "%s%c", fieldname, ':');

	char *ptr;
	if( ( ptr = strstr( string, fname ) ) != NULL ) {
		if( ptr[strlen(fname)] == ' ' ) {
			ptr += strlen(fname) + 1;
		} else {
			ptr += strlen(fname);
		}
		memset( retstr, '\0', size );
		strncpy( retstr, ptr, size - 1 );
    }
	return 0;
}

// Is ip in arr?
int ip_in_array( char** arr, char* ip, int arrsize ) {
	int i;
	for( i = 0; i < arrsize; i++ ) {
		if( strcmp( arr[i], ip ) == 0 ) {
			return i;
		} // if arr == ip
	} // for [ i ]
	return -1;
}

// replace {IPNUM} with ip and return size
int parsebanstring_size( char* banstring, char* ip ) {
	if( strstr( banstring, "{IPNUM}" ) == NULL ) {
		return -1;
	}
	return ( strlen(banstring) - 7 + strlen(ip) - 1 );	// 7 - {IPNUM}
}

// replace {IPNUM} with ip
int parsebanstring( char* banstring, char* ip, char* retstr, int size ) {
	char *ptr = NULL;
	if( ( ptr = strstr( banstring, "{IPNUM}" ) ) != NULL ) {
		ptr += 7;
	} // strstr

	int dl2 = ( strlen(banstring) - 7 - strlen(ptr) );
	memset( retstr, '\0', size );
	int i = 1;
	for( i = 1; i < size; i++ ) {
		if( i < dl2 ) {
			(retstr)[i-1] = banstring[i];
		}
		if ( i >= dl2 && i < (int)( strlen(ip) + dl2 ) ) {
			strcat( retstr, ip );
			i += ( strlen(ip) - 1 );
			continue;
		}
		if( i > dl2 ) {
			(retstr)[i-1] = ptr[ i - ( dl2 + strlen(ip) ) ];
		}
	}
	return 0;
}

// write to syslog ( private function invoked by pinfo )
int wtosyslog( char* msg ) {
	openlog( APPNAME, LOG_CONS, LOG_DAEMON );
	syslog( LOG_MAKEPRI( LOG_DAEMON, LOG_NOTICE ), msg );
	closelog();
	return 0;
}

// print info to stdout / syslog
int pinfo( char* msg, int wts ) {
	// wts - write to syslog
	if( wts == 0 ) {
		wtosyslog( msg );
	} else {
		printf( "%s\n", msg );
	}
	return 0;
}

// config read
int read_config(void) {

	extern int write_to_syslog;
	extern int banafter;
	extern char* banstring;
	extern int* tcpports;
	extern int* udpports;
	extern int uid;
	extern int gid;
	extern char** whitelist_ip;
	extern int tcpports_size;
	extern int udpports_size;

	int whitelist_ip_ctr = 0, i = 0, size = 0;

	// ---------------------------------------------------- read config
	// lock file (?)
	FILE* fd = fopen( CONFIG_FILE, "r" );
	char c;
	while( ( c = fgetc(fd) ) != -1 ) { i++; }

	fseek( fd, 0, 0 );
	char filestr[i+1];
	memset( filestr, '\0', i+1 );
	i = 0;
	while( ( c = fgetc( fd ) ) != -1 ) {
		if( c == '#' ) {	// comments gtfo
			while( c != '\n' && !feof( fd ) ) {
				c = fgetc( fd );
			}
		}
		filestr[i] = c;
		i++;
	}
	fclose( fd );

	size = cutfield_size( "write_to_syslog", filestr );
	if( size == -1 ) {
		write_to_syslog = 1;	// default
		pinfo( "Field \"write_to_syslog\" not found in config file!", write_to_syslog );
	} else {
		char* write_to_syslog_str = malloc( size );
		cutfield( "write_to_syslog", filestr, write_to_syslog_str, size );
		if( strcmp( write_to_syslog_str, "false" ) == 0 ) {
			write_to_syslog = 1;
		}
		free( write_to_syslog_str );
	}

	size = -1;
	size = cutfield_size( "ban_after", filestr );
	if( size == -1 ) {
		pinfo( "Field \"ban_after\" not found in config file!", write_to_syslog );
		banafter = 5;	// default
	}
	char* ban_after = malloc( size );
	cutfield( "ban_after", filestr, ban_after, size );
	banafter = atoi( ban_after );
	free( ban_after );

	size = cutfield_size( "banstring", filestr );
	if( size == -1 ) {
		pinfo( "Field \"banstring\" not found in config file!", write_to_syslog );
		return -1;
	}

	banstring = malloc( size );
	cutfield( "banstring", filestr, banstring, size );

	size = cutfield_size( "tcpports", filestr );
	if( size == -1 ) {
		pinfo( "Field \"tcpports\" not found in config file!", write_to_syslog );
		return -1;
	}
	char* tcpstr = malloc( size );
	cutfield( "tcpports", filestr, tcpstr, size );
	int counter = 0;
	for( i = 0; i < size; i++ ) {
		if( tcpstr[i] == ' ' ) {
			counter++;
		}
	}

	tcpports_size = counter;
	tcpports = malloc( counter * sizeof(int) );
	char *port = NULL;
	port = strtok( tcpstr, " " );
	(tcpports)[0] = atoi( port );
	i = 1;
	for( i = 1; i <= counter; i++ ) {
		port = strtok( NULL, " " );
		tcpports[i] = atoi( port );
	}
	free( tcpstr );

	size = cutfield_size( "udpports", filestr );
	if( size == -1 ) {
		pinfo( "Field \"udpports\" not found in config file!", write_to_syslog );
		return -1;
	}
	char* udpstr = malloc( size );
	cutfield( "udpports", filestr, udpstr, size );
	counter = 0;
	for( i = 0; i < size; i++ ) {
		if( udpstr[i] == ' ' ) {
			counter++;
		}
	}

	udpports_size = counter;
	// /////////////////////////////////////////////////// int udpports[counter];
	udpports = malloc( counter * sizeof(int) );
	char *uport = NULL;
	uport = strtok( udpstr, " " );
	(udpports)[0] = atoi( uport );
	i = 1;
	for( i = 1; i <= counter; i++ ) {
		uport = strtok( NULL, " " );
		udpports[i] = atoi( uport );
	}
	free( udpstr );

	size = cutfield_size( "uid", filestr );
	if( size == -1 ) {
		pinfo( "Field \"uid\" not found in config file! Setting UID to 0.", write_to_syslog );
		uid = 0;
	} else {
		char* uidstr = malloc( size );
		cutfield( "uid", filestr, uidstr, size );
		uid = atoi( uidstr );
		free( uidstr );
	}

	size = cutfield_size( "gid", filestr );
	if( size == -1 ) {
		pinfo( "Field \"gid\" not found in config file! Setting GID to 0.", write_to_syslog );
		gid = 0;
	} else {
		char* gidstr = malloc( size );
		cutfield( "gid", filestr, gidstr, size );
		gid = atoi( gidstr );
		free( gidstr );
	}

	size = cutfield_size( "whitelist", filestr );
	if( size == -1 ) {
		pinfo( "Field \"whitelist\" not found in config file!", write_to_syslog );
	} else {
		char* whitelist_str = malloc( size );
		cutfield( "whitelist", filestr, whitelist_str, size );
		char* ptr = strtok( whitelist_str, " " );
		while( ptr != NULL ) {
			if( whitelist_ip_ctr == 0 ) {
				whitelist_ip = malloc( sizeof(char*) );
			} else {
				whitelist_ip = realloc( whitelist_ip, ( sizeof(char*) * whitelist_ip_ctr ) + sizeof(char*) );
			}
			whitelist_ip[whitelist_ip_ctr] = malloc( strlen(ptr) + 1 );
			sprintf( whitelist_ip[whitelist_ip_ctr], ptr );
			whitelist_ip_ctr++;
			ptr = strtok( NULL, " " );
		}
		free( whitelist_str );
	}

	#ifdef BSD
		size = cutfield_size( "ipfw_divertedsock_rulenum", filestr );
		if( size == -1 ) {
			pinfo( "Field \"ipfw_divertedsock_rulenum\" not found in config file!", write_to_syslog );
			return -1;
		} else {
			char ipfw_divertedsock_rulenum_str[size];
			cutfield( "ipfw_divertedsock_rulenum", filestr, ipfw_divertedsock_rulenum_str, size );
			ipfw_divertedsock_rulenum = atoi( ipfw_divertedsock_rulenum_str );
		}

		size = cutfield_size( "ipfw_divertedsock_port", filestr );
		if( size == -1 ) {
			pinfo( "Field \"ipfw_divertedsock_port\" not found in config file!", write_to_syslog );
			return -1;
		} else {
			char ipfw_divertedsock_port_str[size];
			cutfield( "ipfw_divertedsock_port", filestr, ipfw_divertedsock_port_str, size );
			ipfw_divertedsock_port = atoi( ipfw_divertedsock_port_str );
		}
	#endif
	return 0;
	// ---------------------------------------------------- config read end
}

// - ende -