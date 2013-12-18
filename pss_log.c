/*!
	\file pss_log.c
*/

#include "pss_log.h"
#include "pss_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <syslog.h>

extern volatile struct pss_config_vars pss_configuration;

/*!
	\brief Writes log to syslog/stdout, depending on config settings.
	\param syslog_prior Priority passed to vsyslog() function.
	\param format printf() style message format to log.
	\param args va_list args.
*/
static void vpss_log( int syslog_prior, const char *format, va_list args ) {

	assert( format != NULL );

	if( pss_configuration.write_to_syslog == 0 ) {
		vprintf( format, args );
	} else {
		openlog( SYSLOG_APPNAME, LOG_CONS | LOG_NDELAY, LOG_DAEMON );
		vsyslog( syslog_prior, format, args );
		closelog();
	}

}

void pss_log( const char *format, ... ) {

	assert( format != NULL );

	va_list args;
	va_start( args, format );
	vpss_log( LOG_WARNING, format, args );
	va_end( args );

}

void pss_fatal( const char *format, ... ) {

	assert( format != NULL );

	va_list args;
	va_start( args, format );

	if( pss_configuration.write_to_syslog == 0 ) {
		#define PSS_RED_CLR "\e[1;31m" // Fancy red fatal msg is 100% necessary.
		#define PSS_RST_CLR "\e[0m"
		printf( PSS_RED_CLR "[FATAL ERROR]" PSS_RST_CLR " " );
		#undef PSS_RED_CLR
		#undef PSS_RST_CLR
	}

	vpss_log( LOG_ERR, format, args );

	va_end( args );

	exit( EXIT_FAILURE );

}
