/*!
	\file pss_pidfile.c
*/

#include "pss_pidfile.h"
#include "pss_log.h"
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/*!
	\brief Creates pidfile.
	\param pidfile Pidfile name and path. If NULL, DEFAULT_PIDFILE is used.
*/
static void pidfile_create( const char *pidfile ) {

	FILE *fp = fopen( pidfile == NULL ? DEFAULT_PIDFILE : pidfile, "w" );

	if( fp == NULL ) {
		pss_fatal( "Pidfile create failed! Error #%d: %s\n", errno, strerror(errno) );
	}

	fclose( fp );

}

/*!
	\brief Checks if pidfile allready exists.
	\param pidfile Pidfile name and path.  If NULL, DEFAULT_PIDFILE is used.
	\return 1 if pidfile exists, 0 otherwise.
*/
static int pidfile_exists( const char *pidfile ) {

	FILE *fp = fopen( pidfile == NULL ? DEFAULT_PIDFILE : pidfile, "r" );

	if( fp == NULL ) {
		return 0;
	} else {
		fclose( fp );
		return 1;
	}

}

void pidfile_init( const char *pidfile ) {

	if( pidfile_exists( pidfile ) == 1 ) {

		pss_fatal( "Daemon already running (pidfile %s exists)!\n", pidfile == NULL ? DEFAULT_PIDFILE : pidfile );

	} else {

		pidfile_create( pidfile );

	}

}

void pidfile_remove( const char *pidfile ) {

	if( remove( pidfile == NULL ? DEFAULT_PIDFILE : pidfile ) == -1 ) {
		pss_fatal( "Pidfile remove failed! Error #%d: %s\n", errno, strerror(errno) );
	}

}
