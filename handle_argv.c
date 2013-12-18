/*!
	\file handle_argv.c
*/

#include "handle_argv.h"
#include "pss_log.h"
#include "pss_pidfile.h"
#include "version.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

void print_help( void ) {

	printf( "portscanshield, v3.0\n"
			"Options:\n"
			"\t -h --help Show help message (this) & exit.\n"
			"\t -v --version Show version info & exit.\n"
			"\t -c --config new_conf_file_path Set non-default configuration file.\n"
			"\t -p --pidfile new_pidfile_path Set new pidfile path to new_pidfile_path.\n"
			"\t -f --force Force run, ignores existing pidfile.\n"
			"\t -d --daemonize Run in background.\n"
			"End options.\n\n" );

}

void handle_argv( int argc, char **argv, void **options ) {

	assert( argc > 1 && argv != NULL && options != NULL );

	#define DAEMON_FLAG (1U << 0)
	#define PIDFILE_REMOVE_FLAG (1U << 1)
	#define EXIT_FLAG (1U << 2)
	int todo_flags = 0;

	int i = 0;
	for( i = 1; i < argc; ++i ) {

		if( strcmp( argv[i], "-h" ) == 0 || strcmp( argv[i], "--help" ) == 0 ) {
			print_help();
			todo_flags |= EXIT_FLAG;
		} else if( strcmp( argv[i], "-v" ) == 0 || strcmp( argv[i], "--version" ) == 0 ) {
			printf( "portscanshield, version %d.%d (%s)\n", PSS_VERSION_MAJOR, PSS_VERSION_MINOR, PSS_VERSION_STR );
			todo_flags |= EXIT_FLAG;
		} else if( strcmp( argv[i], "-c" ) == 0 || strcmp( argv[i], "--config" ) == 0 ) {

			if( i+1 >= argc ) {
				pss_fatal( "Wrong --config parameter!\n" );
			}
			*((char **)options[1]) = argv[++i]; // options[1] = new config file

		} else if( strcmp( argv[i], "-p" ) == 0 || strcmp( argv[i], "--pidfile" ) == 0 ) {

			if( i+1 >= argc ) {
				pss_fatal( "Wrong --pidfile parameter!\n" );
			}
			*((char **)options[0]) = argv[++i]; // options[0] = new pidfile

		} else if( strcmp( argv[i], "-f" ) == 0 || strcmp( argv[i], "--force" ) == 0 ) {
			todo_flags |= PIDFILE_REMOVE_FLAG;
		} else if( strcmp( argv[i], "-d" ) == 0 || strcmp( argv[i], "--daemonize" ) == 0 ) {
			todo_flags |= DAEMON_FLAG;
		} else {
			pss_fatal( "Unknown argument %d: %s\n", i, argv[i] );
		}

	}

	if( todo_flags & EXIT_FLAG ) {
		exit(0);
	}

	if( todo_flags & PIDFILE_REMOVE_FLAG ) {
		pidfile_remove( options[0] );
	}

	if( todo_flags & DAEMON_FLAG ) {
		daemon( 1 /* nochdir */, 0 /* noclose */ );
	}

	#undef DAEMON_FLAG
	#undef PIDFILE_REMOVE_FLAG
	#undef EXIT_FLAG

}
