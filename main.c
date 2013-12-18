#include "pss_config.h"
#include "pss_pidfile.h"
#include "pss_log.h"
#include "portscanshield.h"
#include "signal_handlers.h"
#include "handle_argv.h"
#include "version.h"
#include "vector_template/vector_template.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

char *pss_config_path = "pss.conf";

volatile struct pss_config_vars pss_configuration;
volatile int superloop_exit_flag = 0; //!< Set by handled signals.

/*
	TODO:
		- clean knock vectors after n hits/time (?)

		- change nochdir in daemon
		- pss -> /etc/portscanshield.conf
*/

int main( int argc, char **argv ) {

	char *pidfile = NULL;

	if( argc > 1 ) {

		void *tmp_param_arr[] = { (void *)&pidfile, (void *)&pss_config_path };
		handle_argv( argc, argv, tmp_param_arr );

	} else {
		print_help();
		// return 0;
	}

	parse_config( pss_config_path, (struct pss_config_vars *)&pss_configuration );

	// print_config_vars( (struct pss_config_vars *)&pss_configuration );

	pidfile_init( pidfile );

	signal( SIGTERM, set_superloop_exitflag );
	signal( SIGQUIT, set_superloop_exitflag );
	signal( SIGINT, set_superloop_exitflag );

	signal( SIGUSR1, reload_conf );

	pss_log( "portscanshield started.\n" );

	/* Run daemon, wait for signal to stop it... */
	pss_run();

	free_config( (struct pss_config_vars *)&pss_configuration );

	pidfile_remove( pidfile );

	pss_log( "portscanshield exited.\n" );
	
	return 0;

}
