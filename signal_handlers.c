/*!
	\file signal_handlers.c
*/

#include "signal_handlers.h"
#include "pss_config.h"
#include "pss_log.h"
#include "portscanshield.h"
#include <signal.h>

void set_superloop_exitflag( int sigid ) {

	if( sigid == SIGTERM || sigid == SIGQUIT || sigid == SIGINT ) {
		extern volatile int superloop_exit_flag;
		superloop_exit_flag = 1;
	}

}

void reload_conf( int sigid ) {

	if( sigid == SIGUSR1 ) {
		extern volatile char *pss_config_path;
		extern volatile struct pss_config_vars pss_configuration;

		struct pss_config_vars new_conf;
		parse_config( (char *)pss_config_path, &new_conf );

		/* UID & GID are set right after socket setup, if they've changed they have
		to be reset. This will propably end up with error EPERM (operation not permitted),
		but doing it anyway. */
		if( new_conf.uid != pss_configuration.uid || new_conf.gid != pss_configuration.gid ) {
			copy_config_vars( (struct pss_config_vars *)&pss_configuration, &new_conf );
			pss_drop_rights();
		} else {
			copy_config_vars( (struct pss_config_vars *)&pss_configuration, &new_conf );
		}

		pss_log( "Configuration reloaded." );

		// print_config_vars( (struct pss_config_vars *)&pss_configuration );

	}

}
