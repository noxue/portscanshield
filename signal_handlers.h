/*!
	\file signal_handlers.h
	\brief portscanshield signal handlers.
*/

#ifndef __SIGNAL_HANDLERS_H__
#define __SIGNAL_HANDLERS_H__

/*!
	\brief SIGINT, SIGQUIT and SIGTERM handler. Initializes portscanshield cleanup & exit.
*/
void set_superloop_exitflag( int sigid );

/*!
	\brief SIGUSR1 handler. Rereads config file, and reloads portscanshield config.
*/
void reload_conf( int sigid );

#endif
