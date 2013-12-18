/*!
	\file pss_pidfile.h
	\brief Handles creating, removing and checking if pidfile exists.
*/

#ifndef __PSS_PIDFILE_H__
#define __PSS_PIDFILE_H__

#define DEFAULT_PIDFILE "/var/run/portscanshield.pid" //!< Default pidfile name & path.

/*!
	\brief Creates pidfile if not exists, exits with error message if it does.
	\param pidfile Pidfile name and path.
*/
void pidfile_init( const char *pidfile );

/*!
	\brief Removes pidfile.
	\param pidfile Pidfile name and path.
*/
void pidfile_remove( const char *pidfile );

#endif
