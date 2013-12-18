/*!
	\file pss_log.h
	\brief portscanshield logging functions.
*/

#ifndef __PSS_LOG_H__
#define __PSS_LOG_H__

#define SYSLOG_APPNAME "portscanshield" //!< Used as openlog() param.

/*!
	\brief Logs message.
	\param format printf() style message format to log.
*/
void pss_log( const char *format, ... );

/*!
	\brief Logs fatal message and exists with EXIT_FAILURE return code.
	\param format printf() style message format to log.
*/
void pss_fatal( const char *format, ... );

#endif
