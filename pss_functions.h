#ifndef _PSS_FUNCTIONS_H_
#define _PSS_FUNCTIONS_H_

int in_arr( int needle, int haystack_arr[], int size );
int ip_in_array( char** arr, char* ip, int arrsize );
int cutfield_size( char* fieldname, char* string );
int cutfield( char* fieldname, char* string, char* retstr, int size );
int parsebanstring_size( char* banstring, char* ip );
int parsebanstring( char* banstring, char* ip, char* retstr, int size );
int wtosyslog( char* msg );
int pinfo( char* msg, int write_to_syslog );
int read_config(void);


#endif
