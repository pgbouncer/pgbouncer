#ifndef WIN32SERVICE
#define WIN32SERVICE
/*-------------------------------------------------------------------------
 * win32service.h
 *
 *  Windows service definitions
 *
 *	Copyright (c) 2008, PostgreSQL Global Development Group
 *-------------------------------------------------------------------------
 */

#define openlog		w_openlog
#define syslog		w_syslog
#define closelog	w_closelog

#define LOG_EMERG	0
#define LOG_ALERT	1
#define LOG_CRIT	2
#define LOG_ERR		3
#define LOG_WARNING	4
#define LOG_NOTICE	5
#define LOG_INFO	6
#define LOG_DEBUG	7

#define LOG_PID 0

#define LOG_KERN 0
#define LOG_USER 0
#define LOG_MAIL 0
#define LOG_DAEMON 0
#define LOG_AUTH 0
#define LOG_SYSLOG 0
#define LOG_LPR 0
#define LOG_NEWS 0
#define LOG_UUCP 0
#define LOG_CRON 0
#define LOG_AUTHPRIV 0
#define LOG_FTP 0
#define LOG_LOCAL0 0
#define LOG_LOCAL1 0
#define LOG_LOCAL2 0
#define LOG_LOCAL3 0
#define LOG_LOCAL4 0
#define LOG_LOCAL5 0
#define LOG_LOCAL6 0
#define LOG_LOCAL7 0


void openlog(const char *ident, int option, int facility);
void syslog(int priority, const char *format, ...);
void closelog(void);

#endif
