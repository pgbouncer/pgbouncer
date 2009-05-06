/*-------------------------------------------------------------------------
 * win32service.c
 *
 *  Windows service integration and eventlog
 *
 *	Copyright (c) 2005, PostgreSQL Global Development Group
 *	Authors: Magnus Hagander, Hiroshi Saito, Marko Kreen
 *-------------------------------------------------------------------------
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>

#include "bouncer.h"

#if defined(UNICODE) || defined(_UNICODE)
#error This code does not support wide characters.
#endif

/* Globals for service control */
static SERVICE_STATUS_HANDLE hStatus = 0;
static SERVICE_STATUS svcStatus = {
	.dwServiceType = SERVICE_WIN32_OWN_PROCESS,
	.dwControlsAccepted = 0,
	.dwWin32ExitCode = NO_ERROR,
	.dwCheckPoint = 0,
	.dwWaitHint = 0,
	.dwCurrentState = SERVICE_START_PENDING,
};

/* Event source name for ReportEvent.
 *
 * Also used as placeholder for service handling API's, but it is ignored
 * because our service is defined as WIN32_OWN_PROCESS.
 */
static char *servicename = "pgbouncer";

static char *serviceDescription = "Lightweight connection pooler for PostgreSQL.";

/* custom help string for win32 exe */
static const char *usage_str =
"Usage: %s [OPTION]... config.ini\n"
"  -q            No console messages\n"
"  -v            Increase verbosity\n"
"  -V            Show version\n"
"  -h            Show this help screen and exit\n"
"Windows service registration:\n"
"  -regservice   config.ini\n"
"  -unregservice config.ini\n"
"";

static void usage(int err, char *exe)
{
	printf(usage_str, basename(exe));
	exit(err);
}

static int exec_real_main(int argc, char *argv[])
{
	int i, j;

	/* win32 stdio seems to be fully buffered by default */
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	/* check if regular arguments are in allowed list */
	for (i = 1; i < argc; i++) {
		char *p = argv[i];
		if (p[0] != '-')
			continue;
		for (j = 1; p[j]; j++) {
			if (!strchr("qvhV", p[j]))
				usage(1, argv[0]);
			if (p[j] == 'h')
				usage(0, argv[0]);
		}
	}

	/* call actual main() */
	return real_main(argc, argv);
}

/* Set the current service status */
static void win32_setservicestatus(DWORD state)
{
	svcStatus.dwCurrentState = state;
	switch (state) {
	case SERVICE_START_PENDING:
	case SERVICE_STOP_PENDING:
		svcStatus.dwControlsAccepted = 0;
		svcStatus.dwWaitHint = 5000;
		break;
	default:
		svcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
		svcStatus.dwWaitHint = 0;
	}

	SetServiceStatus(hStatus, &svcStatus);
}

/*
 * Handle any events sent by the service control manager
 * NOTE! Events are sent on a different thread! And it's
 * not a pthreads thread, so avoid calling anything that
 * may use pthreads - like pgbouncer_log()
 */
static void WINAPI win32_servicehandler(DWORD request)
{
	switch (request) {
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
		win32_setservicestatus(SERVICE_STOP_PENDING);
		cf_shutdown = 2;
		break;
	case SERVICE_CONTROL_INTERROGATE:
		SetServiceStatus(hStatus, &svcStatus);
		break;
	}
}

/* notify control thread about stop */
static void win32_service_cleanup(void)
{
	if (hStatus)
		win32_setservicestatus(SERVICE_STOPPED);
	hStatus = 0; /* may get called twice from atexit */
}

/*
 * Entrypoint for actual service work.
 *
 * Service is set-up and then actual main() is called.
 */
static void WINAPI win32_servicemain(DWORD argc, LPSTR *argv)
{
	int new_argc = 2;
	char *new_argv[] = { servicename, cf_config_file, NULL };

	/* register control request handler */
	hStatus = RegisterServiceCtrlHandler(servicename, win32_servicehandler);
	if (hStatus == 0) {
		fatal("could not connect to service control handler: %s", strerror(GetLastError()));
		exit(1);
	}

	/* Tell SCM we are running before we make any API calls */
	win32_setservicestatus(SERVICE_RUNNING);

	/* register with system atexit(), in case somebody calls exit() */
	atexit(win32_service_cleanup);

	/* Execute actual main() */
	exec_real_main(new_argc, new_argv);

	win32_service_cleanup();
}

/* Start running as a service */
static void win32_servicestart(void)
{
	SERVICE_TABLE_ENTRY st[] = { {servicename, win32_servicemain}, {NULL, NULL} };

	if (StartServiceCtrlDispatcher(st) == 0) {
		fprintf(stderr, "could not start service control dispatcher: %s\n",
			strerror(GetLastError()));
		exit(1);
	}
}

/* Open Service Control Manager */
static SC_HANDLE openSCM(void)
{
	SC_HANDLE manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!manager) {
		fprintf(stderr, "Failed to open service control manager: %s\n", strerror(GetLastError()));
		exit(1);
	}
	return manager;
}

/* Full path to current config file.  */
static const char *get_config_fullpath(void)
{
	DWORD r;
	static char buf[PATH_MAX];

	r = GetFullPathName(cf_config_file, sizeof(buf), buf, NULL);
	if (r == 0 || r >= sizeof(buf)) {
		fprintf(stderr, "Failed to get full pathname for '%s': %s\n",
			cf_config_file, strerror(GetLastError()));
		exit(1);
	}
	return buf;
}

/* Check windows version against Server 2003 to determine service functionality */
static bool is_windows2003ornewer(void)
{
	OSVERSIONINFO vi;

	vi.dwOSVersionInfoSize = sizeof(vi);
	if (!GetVersionEx(&vi)) {
		fprintf(stderr, "Failed to determine OS version: %s\n", strerror(GetLastError()));
		exit(1);
	}
	if (vi.dwMajorVersion > 5)
		return true;	/* Vista + */
	if (vi.dwMajorVersion == 5 && vi.dwMinorVersion >= 2)
		return true;	/* Win 2003 */
	return false;
}

/* Register a service with the specified name with the local service control manager */
static void RegisterService(void)
{
	char self[1024];
	char cmdline[2048];
	const char *config_fn = get_config_fullpath();
	SC_HANDLE manager;
	SC_HANDLE service;
	SERVICE_DESCRIPTION sd;
	DWORD r;
	char *account = is_windows2003ornewer() ? "NT AUTHORITY\\Local Service" : NULL;

	r = GetModuleFileName(NULL, self, sizeof(self));
	if (!r || r >= sizeof(self)) {
		fprintf(stderr, "Failed to determine path name: %s\n", strerror(GetLastError()));
		exit(1);
	}
	snprintf(cmdline, sizeof(cmdline), "%s -service \"%s\"", self, config_fn);

	manager = openSCM();
	service = CreateService(manager, cf_jobname, cf_jobname, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
				SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, cmdline, NULL, NULL, "RPCSS\0", account, "");
	if (!service) {
		fprintf(stderr, "Failed to create service: %s\n", strerror(GetLastError()));
		exit(1);
	}

	/* explain the service purpose */
	sd.lpDescription = serviceDescription;
	ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &sd);

	CloseServiceHandle(service);
	CloseServiceHandle(manager);

	printf("Service registered.\n");
	if (account == NULL) {
		printf("\nWARNING! Service is registered to run as Local System. You are\n");
		printf("encouraged to change this to a low privilege account to increase\n");
		printf("system security.\n");
	}
}

/* Remove a service with the specified name from the local service control manager */
static void UnRegisterService(void)
{
	SC_HANDLE manager;
	SC_HANDLE service;

	manager = openSCM();
	service = OpenService(manager, cf_jobname, SC_MANAGER_ALL_ACCESS);
	if (!service) {
		fprintf(stderr, "Failed to open service: %s\n", strerror(GetLastError()));
		exit(1);
	}

	if (!DeleteService(service)) {
		fprintf(stderr, "Failed to delete service: %s\n", strerror(GetLastError()));
		exit(1);
	}

	CloseServiceHandle(service);
	CloseServiceHandle(manager);

	printf("Service removed.\n");
}


/*
 * syslog() interface to event log.
 */

void win32_eventlog(int level, const char *fmt, ...)
{
	static HANDLE evtHandle = INVALID_HANDLE_VALUE;
	int elevel;
	char buf[1024];
	const char *strlist[1] = { buf };
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	switch (level) {
	case LOG_CRIT:
	case LOG_ERR:
		elevel = EVENTLOG_ERROR_TYPE;
		break;
	case LOG_WARNING:
		elevel = EVENTLOG_WARNING_TYPE;
		break;
	default:
		elevel = EVENTLOG_INFORMATION_TYPE;
	}

	if (evtHandle == INVALID_HANDLE_VALUE) {
		evtHandle = RegisterEventSource(NULL, servicename);
		if (evtHandle == NULL || evtHandle == INVALID_HANDLE_VALUE) {
			evtHandle = INVALID_HANDLE_VALUE;
			return;
		}
	}
	ReportEvent(evtHandle, elevel, 0, 0, NULL, 1, 0, strlist, NULL);
}

/*
 * Error strings for win32 errors.
 */

const char *win32_strerror(int e)
{
	static char buf[1024];
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, e,
		      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		      buf, sizeof(buf), NULL);
	return buf;
}

/* config loader for service register/unregister */
static void win32_load_config(char *conf)
{
	cf_config_file = conf;
	init_objects();
	load_config(false);
}

/*
 * Wrapper around actual main() that handles win32 hacks.
 */

#undef main
int main(int argc, char *argv[])
{
	WSADATA wsaData;

	/* initialize socket subsystem */
	if (WSAStartup(MAKEWORD(2,0), &wsaData))
		fatal("Cannot start the network subsystem");

	/* service cmdline */
	if (argc == 3) {
		if (!strcmp(argv[1], "-service")) {
			cf_quiet = 1;
			cf_config_file = argv[2];
			win32_servicestart();
			return 0;
		}

		if (!strcmp(argv[1], "-regservice")) {
			win32_load_config(argv[2]);
			RegisterService();
			return 0;
		}

		if (!strcmp(argv[1], "-unregservice")) {
			win32_load_config(argv[2]);
			UnRegisterService();
			return 0;
		}
	}

	return exec_real_main(argc, argv);
}

