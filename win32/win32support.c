/*-------------------------------------------------------------------------
 * win32service.c
 *
 *  Windows service integration and eventlog
 *
 *	Copyright (c) 2005, PostgreSQL Global Development Group
 *	Authors: Magnus Hagander, Hiroshi Saito, Marko Kreen
 *-------------------------------------------------------------------------
 */

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

static char *service_username = NULL;
static char *service_password = NULL;

static char *serviceDescription = "Lightweight connection pooler for PostgreSQL.";

static int exec_real_main(int argc, char *argv[])
{
	/* win32 stdio seems to be fully buffered by default */
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

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
	if (hStatus == 0)
		die("could not connect to service control handler: %s", strerror(GetLastError()));

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

	r = GetModuleFileName(NULL, self, sizeof(self));
	if (!r || r >= sizeof(self)) {
		fprintf(stderr, "Failed to determine path name: %s\n", strerror(GetLastError()));
		exit(1);
	}
	snprintf(cmdline, sizeof(cmdline), "%s --service \"%s\"", self, config_fn);

	manager = openSCM();
	service = CreateService(manager, cf_jobname, cf_jobname, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
				SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, cmdline, NULL, NULL, "RPCSS\0",
				service_username, service_password);
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
	if (service_username == NULL) {
		printf("\nWARNING! Service is registered to run as Local System. You are\n");
		printf("encouraged to change this to a low privilege account to increase\n");
		printf("system security.  (Eg. NT AUTHORITY\\Local Service)\n");
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

/* config loader for service register/unregister */
static void win32_load_config(char *conf)
{
	cf_config_file = conf;
	init_objects();
	load_config();
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
		die("could not start the network subsystem");

	/* service cmdline */
	if (argc >= 3) {
		if (strcmp(argv[1], "--service") == 0 || strcmp(argv[1], "-service") == 0) {
			cf_quiet = 1;
			cf_config_file = argv[2];
			win32_servicestart();
			return 0;
		}

		if (strcmp(argv[1], "--regservice") == 0 || strcmp(argv[1], "-regservice") == 0) {
			int i;
			win32_load_config(argv[2]);
			for (i = 3; i < argc; i++) {
				if (strcmp(argv[i], "-U") == 0 && i + 1 < argc) {
					service_username = argv[++i];
				} else if (strcmp(argv[i], "-P") == 0 && i + 1 < argc) {
					service_password = argv[++i];
				} else {
					fprintf(stderr, "unknown arg: %s\n", argv[i]);
					fprintf(stderr, "Try \"%s --help\" for more information.\n", argv[0]);
					exit(1);
				}
			}
			RegisterService();
			return 0;
		}

		if (strcmp(argv[1], "--unregservice") == 0 || strcmp(argv[1], "-unregservice") == 0) {
			win32_load_config(argv[2]);
			UnRegisterService();
			return 0;
		}
	}

	return exec_real_main(argc, argv);
}
