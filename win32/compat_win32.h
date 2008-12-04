#ifndef _CONFIG_WIN32_
#define _CONFIG_WIN32_

#define WIN32_LEAN_AND_MEAN

#include <errno.h>
#include <stdint.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <time.h>

#define ECONNABORTED WSAECONNABORTED
#define EMSGSIZE WSAEMSGSIZE
#define EINPROGRESS WSAEWOULDBLOCK // WSAEINPROGRESS

#undef EAGAIN
#define EAGAIN WSAEWOULDBLOCK // WSAEAGAIN

/* dummy types / functions */
#define uid_t int
#define gid_t int
#define hstrerror strerror
#define getuid() (6667)
#define setsid() getpid()
#define setgid(x) (-1)
#define setuid(x) (-1)
#define fork() (-1)
#define geteuid() getuid()
#define setgroups(s, p) (-1)

#define srandom(s) srand(s)
#define random() rand()

typedef enum
{
	LOG_CRIT = -4,
	LOG_ERR,
	LOG_WARNING,
	LOG_INFO,
	LOG_DEBUG
} Log_Level;

#define in_addr_t   uint32_t

/*
 * make recvmsg/sendmsg and fd related code compile
 */

struct iovec {
	void	*iov_base;	/* Base address. */
	size_t	 iov_len;	/* Length. */
};

struct msghdr {
	void         *msg_name;
	socklen_t     msg_namelen;
	struct iovec *msg_iov;
	int           msg_iovlen;
	void         *msg_control;
	socklen_t     msg_controllen;
	int           msg_flags;
};

struct cmsghdr {
	socklen_t	cmsg_len;
	int		cmsg_level;
	int		cmsg_type;
};


#define SCM_RIGHTS 1

#define CMSG_DATA(cmsg) ((unsigned char *) ((struct cmsghdr *) (cmsg) + 1))
#define CMSG_ALIGN(len) (((len) + sizeof (size_t) - 1) \
	& ~(sizeof (size_t) - 1))
#define CMSG_LEN(len) ((int)(CMSG_ALIGN(sizeof(struct cmsghdr))+(len)))
#define CMSG_FIRSTHDR(mhdr) \
	((mhdr)->msg_controllen >= (int)sizeof(struct cmsghdr) ? \
	(struct cmsghdr *)(mhdr)->msg_control : \
	(struct cmsghdr *)NULL)
#define CMSG_NXTHDR(mhdr, cmsg) \
	(((cmsg) == NULL) ? CMSG_FIRSTHDR(mhdr) : \
	(((u_char *)(cmsg) + CMSG_ALIGN((cmsg)->cmsg_len) \
	+ CMSG_ALIGN(sizeof(struct cmsghdr)) > \
	(u_char *)((mhdr)->msg_control) + (mhdr)->msg_controllen) ? \
	(struct cmsghdr *)NULL : \
	(struct cmsghdr *)((u_char *)(cmsg) + CMSG_ALIGN((cmsg)->cmsg_len))))
#define CMSG_SPACE(len) (CMSG_ALIGN(sizeof(struct cmsghdr))+CMSG_ALIGN(len))

/*
 * unify WSAGetLastError() with errno.
 */

static inline int ewrap(int res) {
	if (res < 0)
		errno = WSAGetLastError();
	return res;
}

/* proper signature for setsockopt */
static inline int w_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
	return ewrap(setsockopt(fd, level, optname, optval, optlen));
}
#define setsockopt(a,b,c,d,e) w_setsockopt(a,b,c,d,e)

#define getsockopt(a,b,c,d,e) ewrap(getsockopt(a,b,c,d,e))
#define connect(a,b,c) ewrap(connect(a,b,c))
#define recv(a,b,c,d) ewrap(recv(a,b,c,d))
#define send(a,b,c,d) ewrap(send(a,b,c,d))
#define socket(a,b,c) ewrap(socket(a,b,c))
#define bind(a,b,c) ewrap(bind(a,b,c))
#define listen(a,b) ewrap(listen(a,b))
#define accept(a,b,c) ewrap(accept(a,b,c))
#define getpeername(a,b,c) ewrap(getpeername(a,b,c))
#define getsockname(a,b,c) ewrap(getsockname(a,b,c))
#define select(a,b,c,d,e) ewrap(select(a,b,c,d,e))

static inline struct hostent *w_gethostbyname(const char *n) {
	struct hostent *res = gethostbyname(n);
	if (!res) errno = WSAGetLastError();
	return res;
}
#define gethostbyname(a) w_gethostbyname(a)

const char *wsa_strerror(int e);

static inline const char *w_strerror(int e) {
	if (e > 900)
		return wsa_strerror(e);
	return strerror(e);
}
#define strerror(x) w_strerror(x)


/* gettimeoutday() */
static inline int win32_gettimeofday(struct timeval * tp, void * tzp)
{
	FILETIME file_time;
	SYSTEMTIME system_time;
	ULARGE_INTEGER ularge;
	__int64 epoch = 116444736000000000LL;

	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);
	ularge.LowPart = file_time.dwLowDateTime;
	ularge.HighPart = file_time.dwHighDateTime;

	tp->tv_sec = (long) ((ularge.QuadPart - epoch) / 10000000L);
	tp->tv_usec = (long) (system_time.wMilliseconds * 1000);

	return 0;
}
#define gettimeofday win32_gettimeofday

/* make unix socket related code compile */
struct sockaddr_un {
	int sun_family;
	char sun_path[128];
};

/* getrlimit() */
#define RLIMIT_NOFILE -1
struct rlimit {
	int rlim_cur;
	int rlim_max;
};
static inline int getrlimit(int res, struct rlimit *dst)
{
	dst->rlim_cur = dst->rlim_max = -1;
	return 0;
}

/* kill is only used to detect if process is running (ESRCH->not) */
static inline int kill(int pid, int sig)
{
	HANDLE hProcess;
	DWORD exitCode;
	int ret = 0;

	if (sig != 0) {
		errno = EINVAL;
		return -1;
	}

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (hProcess == NULL) {
		if (GetLastError() == ERROR_INVALID_PARAMETER)
			ret = ESRCH;
		else
			ret = EPERM;
	} else {
		/* OpenProcess may succed for exited processes */
		if (GetExitCodeProcess(hProcess, &exitCode)) {
			if (exitCode != STILL_ACTIVE)
				ret = ESRCH;
		}
		CloseHandle(hProcess);
	}

	if (ret) {
		errno = ret;
		return -1;
	} else
		return  0;
}

/* sendmsg is not used */
static inline int sendmsg(int s, const struct msghdr *m, int flags)
{
	if (m->msg_iovlen != 1) {
		errno = EINVAL;
		return -1;
	}
	return send(s, m->msg_iov[0].iov_base,
		    m->msg_iov[0].iov_len, flags);
}

/* recvmsg() is, but only with one iov */
static inline int recvmsg(int s, struct msghdr *m, int flags)
{
	if (m->msg_iovlen != 1) {
		errno = EINVAL;
		return -1;
	}
	if (m->msg_controllen)
		m->msg_controllen = 0;
	return recv(s, m->msg_iov[0].iov_base,
		    m->msg_iov[0].iov_len, flags);
}

/* dummy getpwnam() */
struct passwd {
	char *pw_name;
	char *pw_passwd;
	int pw_uid;
	int pw_gid;
};
static inline const struct passwd * getpwnam(const char *u) { return NULL; }

/* fix localtime */
static inline struct tm *w_localtime(const time_t *timep) {
	struct tm *res = localtime(timep);
	if (res) res->tm_year += 1900;
	return res;
}
#define localtime(a) w_localtime(a)

/*
 * fcntl
 */

#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4
#define O_NONBLOCK 1
#define FD_CLOEXEC HANDLE_FLAG_INHERIT

static inline int fcntl(int fd, int cmd, long arg)
{
	ULONG lval;
	DWORD dval;
	switch (cmd) {
	case F_GETFD:
		if (GetHandleInformation((HANDLE)fd, &dval))
			return dval;
		errno = EINVAL;
		return -1;
	case F_SETFD:
		/* set FD_CLOEXEC */
		if (SetHandleInformation((HANDLE)fd, FD_CLOEXEC, arg))
			return 0;
		errno = EINVAL;
		return -1;
	case F_GETFL:
		/* O_NONBLOCK? */
		return 0;
	case F_SETFL:
		/* set O_NONBLOCK */
		lval = (arg & O_NONBLOCK) ? 1 : 0;
		if (ioctlsocket(fd, FIONBIO, &lval) == SOCKET_ERROR) {
			errno = WSAGetLastError();
			return -1;
		}
		return 0;
	default:
		errno = EINVAL;
		return -1;
	}
}

/*
 * syslog
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

/* redirect main() */
#define main(a,b) real_main(a,b)
int real_main(int argc, char *argv[]);

#endif /* _CONFIG_WIN32_ */
