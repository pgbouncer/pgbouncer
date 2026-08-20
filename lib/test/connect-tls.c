#include <usual/tls/tls.h>
#include <usual/tls/tls_cert.h>
#include <usual/tls/tls_internal.h>
#include <usual/err.h>
#include <usual/time.h>
#include <usual/socket.h>
#include <usual/signal.h>

#include <string.h>

#ifdef USUAL_LIBSSL_FOR_TLS
#include <openssl/crypto.h>
#endif

static void show_time(const char *desc, time_t t)
{
	const char *val;
	val = t ? ctime(&t) : "--\n";
	printf("%s: %s", desc, val);
}

static void show_ocsp_info(const char *desc, struct tls *ctx)
{
	int req_status, cert_status, crl_reason, res;
	const char *msg;
	time_t this_update, next_update, revocation_time;

	res = tls_get_ocsp_info(ctx, &req_status, &cert_status, &crl_reason, &this_update, &next_update, &revocation_time, &msg);
	printf("%s: %s\n", desc, msg);
	if (res == 0) {
		printf("  req_status=%d cert_status=%d crl_reason=%d\n", req_status, cert_status, crl_reason);
		show_time("  this update", this_update);
		show_time("  next update", next_update);
		show_time("  revocation", revocation_time);
	}
}

static void ignore_sigpipe(void)
{
#ifndef WIN32
	static bool done;
	sigset_t set;
	int ret;

	if (done)
		return;

	/* block SIGPIPE */
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	ret = sigprocmask(SIG_BLOCK, &set, NULL);
	if (ret < 0)
		err(1, "sigprocmask");
	done = true;
#endif
}

static void test_context(struct tls *ctx)
{
	char buf[2*1024*1024], *ptr = buf;
	ssize_t ret, len = sizeof buf;

	ignore_sigpipe();

	memset(buf, 'X', len);

	buf[len - 4] = ':';
	buf[len - 3] = 'x';
	buf[len - 2] = '\r';
	buf[len - 1] = '\n';
loop:
	len = sizeof buf;
	ptr = buf;

	while (len > 0) {
		ret = tls_write(ctx, ptr, len);
		if (ret <= 0)
			printf("tls_write(%d) = %d\n", (int)len, (int)ret);
		if (ret > 0) {
			len -= ret;
			ptr += ret;
		} else if (ret == TLS_WANT_POLLIN) {
			continue;
		} else if (ret == TLS_WANT_POLLOUT) {
			continue;
		} else {
			printf("tls_write: %s\n", tls_error(ctx));
			break;
		}
	}
	if (len == 0)
		goto loop;
	printf("final len: %d\n", (int)len);
}

int main(int argc, char *argv[])
{
	struct tls_config *conf;
	struct tls *ctx, *ocsp;
	struct tls_cert *cert;
	int res;
	const char *host;
	char buf[256];

	if (argc < 2)
		errx(1, "give host as arg\n");
	host = argv[1];

#ifdef USUAL_LIBSSL_FOR_TLS
	printf("libssl: %s\n", tls_backend_version());
#endif
	res = tls_init();
	if (res < 0)
		errx(1, "tls_init");

	conf = tls_config_new();
	if (!conf)
		errx(1, "tls_config_new");

	tls_config_set_protocols(conf, TLS_PROTOCOLS_ALL);
	tls_config_set_ciphers(conf, "fast");

	ctx = tls_client();
	if (!ctx)
		errx(1, "tls_client");

	res = tls_configure(ctx, conf);
	if (res < 0)
		errx(1, "tls_configure: %s", tls_error(ctx));

	res = tls_connect(ctx, host, "443");
	if (res < 0)
		errx(1, "tls_connect: %s", tls_error(ctx));

	res = tls_handshake(ctx);
	if (res < 0)
		errx(1, "tls_handshake: %s", tls_error(ctx));

	res = tls_get_peer_cert(ctx, &cert, NULL);
	if (res < 0)
		errx(1, "tls_get_peer_cert: %s", tls_error(ctx));

	tls_get_connection_info(ctx, buf, sizeof buf);

	printf("Connection: '%s'\n", buf);
	printf("  CN='%s'\n", cert->subject.common_name);
	printf("  C='%s'\n", cert->subject.country_name);
	printf("  ST='%s'\n", cert->subject.state_or_province_name);
	printf("  L='%s'\n", cert->subject.locality_name);
	printf("  S='%s'\n", cert->subject.street_address);
	printf("  O='%s'\n", cert->subject.organization_name);
	printf("  OU='%s'\n", cert->subject.organizational_unit_name);

	show_ocsp_info("OCSP stapling", ctx);

	ocsp = NULL;
	res = tls_ocsp_check_peer(&ocsp, NULL, ctx);
	if (ocsp) {
		show_ocsp_info("OCSP responder", ocsp);
		usual_tls_free(ocsp);
	} else if (res == TLS_NO_OCSP) {
		printf("OCSP responder: No OCSP support in libtls\n");
	}

	if (0) test_context(ctx);

	tls_close(ctx);
	usual_tls_free(ctx);
	tls_config_free(conf);
	tls_cert_free(cert);

	return 0;
}
