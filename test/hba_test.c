
#include "bouncer.h"

#include <usual/fileutil.h>
#include <usual/logging.h>
#include <usual/string.h>
#include <usual/time.h>
#include <usual/logging.h>
#include <usual/mbuf.h>
#include <usual/socket.h>
#include <usual/err.h>

int cf_tcp_keepcnt;
int cf_tcp_keepintvl;
int cf_tcp_keepidle;
int cf_tcp_keepalive;
int cf_tcp_user_timeout;
int cf_tcp_socket_buffer;
int cf_listen_port;

static const char *method2string(int method)
{
	switch (method) {
	case AUTH_TRUST:
		return "trust";
	case AUTH_PLAIN:
		return "password";
	case AUTH_CRYPT:
		return "crypt";
	case AUTH_MD5:
		return "md5";
	case AUTH_CERT:
		return "cert";
	case AUTH_PEER:
		return "peer";
	case AUTH_HBA:
		return "hba";
	case AUTH_REJECT:
		return "reject";
	case AUTH_PAM:
		return "pam";
	case AUTH_SCRAM_SHA_256:
		return "scram-sha-256";
	default:
		return "???";
	}
}

static char *get_token(char **ln_p)
{
	char *ln = *ln_p, *tok, *end;

	while (*ln && *ln == '\t') ln++;
	tok = ln;
	while (*ln && *ln != '\t') ln++;
	end = ln;
	while (*ln && *ln == '\t') ln++;

	*ln_p = ln;
	if (tok == end)
		return NULL;
	*end = 0;
	return tok;
}

static int hba_test_eval(struct HBA *hba, char *ln, int linenr)
{
	const char *addr=NULL, *user=NULL, *db=NULL, *modifier=NULL, *exp=NULL;
	PgAddr pgaddr;
	struct HBARule *rule;
	int res = 0;
	bool tls;
	ReplicationType replication;

	if (ln[0] == '#')
		return 0;
	exp = get_token(&ln);
	db = get_token(&ln);
	user = get_token(&ln);
	addr = get_token(&ln);
	modifier = get_token(&ln);
	tls = strcmpeq(modifier, "tls");
	replication = strcmpeq(modifier, "replication") ?  REPLICATION_PHYSICAL : REPLICATION_NONE;
	if (!exp)
		return 0;
	if (!db || !user)
		die("hbatest: invalid line #%d", linenr);

	if (!pga_pton(&pgaddr, addr, 9999))
		die("hbatest: invalid addr on line #%d", linenr);

	rule = hba_eval(hba, &pgaddr, !!tls, replication, db, user);

	if (!rule) {
	       if (strcmp("reject", exp) == 0) {
		       	res = 0;
	       } else {
			log_warning("FAIL on line %d: No rule for user=%s db=%s addr=%s",
                            linenr, user, db, addr);
			res = 1;
	       }

	} else {
		if (strcmp(method2string(rule->rule_method), exp) == 0) {
			res = 0;
		} else {
			log_warning("FAIL on line %d: expected '%s' got '%s' - user=%s db=%s addr=%s",
			    linenr, exp, method2string(rule->rule_method), user, db, addr);
			res = 1;
		}
	}

	return res;
}

static void hba_test(void)
{
	struct HBA *hba;
	FILE *f;
	char *ln = NULL;
	size_t lnbuf = 0;
	ssize_t len;
	int linenr;
	int nfailed = 0;

	hba = hba_load_rules("hba_test.rules", NULL);
	if (!hba)
		die("hbatest: did not find config");

	f = fopen("hba_test.eval", "r");
	if (!f)
		die("hbatest: cannot open eval");

	for (linenr = 1; ; linenr++) {
		len = getline(&ln, &lnbuf, f);
		if (len < 0)
			break;
		if (len && ln[len-1] == '\n')
			ln[len-1] = 0;
		nfailed += hba_test_eval(hba, ln, linenr);
	}
	free(ln);
	fclose(f);
	hba_free(hba);
	if (nfailed)
		errx(1, "HBA test failures: %d", nfailed);
	else
		printf("HBA test OK\n");
}

int main(void)
{
	hba_test();
	return 0;
}
