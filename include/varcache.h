
#define VAR_ENCODING_LEN	16
#define VAR_DATESTYLE_LEN	32
#define VAR_TIMEZONE_LEN	36
#define VAR_STDSTR_LEN		4

typedef struct VarCache VarCache;

struct VarCache {
	char client_encoding[VAR_ENCODING_LEN];
	char datestyle[VAR_DATESTYLE_LEN];
	char timezone[VAR_TIMEZONE_LEN];
	char std_strings[VAR_STDSTR_LEN];
};

bool varcache_set(VarCache *cache, const char *key, const char *value) /* _MUSTCHECK */;
bool varcache_apply(PgSocket *server, PgSocket *client, bool *changes_p) _MUSTCHECK;
void varcache_fill_unset(VarCache *src, PgSocket *dst);
void varcache_clean(VarCache *cache);
void varcache_add_params(PktBuf *pkt, VarCache *vars);

