#include <usual/strpool.h>

enum VarCacheIdx {
	VDateStyle = 0,
	VClientEncoding,
	VTimeZone,
	VStdStr,
	VAppName,
	VInHotStandby,
	VDefaultTransactionReadOnly,
	NumVars
};

typedef struct VarCache VarCache;

struct VarCache {
	struct PStr **var_list;
};

void init_var_lookup(const char *cf_track_extra_parameters);
int get_num_var_cached(void);
bool varcache_set(VarCache *cache, const char *key, const char *value) /* _MUSTCHECK */;
bool varcache_apply(PgSocket *server, PgSocket *client, bool *changes_p) _MUSTCHECK;
void varcache_apply_startup(PktBuf *pkt, PgSocket *client);
void varcache_fill_unset(VarCache *src, PgSocket *dst);
void varcache_clean(VarCache *cache);
void varcache_add_params(PktBuf *pkt, VarCache *vars);
void varcache_deinit(void);
void varcache_set_canonical(PgSocket *server, PgSocket *client);
